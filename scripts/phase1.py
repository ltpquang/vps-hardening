#!/usr/bin/env python3
"""Staged Ubuntu 24.04 VPS hardening. No third-party Python dependencies.

Read README.md in the repository before applying. plan/verify never change configuration.
apply stages SSH/firewall changes with a persistent rollback timer; commit requires
a new SSH session on the selected port and an explicit external-check assertion.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/vps-phase1')
TIMER = 'vps-phase1-rollback'
PATHS = (
    '/etc/ssh/sshd_config.d/00-local-security.conf',
    '/etc/ssh/sshd_config.d/00-local-ports.conf',
    '/etc/vps-edge.nft',
    '/etc/systemd/system/vps-edge.service',
    '/etc/systemd/system/docker.service.d/10-firewall.conf',
    '/etc/fail2ban/jail.d/sshd.local',
    '/etc/apt/apt.conf.d/20auto-upgrades',
)
PACKAGES = ('openssh-server', 'sudo', 'ca-certificates', 'curl', 'nano',
            'nftables', 'unattended-upgrades', 'fail2ban', 'python3-systemd')
SECURITY = {
    'pubkeyauthentication': 'yes', 'permitrootlogin': 'no',
    'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
    'allowagentforwarding': 'no', 'x11forwarding': 'no',
    'allowtcpforwarding': 'local', 'disableforwarding': 'no',
    'authenticationmethods': 'publickey', 'hostbasedauthentication': 'no',
    'gssapiauthentication': 'no',
}


class Error(RuntimeError):
    pass


def run(*args: str, check=True, data=None) -> str:
    try:
        proc = subprocess.run(args, input=data, text=True, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise Error(f'{shlex.join(args)} timed out.') from None
    if check and proc.returncode:
        # Commands here never contain credentials. Avoid dumping arbitrary stdout.
        raise Error(f'{shlex.join(args)} failed: {proc.stderr.strip()[:2000]}')
    return proc.stdout.strip()


def successful(*args: str) -> bool:
    try:
        return subprocess.run(args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def active(unit: str) -> bool:
    return successful('systemctl', 'is-active', '--quiet', unit)


def enabled(unit: str) -> bool:
    return successful('systemctl', 'is-enabled', '--quiet', unit)


def require_root():
    if os.geteuid() != 0:
        raise Error('Run with sudo. Root is needed even for a complete read-only plan/audit.')


def write(path: Path, value: str | bytes, mode=0o644):
    """Atomic file replacement; reject symlink parents rather than following them."""
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise Error(f'Refusing symlink: {parent}')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.phase1-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(value.encode() if isinstance(value, str) else value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_state(folder: Path, state: dict):
    write(folder / 'state.json', json.dumps(state, indent=2) + '\n', 0o600)


def port_number(value) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise Error('SSH port must be an integer from 1 to 65535.') from None
    if not 1 <= value <= 65535:
        raise Error('SSH port must be from 1 to 65535.')
    # Reserved internal services must never become permitted "SSH" ports.
    if value in {53, 80, 443, 2375, 2376, 2377, 3000, 4789, 5432, 6379, 7946}:
        raise Error(f'Port {value} is reserved by this handbook; choose a dedicated SSH port.')
    return value


def ssh_config(user: str, client: str | None = None) -> dict[str, list[str]]:
    args = ['/usr/sbin/sshd', '-T']
    if client:
        args += ['-C', f'user={user},addr={client},host={client}']
    result: dict[str, list[str]] = {}
    for line in run(*args).splitlines():
        key, _, value = line.partition(' ')
        result.setdefault(key, []).append(value)
    return result


def parse_tables(text: str) -> set[tuple[str, str]]:
    tables = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'table\s+(\w+)\s+([\w-]+)\s*', line)
        if not match:
            raise Error('Unsupported nftables table listing; refusing to guess its policy.')
        tables.add(tuple(match.groups()))
    return tables


def normalize_rules(text: str) -> str:
    # Preserve rules/ordering but ignore counters, which change with traffic.
    text = re.sub(r'counter packets \d+ bytes \d+', 'counter', text)
    return ' '.join(text.split())


def choose_interfaces(addresses: list, routes: list, requested: list[str]) -> list[str]:
    names = {item['ifname'] for item in addresses}
    discovered = {route['dev'] for route in routes if route.get('dev') != 'lo' and route.get('dev')}
    for item in addresses:
        if item['ifname'] == 'lo':
            continue
        if any(ipaddress.ip_address(a['local']).is_global
               for a in item.get('addr_info', [])):
            discovered.add(item['ifname'])
    selected = set(requested) if requested else discovered
    if not selected or not selected <= names or 'lo' in selected:
        raise Error('Cannot identify public interfaces; supply --interface for each uplink.')
    if not discovered <= selected:
        raise Error(f'Interface selection omits detected uplinks: {sorted(discovered - selected)}')
    if any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name) for name in selected):
        raise Error('Unsupported interface name.')
    return sorted(selected)


def nft_config(interfaces: list[str], ports: list[int]) -> str:
    ifaces = '{ ' + ', '.join(json.dumps(i) for i in interfaces) + ' }'
    permits = '{ ' + ', '.join(str(port_number(p)) for p in sorted(set(ports))) + ' }'
    return f'''# Managed by the Phase 1 handbook script.
add table inet vps_edge
flush table inet vps_edge
table inet vps_edge {{
    chain prerouting {{
        type filter hook prerouting priority -110; policy accept;
        iifname {ifaces} jump public_ingress
    }}
    chain public_ingress {{
        ct state established,related accept
        ct state invalid drop
        tcp dport {permits} accept
        meta l4proto {{ icmp, ipv6-icmp }} accept
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        counter drop
    }}
}}
'''


def configuration(interfaces: list[str], ports: list[int]) -> dict[str, str]:
    permits = ','.join(map(str, sorted(set(ports))))
    return {
        PATHS[0]: '''# Phase 1: key-only administration; retain local recovery tunnels.
PubkeyAuthentication yes
AuthenticationMethods publickey
HostbasedAuthentication no
GSSAPIAuthentication no
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowAgentForwarding no
X11Forwarding no
AllowTcpForwarding local
DisableForwarding no
''',
        PATHS[1]: '# Phase 1 SSH listeners.\n' + ''.join(f'Port {p}\n' for p in sorted(set(ports))),
        PATHS[2]: nft_config(interfaces, ports),
        PATHS[3]: '''[Unit]
Description=Public interface ingress firewall
Before=docker.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/vps-edge.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        PATHS[4]: '''[Unit]
Requires=vps-edge.service
After=vps-edge.service
''',
        PATHS[5]: f'''[sshd]
enabled = true
backend = systemd
filter = sshd
port = {permits}
protocol = tcp
banaction = nftables[type=multiport]
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8 ::1
''',
        PATHS[6]: '''// Phase 1 Ubuntu archive security updates.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
''',
    }


def session() -> dict | None:
    """Find SSH session metadata in ancestors, even when sudo strips environment."""
    pid = os.getpid()
    connection = os.environ.get('SSH_CONNECTION')
    ssh_start = None
    boot = int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines()
                    if line.startswith('btime ')))
    ticks = os.sysconf('SC_CLK_TCK')
    while pid > 1:
        try:
            proc = Path('/proc') / str(pid)
            if not connection:
                values = proc.joinpath('environ').read_bytes().split(b'\0')
                connection = next((v.split(b'=', 1)[1].decode() for v in values
                                   if v.startswith(b'SSH_CONNECTION=')), None)
            fields = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()
            parent = int(fields[1])
            comm = proc.joinpath('comm').read_text().strip()
            if comm in {'sshd', 'sshd-session'} and parent != 1 and ssh_start is None:
                ssh_start = boot + int(fields[19]) / ticks
            pid = parent
        except (OSError, ValueError, IndexError):
            return None
    if not connection or ssh_start is None:
        return None
    pieces = connection.split()
    if len(pieces) != 4:
        return None
    try:
        ipaddress.ip_address(pieces[0]); ipaddress.ip_address(pieces[2])
        port = int(pieces[3])
    except ValueError:
        return None
    return {'client': pieces[0], 'port': port, 'started': ssh_start}


def check_commit_session(info: dict | None, state: dict, sudo_user: str | None):
    if not info or sudo_user != state['admin']:
        raise Error('Commit through sudo from a new SSH login as the configured administrator.')
    if info['port'] != state['port']:
        raise Error(f"Connect on port {state['port']} before committing.")
    if info['started'] <= state['staged_at']:
        raise Error('This SSH session predates staging. Open a fresh connection without multiplexing.')


def unit_states() -> dict:
    return {u: {'enabled': enabled(u), 'active': active(u)}
            for u in ('vps-edge.service', 'fail2ban.service', 'apt-daily.timer', 'apt-daily-upgrade.timer')}


def safety_checks():
    if shutil.which('docker') or Path('/usr/bin/dockerd').exists():
        raise Error('Docker is already installed. Phase 1 apply is for pre-Docker hosts only.')
    for unit in ('ufw.service', 'firewalld.service', 'nftables.service'):
        if active(unit) or enabled(unit):
            raise Error(f'{unit} is active or enabled. Reconcile the existing firewall manually first.')
    if shutil.which('nft'):
        tables = parse_tables(run('nft', 'list', 'tables'))
        unknown = tables - {('inet', 'vps_edge'), ('inet', 'f2b-table')}
        if unknown:
            raise Error(f'Unrecognized firewall tables: {sorted(unknown)}. Refusing to replace policy.')


def preflight(args) -> dict:
    osinfo = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                  if '=' in line)
    if osinfo.get('ID', '').strip('"') != 'ubuntu' or osinfo.get('VERSION_ID', '').strip('"') != '24.04':
        raise Error('This script supports Ubuntu 24.04 LTS only.')
    if not Path('/run/systemd/system').exists():
        raise Error('A booted systemd host is required, not a container or chroot.')
    for command in ('ip', 'ss', 'systemctl', 'systemd-analyze', 'ssh-keygen', 'apt-get'):
        if not shutil.which(command):
            raise Error(f'Missing prerequisite: {command}')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*', args.admin):
        raise Error('Invalid administrator username.')
    try:
        account = pwd.getpwnam(args.admin)
    except KeyError:
        raise Error('Provision the non-root administrator before running this script.') from None
    if account.pw_uid == 0:
        raise Error('The administrator must be non-root.')
    if 'sudo' not in run('id', '-nG', args.admin).split():
        raise Error('The administrator must be in Ubuntu’s sudo group; test sudo access first.')
    auth = Path(account.pw_dir) / '.ssh/authorized_keys'
    if not auth.is_file() or not auth.read_text().strip():
        raise Error(f'Provision and test a public SSH key in {auth} first.')
    run('ssh-keygen', '-l', '-f', str(auth))
    run('/usr/sbin/sshd', '-t')
    info = session()
    config = ssh_config(args.admin, info['client'] if info else None)
    authorized = config.get('authorizedkeysfile', [''])[0].split()
    if not ({'.ssh/authorized_keys', str(auth)} & set(authorized)):
        raise Error('Nonstandard AuthorizedKeysFile is outside this script’s supported setup.')
    ports = sorted({port_number(p) for p in config.get('port', [])})
    if not ports:
        raise Error('No effective SSH port found.')
    # Socket overrides can disagree with sshd_config; do not guess what is live.
    if active('ssh.socket'):
        listen = run('systemctl', 'show', 'ssh.socket', '-p', 'Listen', '--value')
        socket_ports = {int(p) for p in re.findall(r':(\d+)\s+\(Stream\)', listen)}
        if socket_ports != set(ports):
            raise Error('ssh.socket listeners disagree with sshd_config; resolve overrides first.')
    elif not active('ssh.service'):
        raise Error('Neither supported SSH listener mode is active.')
    if info and info['port'] not in ports:
        raise Error('The current SSH port differs from effective configuration; resolve it first.')
    target = port_number(args.ssh_port) if args.ssh_port else (info['port'] if info else ports[0])
    listener_text = run('ss', '-H', '-lntp')
    direct_ssh_ports = set()
    for line in listener_text.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[3].rsplit(':', 1)[-1].isdigit():
            continue
        listening_port = int(fields[3].rsplit(':', 1)[-1])
        if re.search(r'"(?:sshd|sshd-session)"', line):
            direct_ssh_ports.add(listening_port)
        if listening_port in {80, 443, 3000}:
            raise Error('An application is already listening on 80/443/3000. This is a pre-application script.')
        if listening_port == target and target not in ports:
            raise Error('The requested new SSH port is already occupied.')
    if not active('ssh.socket') and direct_ssh_ports != set(ports):
        raise Error('Live SSH ports disagree with sshd_config; resolve service command-line overrides first.')
    addresses = json.loads(run('ip', '-j', 'address', 'show'))
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
    routes += json.loads(run('ip', '-j', '-6', 'route', 'show', 'default'))
    interfaces = choose_interfaces(addresses, routes, args.interface)
    safety_checks()
    return {'admin': args.admin, 'port': target, 'previous_ports': ports,
            'stage_ports': sorted(set(ports + [target])), 'interfaces': interfaces,
            'socket': active('ssh.socket'), 'client': info['client'] if info else None}


def plan(args):
    state = preflight(args)
    print(json.dumps(state, indent=2))
    print('\nPLAN ONLY: no files, packages, services, or firewall rules changed.')
    print('Packages:', 'unchanged (--skip-packages)' if args.skip_packages else
          'apt update, upgrade (preserve configuration), install ' + ' '.join(PACKAGES))
    for name, content in configuration(state['interfaces'], state['stage_ports']).items():
        print(f'\n--- {name} ---\n{content}', end='')
    print('\nApply will back up these files and stage a timed rollback before network changes.')
    print('Manual: provider-account MFA/recovery, verified sudo/key access, external IPv4/IPv6 tests, reboot.')
    print('No provider network firewall is required. The host guard enforces the ingress policy.')


def make_run(state: dict) -> tuple[Path, dict]:
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid != os.geteuid():
        raise Error('Unsafe state directory.')
    os.chmod(STATE, 0o700)
    runid = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(4)
    folder = STATE / runid
    folder.mkdir(mode=0o700)
    state.update(id=runid, status='preparing', units=unit_states())
    snapshots = {}
    for index, name in enumerate(PATHS):
        path = Path(name)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise Error(f'Unsupported configuration path: {path}')
        if path.exists():
            original = path.stat()
            backup = folder / f'file-{index}'
            backup.write_bytes(path.read_bytes()); os.chmod(backup, 0o600)
            snapshots[name] = {'backup': backup.name, 'mode': stat.S_IMODE(original.st_mode),
                               'uid': original.st_uid, 'gid': original.st_gid}
        else:
            snapshots[name] = None
    state['files'] = snapshots
    write(folder / 'baseline.txt',
          'Enabled services before script configuration:\n' +
          run('systemctl', 'list-unit-files', '--type=service', '--state=enabled', '--no-pager') +
          '\n\nRecent SSH journal (review privately):\n' +
          run('journalctl', '-u', 'ssh', '-n', '100', '--no-pager', check=False) + '\n', 0o600)
    if shutil.which('nft') and ('inet', 'vps_edge') in parse_tables(run('nft', 'list', 'tables')):
        state['previous_rules'] = run('nft', 'list', 'table', 'inet', 'vps_edge')
    else:
        state['previous_rules'] = None
    script = folder / 'phase1.py'
    script.write_bytes(Path(__file__).resolve().read_bytes()); os.chmod(script, 0o700)
    save_state(folder, state)
    return folder, state


def load(runid: str) -> tuple[Path, dict]:
    if not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{8}', runid):
        raise Error('Invalid run ID.')
    folder = STATE / runid
    state = json.loads(folder.joinpath('state.json').read_text())
    if state['id'] != runid or set(state['files']) != set(PATHS):
        raise Error('Invalid backup manifest.')
    return folder, state


def pending_runs() -> list[str]:
    if not STATE.exists():
        return []
    pending = []
    for path in STATE.glob('*/state.json'):
        state = json.loads(path.read_text())
        if state['status'] not in {'committed', 'rolled_back', 'preparing'}:
            pending.append(state['id'])
    return pending


def timer_units(folder: Path, deadline: float) -> dict[str, str]:
    when = dt.datetime.fromtimestamp(deadline, dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    return {
        f'/etc/systemd/system/{TIMER}.service': f'''[Unit]
Description=Restore uncommitted Phase 1 network settings
StartLimitIntervalSec=0
[Service]
Type=oneshot
TimeoutStartSec=0
Restart=on-failure
RestartSec=10s
ExecStart=/usr/bin/python3 {folder}/phase1.py rollback --run-id {folder.name}
''',
        f'/etc/systemd/system/{TIMER}.timer': f'''[Unit]
Description=Deadline for Phase 1 SSH/firewall confirmation
[Timer]
OnCalendar={when}
Persistent=true
AccuracySec=1s
Unit={TIMER}.service
[Install]
WantedBy=timers.target
''',
    }


def arm_timer(folder: Path, deadline: float):
    for name, value in timer_units(folder, deadline).items():
        write(Path(name), value)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', TIMER + '.timer')
    if not active(TIMER + '.timer'):
        raise Error('Rollback timer did not start; refusing network changes.')


def disarm_timer():
    run('systemctl', 'disable', '--now', TIMER + '.timer', check=False)


def install_files(state: dict, ports: list[int]):
    values = configuration(state['interfaces'], ports)
    for name, value in values.items():
        write(Path(name), value)
    state['hashes'] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in values.items()}


def validate_config(state: dict, ports: list[int]):
    run('/usr/sbin/sshd', '-t')
    for client in (None, state.get('client') or '127.0.0.1'):
        cfg = ssh_config(state['admin'], client)
        for key, expected in SECURITY.items():
            if cfg.get(key) != [expected]:
                raise Error(f'SSH setting {key} is overridden: expected {expected}.')
        if {int(p) for p in cfg.get('port', [])} != set(ports):
            raise Error('An extra Port directive or Match block overrides the managed SSH ports.')
    run('nft', '-c', '-f', '/etc/vps-edge.nft')
    run('fail2ban-client', '-t')
    run('systemd-analyze', 'verify', '/etc/systemd/system/vps-edge.service')


def reload_ssh(state: dict):
    if state['socket']:
        run('systemctl', 'restart', 'ssh.socket', 'ssh.service')
    else:
        run('systemctl', 'reload', 'ssh.service')


def activate(state: dict):
    run('systemctl', 'daemon-reload')
    # Apply directly as an already-active oneshot will not rerun on start.
    run('nft', '-f', '/etc/vps-edge.nft')
    run('systemctl', 'enable', '--now', 'vps-edge.service')
    reload_ssh(state)
    run('systemctl', 'enable', 'fail2ban.service')
    run('systemctl', 'restart', 'fail2ban.service')
    # The packaged service can return before the control socket/jail is ready.
    wait_for_fail2ban()
    run('systemctl', 'enable', '--now', 'apt-daily.timer', 'apt-daily-upgrade.timer')
    state['rules'] = normalize_rules(run('nft', 'list', 'table', 'inet', 'vps_edge'))


def wait_for_fail2ban():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if successful('fail2ban-client', 'ping') and successful('fail2ban-client', 'status', 'sshd'):
            return
        time.sleep(0.25)
    raise Error('Fail2ban did not become ready; inspect its journal.')


def audit(state: dict, ports: list[int]) -> list[str]:
    issues = []
    def check(label, operation):
        try:
            operation()
        except (Error, OSError, ValueError) as exc:
            issues.append(f'{label}: {exc}')
    check('Configuration', lambda: validate_config(state, ports))
    def uplinks():
        addresses = json.loads(run('ip', '-j', 'address', 'show'))
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
        routes += json.loads(run('ip', '-j', '-6', 'route', 'show', 'default'))
        choose_interfaces(addresses, routes, state['interfaces'])
    check('Public interfaces', uplinks)
    for name, expected in state.get('hashes', {}).items():
        if not Path(name).is_file() or hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            issues.append(f'Managed file changed: {name}')
    for unit in ('vps-edge.service', 'fail2ban.service', 'apt-daily.timer', 'apt-daily-upgrade.timer'):
        if not enabled(unit) or not active(unit):
            issues.append(f'{unit} must be enabled and active.')
    check('Fail2ban', lambda: run('fail2ban-client', 'status', 'sshd'))
    check('Fail2ban heartbeat', lambda: run('fail2ban-client', 'ping'))
    def ban_action():
        value = run('fail2ban-client', 'get', 'sshd', 'action', 'nftables', 'port')
        if {int(p) for p in re.findall(r'\d+', value)} != set(ports):
            raise Error('Loaded nftables SSH ban action uses the wrong ports.')
        for key, expected in (('maxretry', '5'), ('findtime', '600'), ('bantime', '3600')):
            if run('fail2ban-client', 'get', 'sshd', key) != expected:
                raise Error(f'Loaded Fail2ban {key} differs from the configured policy.')
    check('Fail2ban action', ban_action)
    def live_rules():
        value = normalize_rules(run('nft', 'list', 'table', 'inet', 'vps_edge'))
        if value != state.get('rules'):
            raise Error('Live vps_edge rules differ from the applied snapshot.')
    check('Firewall', live_rules)
    def listeners():
        raw = run('ss', '-H', '-lntp')
        listening = set()
        for line in raw.splitlines():
            # Ensure these are SSH/systemd listener processes, not another service.
            if not re.search(r'"(?:sshd|sshd-session|systemd)"', line):
                continue
            fields = line.split()
            if len(fields) >= 4 and fields[3].rsplit(':', 1)[-1].isdigit():
                listening.add(int(fields[3].rsplit(':', 1)[-1]))
        if not set(ports) <= listening:
            raise Error(f'Expected SSH listeners on {ports}; saw {sorted(listening)}.')
    check('SSH listeners', listeners)
    return issues


def rollback(folder: Path, state: dict):
    if state['status'] in {'committed', 'rolled_back'}:
        print(f"Run {state['id']} is {state['status']}; nothing to roll back.")
        return
    state['status'] = 'rolling_back'; save_state(folder, state)
    errors = []
    for name, metadata in state['files'].items():
        try:
            path = Path(name)
            if metadata:
                source = folder / metadata['backup']
                if source.parent != folder:
                    raise Error('Invalid backup path.')
                write(path, source.read_bytes(), metadata['mode'])
                os.chown(path, metadata['uid'], metadata['gid'])
            elif path.exists():
                if path.is_symlink():
                    raise Error(f'Refusing to remove symlink: {path}')
                path.unlink()
        except (Error, OSError) as exc:
            errors.append(str(exc))
    # Restore independent layers even if one service fails; in particular a
    # broken old unit must not prevent restoration of the old live guard.
    for label, operation in (
        ('systemd reload', lambda: run('systemctl', 'daemon-reload')),
        ('SSH restore', lambda: reload_ssh(state)),
    ):
        try:
            operation()
        except Error as exc:
            errors.append(f'{label}: {exc}')
    for unit, original in state['units'].items():
        try:
            run('systemctl', 'enable' if original['enabled'] else 'disable', unit, check=False)
            if original['active']:
                run('systemctl', 'restart', unit)
            else:
                run('systemctl', 'stop', unit, check=False)
        except Error as exc:
            errors.append(f'{unit}: {exc}')
    try:
        # The previous live table can differ from its persistent file.
        if state['previous_rules']:
            run('nft', '-f', '-', data='add table inet vps_edge\nflush table inet vps_edge\n' + state['previous_rules'] + '\n')
        elif ('inet', 'vps_edge') in parse_tables(run('nft', 'list', 'tables')):
            run('nft', 'delete', 'table', 'inet', 'vps_edge')
    except Error as exc:
        errors.append(str(exc))
    state['status'] = 'rollback_failed' if errors else 'rolled_back'
    state['rollback_errors'] = errors; save_state(folder, state)
    if errors:
        raise Error('Rollback incomplete; use provider console. ' + '; '.join(errors))
    disarm_timer()
    print(f"ROLLED BACK {state['id']}: managed files/network settings restored. Packages remain installed.")


def apply(args):
    if pending_runs():
        raise Error(f'An unfinished run exists: {pending_runs()}. Commit or roll it back first.')
    if active(TIMER + '.timer'):
        raise Error('An existing rollback timer is active; investigate before another run.')
    state = preflight(args)
    print('Preflight passed:', json.dumps(state), flush=True)
    if not args.skip_packages:
        env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
        for command in (
            ['apt-get', 'update'],
            ['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confold', 'upgrade'],
            ['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confold', 'install', *PACKAGES],
        ):
            print('Running', shlex.join(command), flush=True)
            if subprocess.run(command, env=env).returncode:
                raise Error('Package operation failed. No script-managed network changes have been made.')
    for command in ('nft', 'fail2ban-client', 'unattended-upgrade'):
        if not shutil.which(command):
            raise Error(f'Missing {command}; install prerequisites or omit --skip-packages.')
    safety_checks()
    # Recheck configuration after upgrades before creating the rollback baseline.
    state = preflight(args)
    folder, state = make_run(state)
    state['deadline'] = time.time() + args.rollback_minutes * 60
    save_state(folder, state)
    try:
        arm_timer(folder, state['deadline'])
        state['status'] = 'staging'; save_state(folder, state)
        install_files(state, state['stage_ports'])
        validate_config(state, state['stage_ports'])
        activate(state)
        issues = audit(state, state['stage_ports'])
        if issues:
            raise Error('; '.join(issues))
        if time.time() >= state['deadline']:
            raise Error('Staging exceeded the confirmation deadline; reverting.')
        state['staged_at'] = time.time()
        state['status'] = 'awaiting_commit'; save_state(folder, state)
    except Exception:
        rollback(folder, state)
        raise
    print(f"\nSTAGED RUN: {state['id']}")
    print('Backups and root-owned runner:', folder)
    print('Automatic rollback deadline:', dt.datetime.fromtimestamp(state['deadline'], dt.timezone.utc).isoformat())
    print('Keep this session open. Test a NEW key login with SSH multiplexing disabled:')
    print(f"ssh -p {state['port']} -o ControlMaster=no -o ControlPath=none {state['admin']}@VPS_IP")
    print('After sudo and external IPv4/IPv6 tests, commit FROM THAT NEW SESSION:')
    print(f'sudo /usr/bin/python3 {folder}/phase1.py commit --run-id {state["id"]} --external-checks-passed')
    print('Do not install Docker or reboot before committing. Package upgrades are not rolled back.')


def commit(args, folder: Path, state: dict):
    if state['status'] != 'awaiting_commit':
        raise Error('Only an awaiting_commit run can be committed.')
    if time.time() >= state['deadline']:
        rollback(folder, state)
        raise Error('Deadline expired; the previous network configuration was restored.')
    if not args.external_checks_passed:
        raise Error('Complete external IPv4/IPv6 listener tests and pass --external-checks-passed.')
    info = session()
    check_commit_session(info, state, os.environ.get('SUDO_USER'))
    state['client'] = info['client']
    if not active(TIMER + '.timer'):
        raise Error('Rollback timer is not active. Restore it or roll back before committing.')
    try:
        issues = audit(state, state['stage_ports'])
        if issues:
            raise Error('; '.join(issues))
        install_files(state, [state['port']])
        validate_config(state, [state['port']])
        activate(state)
        issues = audit(state, [state['port']])
        if issues:
            raise Error('; '.join(issues))
        state['status'] = 'committed'; state['committed_at'] = time.time()
        save_state(folder, state)
        disarm_timer()
    except Exception:
        # A failed final-port activation must not leave an unconfirmed lockout.
        state['status'] = 'commit_failed'; save_state(folder, state)
        rollback(folder, state)
        raise
    print(f"COMMITTED {state['id']}: only SSH port {state['port']} permitted on public interfaces.")
    print('Open another SSH connection, then reboot and verify. If an optional upstream firewall exists, retire old SSH-port rules.')


def parser():
    root = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = root.add_subparsers(dest='command', required=True)
    for mode in ('plan', 'apply'):
        p = sub.add_parser(mode, help='Read-only preview' if mode == 'plan' else 'Stage with timed rollback')
        p.add_argument('--admin', default='ubuntu')
        p.add_argument('--ssh-port', type=int, help='Keep current port by default; e.g. 2222 to migrate')
        p.add_argument('--interface', action='append', default=[], help='Repeat for each public uplink; otherwise detected')
        p.add_argument('--skip-packages', action='store_true', help='For already-patched hosts with all prerequisites installed')
        if mode == 'apply':
            p.add_argument('--rollback-minutes', type=int, default=20, choices=range(5, 121), metavar='5..120')
    for mode in ('verify', 'commit', 'rollback'):
        p = sub.add_parser(mode)
        p.add_argument('--run-id', required=True)
        if mode == 'commit':
            p.add_argument('--external-checks-passed', action='store_true')
    return root


@contextlib.contextmanager
def lock():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid != os.geteuid():
        raise Error('Unsafe state directory.')
    os.chmod(STATE, 0o700)
    fd = os.open(STATE / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as handle:
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        require_root()
        if args.command == 'plan':
            plan(args)
        elif args.command == 'verify':
            _, state = load(args.run_id)
            ports = [state['port']] if state['status'] == 'committed' else state['stage_ports']
            issues = audit(state, ports)
            print(f"Run: {state['id']}; state: {state['status']}")
            if issues:
                for issue in issues:
                    print('FAIL:', issue)
                return 1
            print(f"PASS: SSH requires public keys; root/password login disabled; administrator {state['admin']}.")
            print(f"PASS: SSH listener port(s): {', '.join(map(str, ports))}.")
            print(f"PASS: IPv4/IPv6 ingress guard covers detected uplinks: {', '.join(state['interfaces'])}.")
            print('PASS: live guard and managed files match the applied configuration; firewall service is enabled/active.')
            print('PASS: Fail2ban SSH jail is active with matching nftables port(s), 5 retries/10 minutes, 1-hour ban.')
            print('PASS: Ubuntu APT update timers are enabled/active and periodic upgrades are configured.')
            print('MANUAL: prove external port blocking with live listeners, confirm key login/sudo, review updates and reboot.')
            print('SCOPE: no provider firewall required; outbound traffic is allowed; this audit does not certify absence of compromise.')
        else:
            with lock():
                if args.command == 'apply':
                    apply(args)
                else:
                    folder, state = load(args.run_id)
                    if args.command == 'rollback':
                        rollback(folder, state)
                    else:
                        commit(args, folder, state)
        return 0
    except (Error, OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
