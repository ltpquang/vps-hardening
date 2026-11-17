"""Offline tests: never invoke system commands or modify /etc, accounts, or nftables."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('phase1', Path(__file__).parents[1] / 'scripts/phase1.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class PureTests(unittest.TestCase):
    def setUp(self):
        self.enabled = patch.object(p, 'enabled', return_value=False)
        self.enabled.start()
        self.addCleanup(self.enabled.stop)

    def test_guard_all_ip_families_before_docker_nat_and_no_global_flush(self):
        text = p.nft_config(['ens3', 'ens4'], [2222, 22])
        self.assertIn('table inet vps_edge', text)
        self.assertIn('priority -110', text)
        self.assertIn('iifname { "ens3", "ens4" }', text)
        self.assertIn('tcp dport { 22, 2222 } accept', text)
        self.assertIn('counter drop', text)
        self.assertNotIn('flush ruleset', text)
        self.assertNotIn('3000', text)

    def test_final_port_does_not_reopen_22(self):
        values = p.configuration(['ens3'], [2222])
        self.assertNotIn('Port 22\n', values[p.PATHS[1]])
        self.assertIn('tcp dport { 2222 } accept', values[p.PATHS[2]])
        self.assertIn('port = 2222\n', values[p.PATHS[5]])
        self.assertIn('nftables[type=multiport]', values[p.PATHS[5]])
        self.assertIn('backend = systemd', values[p.PATHS[5]])

    def test_reserved_and_invalid_ports_rejected(self):
        for value in (0, -1, 65536, 'oops', 80, 443, 3000, 2375, 6379):
            with self.subTest(value=value), self.assertRaises(p.Error):
                p.port_number(value)
        self.assertEqual(p.port_number('2222'), 2222)

    def test_discovers_separate_ipv4_ipv6_public_uplinks(self):
        addresses = [
            {'ifname': 'lo', 'addr_info': [{'local': '127.0.0.1'}]},
            {'ifname': 'ens3', 'addr_info': [{'local': '1.1.1.1'}]},
            {'ifname': 'ens4', 'addr_info': [{'local': '2606:4700::1'}]},
        ]
        self.assertEqual(p.choose_interfaces(addresses, [{'dev': 'ens3'}], []), ['ens3', 'ens4'])
        with self.assertRaises(p.Error):
            p.choose_interfaces(addresses, [{'dev': 'ens3'}], ['ens3'])

    def test_private_default_route_still_included(self):
        addresses = [{'ifname': 'ens3', 'addr_info': [{'local': '10.0.0.5'}]}]
        self.assertEqual(p.choose_interfaces(addresses, [{'dev': 'ens3'}], []), ['ens3'])

    def test_bad_or_missing_interface_rejected(self):
        for names in (['lo'], ['eth0'], []):
            with self.subTest(names=names), self.assertRaises(p.Error):
                p.choose_interfaces([{'ifname': 'lo'}], [], names)

    def test_live_counter_changes_do_not_fail_audit(self):
        self.assertEqual(p.normalize_rules('counter packets 1 bytes 80 drop'),
                         p.normalize_rules('counter packets 9 bytes 720 drop'))
        self.assertNotEqual(p.normalize_rules('tcp dport 22 accept'),
                            p.normalize_rules('tcp dport 3000 accept'))

    def test_table_parser_distinguishes_unrecognized_tables(self):
        self.assertEqual(p.parse_tables('table inet vps_edge\ntable ip filter\n'),
                         {('inet', 'vps_edge'), ('ip', 'filter')})

    def test_unparseable_table_is_not_silently_ignored(self):
        with self.assertRaises(p.Error):
            p.parse_tables('table inet "custom.table"')

    def test_waits_for_fail2ban_socket_and_jail_readiness(self):
        with patch.object(p, 'successful', side_effect=[False, True, False, True, True]), \
             patch.object(p.time, 'sleep') as sleep:
            p.wait_for_fail2ban()
        self.assertEqual(sleep.call_count, 2)

    def test_fail2ban_readiness_timeout_is_reported(self):
        with patch.object(p, 'successful', return_value=False), \
             patch.object(p.time, 'monotonic', side_effect=[0, 1, 21]), \
             patch.object(p.time, 'sleep'):
            with self.assertRaisesRegex(p.Error, 'ready'):
                p.wait_for_fail2ban()

    def test_timer_is_persistent_and_calls_saved_root_runner(self):
        folder = Path('/var/lib/vps-phase1/20261117T000000Z-deadbeef')
        values = p.timer_units(folder, 1794873600)
        self.assertIn('Persistent=true', values['/etc/systemd/system/vps-phase1-rollback.timer'])
        service = values['/etc/systemd/system/vps-phase1-rollback.service']
        self.assertIn(str(folder / 'phase1.py'), service)
        self.assertIn('rollback --run-id 20261117T000000Z-deadbeef', service)
        self.assertIn('Restart=on-failure', service)
        self.assertIn('TimeoutStartSec=0', service)

    def test_commit_requires_new_matching_ssh_session(self):
        state = {'admin': 'ubuntu', 'port': 2222, 'staged_at': 100}
        accepted = {'port': 2222, 'started': 101, 'client': '192.0.2.5'}
        p.check_commit_session(accepted, state, 'ubuntu')
        bad = [None, {**accepted, 'port': 22}, {**accepted, 'started': 99}]
        for info in bad:
            with self.subTest(info=info), self.assertRaises(p.Error):
                p.check_commit_session(info, state, 'ubuntu')
        with self.assertRaises(p.Error):
            p.check_commit_session(accepted, state, 'root')

    def test_unknown_firewall_manager_rejected(self):
        with patch.object(p.shutil, 'which', return_value=None), \
             patch.object(p.Path, 'exists', return_value=False), \
             patch.object(p, 'active', side_effect=lambda unit: unit == 'ufw.service'):
            with self.assertRaisesRegex(p.Error, 'ufw'):
                p.safety_checks()

    def test_docker_host_rejected(self):
        with patch.object(p.shutil, 'which', return_value='/usr/bin/docker'):
            with self.assertRaisesRegex(p.Error, 'Docker'):
                p.safety_checks()

    def test_enabled_but_inactive_firewall_manager_is_rejected(self):
        with patch.object(p.shutil, 'which', return_value=None), \
             patch.object(p.Path, 'exists', return_value=False), \
             patch.object(p, 'active', return_value=False), \
             patch.object(p, 'enabled', side_effect=lambda unit: unit == 'nftables.service'):
            with self.assertRaisesRegex(p.Error, 'nftables.service'):
                p.safety_checks()

    def test_unrelated_nft_table_rejected(self):
        with patch.object(p.shutil, 'which', side_effect=lambda c: '/usr/sbin/nft' if c == 'nft' else None), \
             patch.object(p.Path, 'exists', return_value=False), \
             patch.object(p, 'active', return_value=False), \
             patch.object(p, 'run', return_value='table inet custom_policy'):
            with self.assertRaisesRegex(p.Error, 'Unrecognized'):
                p.safety_checks()

    def test_ssh_match_override_is_rejected_before_activation(self):
        config = {key: [value] for key, value in p.SECURITY.items()}
        config['port'] = ['22', '2222']
        override = copy.deepcopy(config); override['passwordauthentication'] = ['yes']
        with patch.object(p, 'run', return_value=''), \
             patch.object(p, 'ssh_config', side_effect=[config, override]):
            with self.assertRaisesRegex(p.Error, 'passwordauthentication'):
                p.validate_config({'admin': 'ubuntu', 'client': '192.0.2.5'}, [22, 2222])

    def test_unmanaged_extra_ssh_port_is_rejected(self):
        config = {key: [value] for key, value in p.SECURITY.items()}
        config['port'] = ['22', '2222']
        with patch.object(p, 'run', return_value=''), patch.object(p, 'ssh_config', return_value=config):
            with self.assertRaisesRegex(p.Error, 'Port directive'):
                p.validate_config({'admin': 'ubuntu'}, [2222])


class FileAndTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.names = tuple(str(self.root / f'config/file-{i}') for i in range(7))
        self.stack.enter_context(patch.object(p, 'PATHS', self.names))
        self.stack.enter_context(patch.object(p, 'STATE', self.root / 'state'))
        self.commands = []
        def fake_run(*args, **kwargs):
            self.commands.append((args, kwargs))
            return ''
        self.stack.enter_context(patch.object(p, 'run', side_effect=fake_run))
        self.stack.enter_context(patch.object(p, 'active', return_value=False))
        self.stack.enter_context(patch.object(p, 'enabled', return_value=False))
        self.disarm = self.stack.enter_context(patch.object(p, 'disarm_timer'))
        self.base = {'admin': 'ubuntu', 'port': 2222, 'previous_ports': [22],
                     'stage_ports': [22, 2222], 'interfaces': ['ens3'],
                     'socket': True, 'client': '192.0.2.5'}

    def transaction(self):
        Path(self.names[0]).parent.mkdir(parents=True, exist_ok=True)
        Path(self.names[0]).write_text('original SSH settings\n')
        os.chmod(self.names[0], 0o640)
        folder, state = p.make_run(copy.deepcopy(self.base))
        state.update(status='awaiting_commit', deadline=time.time() + 1000,
                     staged_at=time.time() - 10, rules='staged')
        p.save_state(folder, state)
        return folder, state

    def test_backup_and_rollback_restore_contents_modes_and_remove_new_files(self):
        folder, state = self.transaction()
        p.install_files(state, state['stage_ports'])
        p.rollback(folder, state)
        self.assertEqual(Path(self.names[0]).read_text(), 'original SSH settings\n')
        self.assertEqual(stat.S_IMODE(Path(self.names[0]).stat().st_mode), 0o640)
        self.assertFalse(Path(self.names[1]).exists())
        self.assertEqual(json.loads((folder / 'state.json').read_text())['status'], 'rolled_back')
        self.disarm.assert_called_once()
        self.assertFalse(any('flush ruleset' in str(c) for c in self.commands))

    def test_live_previous_table_is_restored_after_unit_restarts(self):
        folder, state = self.transaction()
        state['previous_rules'] = 'table inet vps_edge { chain original { } }'
        state['units']['vps-edge.service']['active'] = True
        p.rollback(folder, state)
        restore = next(i for i, (args, kw) in enumerate(self.commands)
                       if args == ('nft', '-f', '-') and 'chain original' in kw['data'])
        restart = next(i for i, (args, _) in enumerate(self.commands)
                       if args == ('systemctl', 'restart', 'vps-edge.service'))
        self.assertGreater(restore, restart)

    def test_failed_old_unit_does_not_prevent_live_firewall_restoration(self):
        folder, state = self.transaction()
        state['previous_rules'] = 'table inet vps_edge { chain original { } }'
        state['units']['vps-edge.service']['active'] = True
        calls = []
        def fail_restart(*args, **kwargs):
            calls.append((args, kwargs))
            if args == ('systemctl', 'restart', 'vps-edge.service'):
                raise p.Error('old file is invalid')
            return ''
        with patch.object(p, 'run', side_effect=fail_restart), self.assertRaisesRegex(p.Error, 'incomplete'):
            p.rollback(folder, state)
        self.assertTrue(any(args == ('nft', '-f', '-') and 'chain original' in kw['data']
                            for args, kw in calls))
        self.assertEqual(state['status'], 'rollback_failed')
        self.disarm.assert_not_called()

    def test_symlink_write_rejected_without_touching_target(self):
        target = self.root / 'target'; target.write_text('keep')
        link = self.root / 'link'; link.symlink_to(target)
        with self.assertRaises(p.Error):
            p.write(link, 'replace')
        self.assertEqual(target.read_text(), 'keep')

    def test_symlink_parent_rejected(self):
        target = self.root / 'directory'; target.mkdir()
        link = self.root / 'linkdir'; link.symlink_to(target)
        with self.assertRaises(p.Error):
            p.write(link / 'new', 'replace')
        self.assertFalse((target / 'new').exists())

    def test_pending_run_blocks_another_apply(self):
        _, state = self.transaction()
        self.assertEqual(p.pending_runs(), [state['id']])
        with self.assertRaisesRegex(p.Error, 'unfinished'):
            p.apply(argparse.Namespace())

    def test_committed_run_cannot_be_rolled_back_accidentally(self):
        folder, state = self.transaction(); state['status'] = 'committed'
        before_commands = list(self.commands)
        with contextlib.redirect_stdout(io.StringIO()):
            p.rollback(folder, state)
        self.assertEqual(self.commands, before_commands)
        self.disarm.assert_not_called()

    def test_plan_does_not_write_files_or_run_package_changes(self):
        args = argparse.Namespace(skip_packages=True)
        original = set(self.root.rglob('*'))
        with patch.object(p, 'preflight', return_value=self.base), contextlib.redirect_stdout(io.StringIO()):
            p.plan(args)
        self.assertEqual(set(self.root.rglob('*')), original)
        self.assertEqual(self.commands, [])

    def test_staging_failure_automatically_restores_backup(self):
        args = argparse.Namespace(skip_packages=True, rollback_minutes=20)
        Path(self.names[0]).parent.mkdir(parents=True)
        Path(self.names[0]).write_text('before')
        with patch.object(p, 'preflight', side_effect=lambda a: copy.deepcopy(self.base)), \
             patch.object(p, 'safety_checks'), patch.object(p.shutil, 'which', return_value='/mock/tool'), \
             patch.object(p, 'arm_timer') as arm, patch.object(p, 'validate_config'), \
             patch.object(p, 'activate', side_effect=p.Error('SSH reload failed')), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(p.Error, 'reload failed'):
                p.apply(args)
        arm.assert_called_once()
        self.assertEqual(Path(self.names[0]).read_text(), 'before')
        statefile = next(p.STATE.glob('*/state.json'))
        self.assertEqual(json.loads(statefile.read_text())['status'], 'rolled_back')

    def test_rollback_timer_failure_prevents_network_activation(self):
        args = argparse.Namespace(skip_packages=True, rollback_minutes=20)
        with patch.object(p, 'preflight', side_effect=lambda a: copy.deepcopy(self.base)), \
             patch.object(p, 'safety_checks'), patch.object(p.shutil, 'which', return_value='/mock/tool'), \
             patch.object(p, 'arm_timer', side_effect=p.Error('timer failed')), \
             patch.object(p, 'install_files') as install, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(p.Error, 'timer failed'):
                p.apply(args)
        install.assert_not_called()
        self.assertEqual(json.loads(next(p.STATE.glob('*/state.json')).read_text())['status'], 'rolled_back')

    def test_successful_staging_retains_old_and_new_ports(self):
        args = argparse.Namespace(skip_packages=True, rollback_minutes=20)
        with patch.object(p, 'preflight', side_effect=lambda a: copy.deepcopy(self.base)), \
             patch.object(p, 'safety_checks'), patch.object(p.shutil, 'which', return_value='/mock/tool'), \
             patch.object(p, 'arm_timer'), patch.object(p, 'validate_config'), \
             patch.object(p, 'activate'), patch.object(p, 'audit', return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()):
            p.apply(args)
        self.assertIn('Port 22\n', Path(self.names[1]).read_text())
        self.assertIn('Port 2222\n', Path(self.names[1]).read_text())
        state = json.loads(next(p.STATE.glob('*/state.json')).read_text())
        self.assertEqual(state['status'], 'awaiting_commit')
        self.disarm.assert_not_called()

    def commit_patches(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(p, 'session', return_value={'client': '192.0.2.5',
                                                                   'port': 2222, 'started': time.time()}))
        stack.enter_context(patch.dict(os.environ, {'SUDO_USER': 'ubuntu'}))
        stack.enter_context(patch.object(p, 'active', return_value=True))
        stack.enter_context(patch.object(p, 'validate_config'))
        stack.enter_context(patch.object(p, 'audit', return_value=[]))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return stack

    def test_commit_removes_old_port_only_after_new_session_check(self):
        folder, state = self.transaction()
        with self.commit_patches(), patch.object(p, 'activate'):
            p.commit(argparse.Namespace(external_checks_passed=True), folder, state)
        self.assertNotIn('Port 22\n', Path(self.names[1]).read_text())
        self.assertIn('Port 2222\n', Path(self.names[1]).read_text())
        self.assertEqual(state['status'], 'committed')
        self.disarm.assert_called_once()

    def test_failed_commit_activation_rolls_back(self):
        folder, state = self.transaction()
        with self.commit_patches(), patch.object(p, 'activate', side_effect=p.Error('cannot bind')):
            with self.assertRaisesRegex(p.Error, 'cannot bind'):
                p.commit(argparse.Namespace(external_checks_passed=True), folder, state)
        self.assertEqual(state['status'], 'rolled_back')
        self.assertEqual(Path(self.names[0]).read_text(), 'original SSH settings\n')

    def test_commit_rejects_missing_external_assertion(self):
        folder, state = self.transaction()
        with self.assertRaisesRegex(p.Error, 'external'):
            p.commit(argparse.Namespace(external_checks_passed=False), folder, state)
        self.assertEqual(Path(self.names[0]).read_text(), 'original SSH settings\n')

    def test_expired_deadline_restores_configuration(self):
        folder, state = self.transaction(); state['deadline'] = time.time() - 10
        p.install_files(state, state['stage_ports'])
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(p.Error, 'expired'):
            p.commit(argparse.Namespace(external_checks_passed=True), folder, state)
        self.assertEqual(state['status'], 'rolled_back')
        self.assertEqual(Path(self.names[0]).read_text(), 'original SSH settings\n')


class AuditTests(unittest.TestCase):
    def audit(self, *, nft='counter drop', ban_port='2222', listener='sshd', uplink='ens3'):
        state = {'admin': 'ubuntu', 'client': '192.0.2.5', 'rules': 'counter drop', 'interfaces': ['ens3']}
        def fake_run(*args, **kwargs):
            if args[0] == 'ip':
                if 'address' in args:
                    return json.dumps([{'ifname': 'ens3', 'addr_info': []},
                                       {'ifname': 'ens4', 'addr_info': []}])
                return json.dumps([{'dev': uplink}])
            if args[0] == 'nft':
                return nft
            if args[0] == 'ss':
                return f'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("{listener}",pid=100,fd=3))'
            if args[-1] == 'port':
                return ban_port
            return {'maxretry': '5', 'findtime': '600', 'bantime': '3600'}.get(args[-1], 'OK')
        with patch.object(p, 'validate_config'), patch.object(p, 'run', side_effect=fake_run), \
             patch.object(p, 'active', return_value=True), patch.object(p, 'enabled', return_value=True):
            return p.audit(state, [2222])

    def test_audit_accepts_expected_rules_and_loaded_ban_port(self):
        self.assertEqual(self.audit(), [])

    def test_audit_detects_live_firewall_drift(self):
        self.assertTrue(any('Firewall:' in x for x in self.audit(nft='tcp dport 3000 accept')))

    def test_audit_detects_wrong_loaded_fail2ban_port(self):
        self.assertTrue(any('Fail2ban action:' in x for x in self.audit(ban_port='22')))

    def test_audit_does_not_count_another_service_as_ssh(self):
        self.assertTrue(any('SSH listeners:' in x for x in self.audit(listener='python3')))

    def test_audit_detects_new_unprotected_default_route_after_reboot(self):
        self.assertTrue(any('Public interfaces:' in x for x in self.audit(uplink='ens4')))


if __name__ == '__main__':
    unittest.main()
