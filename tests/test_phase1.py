"""Offline tests: never invoke system commands or modify /etc, accounts, or nftables."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

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

    def test_plan_and_apply_accept_the_same_rollback_window(self):
        for command in ('plan', 'apply'):
            with self.subTest(command=command):
                self.assertEqual(p.parser().parse_args([command]).rollback_minutes, 20)
                self.assertEqual(p.parser().parse_args([command, '--rollback-minutes', '30']).rollback_minutes, 30)
                for value in ('4', '121', 'not-a-number'):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        p.parser().parse_args([command, '--rollback-minutes', value])

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

    def test_failed_ufw_restore_keeps_staged_guard(self):
        folder, state = self.transaction()
        state['previous_rules'] = 'table inet vps_edge { chain old { } }'
        state['units']['vps-edge.service']['active'] = True
        with patch.object(p, 'restore_ufw', side_effect=p.Error('cannot restore UFW')):
            with self.assertRaisesRegex(p.Error, 'keeping the staged ingress guard'):
                p.rollback(folder, state)
        self.assertFalse(any(args == ('nft', '-f', '-') or args[:3] == ('nft', 'delete', 'table')
                             for args, kwargs in self.commands))
        self.assertNotIn((('systemctl', 'restart', 'vps-edge.service'), {}), self.commands)
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
        args = p.parser().parse_args(['plan', '--skip-packages', '--rollback-minutes', '30'])
        original = set(self.root.rglob('*'))
        with patch.object(p, 'preflight', return_value=self.base), contextlib.redirect_stdout(io.StringIO()) as output:
            p.plan(args)
        self.assertIn('Rollback window: 30 minutes', output.getvalue())
        self.assertIn('no timer is armed by plan', output.getvalue())
        self.assertEqual(set(self.root.rglob('*')), original)
        self.assertEqual(self.commands, [])

    def test_apply_starts_socket_activated_ssh_before_post_package_preflight(self):
        for socket_active, service_active, skip_packages in (
            (True, False, False),
            (True, True, False),
            (False, True, False),
            (True, False, True),
        ):
            with self.subTest(socket_active=socket_active, service_active=service_active,
                              skip_packages=skip_packages):
                args = argparse.Namespace(skip_packages=skip_packages, rollback_minutes=20)
                units = {'ssh.socket': socket_active, 'ssh.service': service_active}
                calls = Mock()
                with patch.object(p, 'preflight', side_effect=[self.base, p.Error('second preflight')]) as preflight, \
                     patch.object(p, 'active', side_effect=lambda unit: units.get(unit, False)), \
                     patch.object(p.shutil, 'which', return_value='/mock/tool'), \
                     patch.object(p.subprocess, 'run') as packages, patch.object(p, 'run') as command, \
                     contextlib.redirect_stdout(io.StringIO()):
                    packages.return_value.returncode = 0
                    calls.attach_mock(preflight, 'preflight')
                    calls.attach_mock(packages, 'package')
                    calls.attach_mock(command, 'command')
                    with self.assertRaisesRegex(p.Error, 'second preflight'):
                        p.apply(args)

                expected = ['preflight']
                if not skip_packages:
                    expected.extend(['package'] * 3)
                if socket_active and not service_active and not skip_packages:
                    expected.append('command')
                    command.assert_called_once_with('systemctl', 'start', 'ssh.service')
                expected.append('preflight')
                self.assertEqual([call[0] for call in calls.mock_calls], expected)

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


class UfwMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ufw = self.root / 'etc/ufw'
        self.ufw.mkdir(parents=True)
        self.defaults = self.root / 'etc/default/ufw'
        self.defaults.parent.mkdir()
        self.defaults.write_text('DEFAULT_INPUT_POLICY="DROP"\n')
        self.conffiles = f' {self.defaults} {hashlib.md5(self.defaults.read_bytes()).hexdigest()}'
        self.package_md5sums = ''
        for name in ('before.rules', 'before6.rules', 'after.rules', 'after6.rules',
                     'before.init', 'after.init'):
            path = self.ufw / name
            path.write_text('*filter\nCOMMIT\n' if name.endswith('.rules') else '#!/bin/sh\n')
            packaged = f'iptables/{name}' if name.endswith('.rules') else name
            digest = hashlib.md5(path.read_bytes()).hexdigest()
            self.package_md5sums += f'{digest}  usr/share/ufw/{packaged}\n'
        self.before = self.ufw / 'before.rules'
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(p, 'UFW_ROOT', self.ufw))
        self.stack.enter_context(patch.object(p, 'UFW_DEFAULT', self.defaults))
        self.stack.enter_context(patch.object(p, 'STATE', self.root / 'state'))

    def inspect(self, status='Status: inactive', added='Added user rules:'):
        def fake_run(*args, **kwargs):
            if args == ('dpkg-query', '-W', '-f=${Conffiles}', 'ufw'):
                return self.conffiles
            if args == ('dpkg-query', '--control-show', 'ufw', 'md5sums'):
                return self.package_md5sums
            return added if args[1:3] == ('show', 'added') else status
        with patch.object(p, 'active', return_value=True), \
             patch.object(p, 'enabled', return_value=True), \
             patch.object(p.shutil, 'which', return_value='/mock/ufw'), \
             patch.object(p, 'run', side_effect=fake_run):
            return p.inspect_ufw()

    def test_enabled_service_with_unused_stock_configuration_needs_no_flag(self):
        info = self.inspect()
        self.assertTrue(info['unit']['active'])
        self.assertFalse(info['running'])
        self.assertFalse(info['requires_confirmation'])

    def test_live_policy_requires_explicit_migration(self):
        self.assertTrue(self.inspect(status='Status: active')['requires_confirmation'])

    def test_saved_rules_require_review_even_if_ufw_is_inactive(self):
        self.assertTrue(self.inspect(added='Added user rules:\nufw allow 443/tcp')['requires_confirmation'])

    def test_hand_edited_user_rules_without_metadata_require_review(self):
        (self.ufw / 'user.rules').write_text('-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n')
        self.assertTrue(self.inspect()['requires_confirmation'])

    def test_changed_before_rules_require_review(self):
        self.before.write_text('custom policy')
        self.assertEqual(self.inspect()['review_reasons'],
                         [f'{self.before} differs from the packaged configuration'])

    def test_missing_template_checksums_require_review(self):
        self.package_md5sums = ''
        self.assertTrue(self.inspect()['requires_confirmation'])

    def test_symlink_to_stock_template_requires_review(self):
        target = self.root / 'stock-before.rules'
        self.before.rename(target)
        self.before.symlink_to(target)
        self.assertEqual(self.inspect()['review_reasons'],
                         [f'{self.before} differs from the packaged configuration'])

    def test_unknown_runtime_status_is_rejected(self):
        with self.assertRaisesRegex(p.Error, 'runtime state'):
            self.inspect(status='unrecognized')

    def test_ufw_table_does_not_exempt_unrelated_chains(self):
        raw = json.dumps({'nftables': [{'chain': {'name': 'custom'}}]})
        with patch.object(p, 'run', return_value=raw), self.assertRaisesRegex(p.Error, 'Unrecognized chain'):
            p.check_ufw_table('ip')

    def test_ufw_table_does_not_exempt_unrelated_builtin_rules(self):
        raw = json.dumps({'nftables': [{'rule': {'chain': 'INPUT', 'expr': [{'accept': None}]}}]})
        with patch.object(p, 'run', return_value=raw), self.assertRaisesRegex(p.Error, 'Non-UFW'):
            p.check_ufw_table('ip')

    def test_ufw_compatibility_table_is_recognized(self):
        raw = json.dumps({'nftables': [
            {'chain': {'name': 'INPUT'}}, {'chain': {'name': 'ufw-before-input'}},
            {'rule': {'chain': 'INPUT', 'expr': [{'counter': {}}, {'jump': {'target': 'ufw-before-input'}}]}},
        ]})
        with patch.object(p, 'run', return_value=raw):
            p.check_ufw_table('ip')

    def test_ipv6_ufw_compatibility_table_is_recognized(self):
        raw = json.dumps({'nftables': [
            {'chain': {'name': 'INPUT'}}, {'chain': {'name': 'ufw6-before-input'}},
            {'rule': {'chain': 'INPUT', 'expr': [{'jump': {'target': 'ufw6-before-input'}}]}},
        ]})
        with patch.object(p, 'run', return_value=raw):
            p.check_ufw_table('ip6')

    def test_inactive_runtime_is_restored_even_if_service_was_active(self):
        info = self.inspect()
        folder = self.root / 'backup'
        folder.mkdir()
        p.backup_ufw(folder, info)
        info['migration_started'] = True
        calls = []
        with patch.object(p, 'run', side_effect=lambda *a, **kw: calls.append(a) or 'Status: inactive'):
            p.restore_ufw(folder, {'ufw': info})
        self.assertIn(('systemctl', 'start', 'ufw.service'), calls)
        self.assertIn(('ufw', '--force', 'disable'), calls)
        self.assertNotIn(('ufw', '--force', 'enable'), calls)

    def test_guard_is_required_before_any_ufw_mutation(self):
        with patch.object(p, 'active', return_value=False), patch.object(p, 'run') as run:
            with self.assertRaisesRegex(p.Error, 'guard must be active'):
                p.migrate_ufw({'ufw': self.inspect()})
        run.assert_not_called()

    def test_activation_disables_ufw_after_guard_and_before_ssh_reload(self):
        info = self.inspect()
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            return 'Status: inactive' if args[:2] == ('ufw', 'status') else 'guard'
        with patch.object(p, 'run', side_effect=fake_run), \
             patch.object(p, 'active', side_effect=lambda unit: unit == 'vps-edge.service'), \
             patch.object(p, 'enabled', side_effect=lambda unit: unit == 'vps-edge.service'), \
             patch.object(p, 'save_state'), patch.object(p, 'wait_for_fail2ban'), \
             patch.object(p, 'reload_ssh', side_effect=lambda state: calls.append(('ssh-reload',))), \
             contextlib.redirect_stdout(io.StringIO()):
            p.activate({'id': 'test-run', 'ufw': info})
        guard = calls.index(('systemctl', 'enable', '--now', 'vps-edge.service'))
        disable = calls.index(('ufw', '--force', 'disable'))
        ssh = calls.index(('ssh-reload',))
        self.assertLess(guard, disable)
        self.assertLess(disable, ssh)
        self.assertTrue(info['migration_started'])
        self.assertTrue(info['migrated'])

    def test_ufw_backup_restores_configuration_and_runtime_separately_from_unit(self):
        info = self.inspect(status='Status: active')
        folder = self.root / 'backup'
        folder.mkdir()
        original = self.before.read_text()
        p.backup_ufw(folder, info)
        self.before.write_text('changed')
        info['migration_started'] = True
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            if args == ('ufw', '--force', 'enable'):
                self.assertEqual(self.before.read_text(), original)
            return 'Status: active'
        with patch.object(p, 'run', side_effect=fake_run):
            p.restore_ufw(folder, {'ufw': info})
        self.assertEqual(self.before.read_text(), original)
        self.assertIn(('ufw', '--force', 'enable'), calls)
        self.assertIn(('systemctl', 'enable', 'ufw.service'), calls)

    def test_missing_migration_flag_stops_apply_before_packages_or_backups(self):
        state = {'ufw': self.inspect(status='Status: active')}
        with patch.object(p, 'pending_runs', return_value=[]), \
             patch.object(p, 'active', return_value=False), \
             patch.object(p, 'preflight', return_value=state), \
             patch.object(p.subprocess, 'run') as packages, patch.object(p, 'make_run') as backup, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(p.Error, '--migrate-ufw'):
                p.apply(argparse.Namespace(migrate_ufw=False))
        packages.assert_not_called()
        backup.assert_not_called()


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
