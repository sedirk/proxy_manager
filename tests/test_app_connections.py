from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

from proxyworkbench import app_connections as connections, hermes_adapter as hermes, process_proxy
from proxyworkbench import app_shortcuts
from proxyworkbench.app_routes import route_key
from proxyworkbench.catalog import Catalog
from proxyworkbench.service import Service


class ApplicationConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flowdesk-connections-')
        self.root = Path(self.temp.name)
        self.home = self.root / 'hermes'
        self.exe = self.home / 'hermes-agent/apps/desktop/release/win-unpacked/Hermes.exe'
        for path in (self.exe, self.home/'bin/hermes.exe', self.home/'hermes-agent/hermes_cli/main.py',
                     self.exe.parent/'resources/app.asar'):
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'fixture; never execute')
        self.record = {'key': route_key(str(self.exe)), 'executable': str(self.exe), 'mode': 'http_environment',
                       'proxy_url': 'http://127.0.0.1:45678', 'updated_at': ''}
        (self.root/'.local').mkdir()
        (self.root/'.local/app-routes.json').write_text(json.dumps({'schema_version':1,'routes':[self.record]}),encoding='utf-8')
        self.install = hermes.installation(str(self.exe))
        self.birth = round(datetime.now(timezone.utc).timestamp()*100)
        self.process = {'ProcessId':12345,'ParentProcessId':1,'ExecutablePath':str(self.home/'tools/python/python.exe'),
                        'Started':str((self.birth*100000)+116444736000000000),
                        'CommandLine':f'"{self.home}/tools/python/python.exe" -m hermes_cli.main --profile default gateway run --quiet'}
        self.state = {'pid':12345,'hermes_home':str(self.home),'start_time':self.birth,'active_agents':0,
                      'updated_at':datetime.now(timezone.utc).isoformat()}
        self.write_state()
        self.socket = patch.object(connections.socket,'create_connection',return_value=Mock(__enter__=Mock(),__exit__=Mock(return_value=False)))
        self.socket.start()
        self.facts = patch.object(process_proxy,'records',return_value=[self.process]); self.facts.start()
        self.argv = patch.object(process_proxy,'argv',return_value=['python.exe','-m','hermes_cli.main','--profile','default','gateway','run','--quiet']);self.argv.start()
        self.env = patch.object(process_proxy,'proxy_values',return_value={});self.env_mock=self.env.start()
        self.home_patch=patch.object(hermes,'desktop_home',return_value=str(self.home));self.home_patch.start()

    def tearDown(self):
        self.home_patch.stop();self.env.stop();self.argv.stop();self.facts.stop();self.socket.stop();self.temp.cleanup()

    def write_state(self):
        (self.home/'gateway_state.json').write_text(json.dumps(self.state),encoding='utf-8')

    def test_installation_never_confuses_cli_or_setup_with_gui(self):
        self.assertIsNotNone(self.install)
        self.assertIsNone(hermes.installation(str(self.home/'bin/hermes.exe')))
        self.assertIsNone(hermes.installation(str(self.home/'Hermes-Setup.exe')))
        self.assertEqual(hermes.describe(str(self.home/'Hermes-Setup.exe'))['id'],'installer')

    def test_missing_backend_proxy_is_observed_and_restart_requires_review(self):
        report=connections.inspect(self.record)
        self.assertIn('缺少',report['summary'])
        self.assertNotIn('_install',connections.public_check(report))
        with patch.object(hermes,'apply') as apply:
            prepared=connections.plan(self.record)
            self.assertTrue(prepared['can_launch']);self.assertTrue(prepared['requires_confirmation'])
            self.assertTrue(any('所有 profile' in step for step in prepared['steps']))
            apply.assert_not_called()

    def test_recycled_pid_wrong_home_stale_or_unknown_command_cannot_restart(self):
        for key,value in [('start_time',self.birth-1000),('hermes_home',str(self.root/'other')),
                          ('updated_at','2020-01-01T00:00:00+00:00'),('active_agents',None)]:
            with self.subTest(key=key):
                old=self.state[key];self.state[key]=value;self.write_state()
                self.assertFalse(connections.plan(self.record)['can_launch'])
                self.state[key]=old
        self.write_state()
        with patch.object(process_proxy,'argv',return_value=['python.exe','-c','gateway run']):
            self.assertFalse(connections.plan(self.record)['can_launch'])

    def test_active_tasks_and_dead_proxy_block_without_mutation(self):
        self.state['active_agents']=1;self.write_state()
        self.assertFalse(connections.plan(self.record)['can_launch'])
        self.state['active_agents']=0;self.write_state()
        with patch.object(connections.socket,'create_connection',side_effect=OSError('fixture')):
            prepared=connections.plan(self.record)
        self.assertFalse(prepared['can_launch']);self.assertIn('代理入口',prepared['summary'])

    def test_old_desktop_environment_and_external_home_refuse_application(self):
        desktop={'ProcessId':77,'ParentProcessId':1,'ExecutablePath':str(self.exe),'Started':'100'}
        with patch.object(process_proxy,'records',return_value=[self.process,desktop]):
            self.assertIn('退出旧窗口',connections.plan(self.record)['summary'])
        with patch.object(hermes,'desktop_home',return_value=str(self.root/'another-home')):
            self.assertFalse(connections.plan(self.record)['can_launch'])

    def test_clear_checks_electron_overrides_and_case_insensitive_inherit(self):
        self.assertEqual(connections._proxy_comparison({'GLOBAL_AGENT_HTTP_PROXY':'http://127.0.0.1:1'},{}),'different')
        self.assertEqual(connections._proxy_comparison({'NO_PROXY':'localhost'},{'no_proxy':'localhost'}),'matches')

    def test_save_cannot_replace_an_application_being_applied(self):
        service=Service(self.root,discover=False)
        try:
            added=service.catalog_add_app({'executable':str(self.exe)})
            with connections.launch_lock(self.root,self.record['key']):
                with self.assertRaisesRegex(ValueError,'正在进行'):
                    service.app_route_save({'app_id':added['app_id'],'mode':'clear_environment'})
        finally:service.close()

    def test_ticket_cannot_be_replayed_or_used_after_save_changes(self):
        reviews=connections.LaunchReviews(self.root)
        prepared=reviews.prepare(self.record)
        changed={**self.record,'mode':'inherit','proxy_url':''}
        with self.assertRaisesRegex(ValueError,'过期|改变'):
            reviews.apply(changed,prepared['ticket'])
        with self.assertRaisesRegex(ValueError,'过期|改变'):
            reviews.apply(self.record,prepared['ticket'])

    def test_recheck_before_execute_refuses_new_process_and_changed_saved_route(self):
        prepared=connections.plan(self.record)
        self.process['Started']=str(int(self.process['Started'])+100000000)
        with patch.object(hermes,'apply') as apply:
            with self.assertRaisesRegex(ValueError,'状态已变化'):
                connections.execute(self.root,self.record,prepared)
            apply.assert_not_called()
        (self.root/'.local/app-routes.json').write_text(json.dumps({'schema_version':1,'routes':[]}),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'设置已变化'):
            connections.execute(self.root,self.record,prepared)

    def test_success_requires_post_restart_environment_and_ready_evidence(self):
        prepared=connections.plan(self.record)
        expected=hermes.environment({},'http_environment',self.record['proxy_url'],self.install)
        with patch.object(hermes,'apply',side_effect=lambda *a,**k:setattr(self.env_mock,'return_value',expected)) as apply, patch.object(connections.app_launch,'launch',return_value={'pid':8}) as launch:
            result=connections.execute(self.root,self.record,prepared)
            self.assertIn('尚未验证',result['notice'])
            self.assertTrue(apply.call_args.kwargs['restart'])
            self.assertEqual(launch.call_args.kwargs['environment']['HERMES_HOME'],str(self.home))
            self.assertIn('192.168.0.0/16',launch.call_args.kwargs['environment']['NO_PROXY'])
        self.env_mock.return_value={}
        prepared=connections.plan(self.record)
        with patch.object(hermes,'apply'),patch.object(connections.app_launch,'launch') as launch:
            with self.assertRaisesRegex(ValueError,'尚未确认'):
                connections.execute(self.root,self.record,prepared)
            launch.assert_not_called()

    def test_already_matching_backend_is_reused_without_restart(self):
        self.env_mock.return_value=hermes.environment({},'http_environment',self.record['proxy_url'],self.install)
        prepared=connections.plan(self.record)
        self.assertFalse(prepared['requires_confirmation'])
        with patch.object(hermes,'apply') as apply,patch.object(connections.app_launch,'launch'):
            connections.execute(self.root,self.record,prepared)
        self.assertFalse(apply.call_args.kwargs['restart'])

    def test_private_proxy_values_and_entire_command_line_are_not_returned(self):
        self.env_mock.return_value={'HTTPS_PROXY':'http://name:secret@127.0.0.1:9/private?token=secret','NO_PROXY':'*'}
        report=json.dumps(connections.public_check(connections.inspect(self.record)))
        for private in ('secret','private?','CommandLine','--profile'):
            self.assertNotIn(private,report)

    def test_hermes_cli_arguments_use_root_profile_and_keep_live_work_guard(self):
        fake=Mock(returncode=0);fake.communicate.return_value=(b'fixture',b'')
        env=hermes.environment({'HERMES_PROFILE':'qwen','UNRELATED':'keep'},'http_environment',self.record['proxy_url'],self.install)
        with patch.object(hermes.subprocess,'Popen',return_value=fake) as spawn:
            hermes.command(self.install,['restart','--detach'],env)
        self.assertEqual(spawn.call_args.args[0],[self.install['cli'],'-p','default','gateway','restart','--detach'])
        self.assertEqual(spawn.call_args.kwargs['stdin'],subprocess.DEVNULL)
        self.assertNotIn('HERMES_PROFILE',env);self.assertEqual(env['UNRELATED'],'keep')

    def test_timed_out_lifecycle_is_not_killed_or_followed_by_ensure(self):
        fake=Mock(returncode=None)
        fake.wait.side_effect=subprocess.TimeoutExpired('fixture',120)
        with patch.object(hermes.subprocess,'Popen',return_value=fake) as spawn:
            with self.assertRaisesRegex(ValueError,'仍未结束'):
                hermes.apply(self.install,{},restart=True)
        self.assertEqual(spawn.call_count,1)
        fake.kill.assert_not_called();fake.terminate.assert_not_called()

    def test_pending_official_restart_prevents_another_apply(self):
        pending={'Name':'hermes.exe','ExecutablePath':self.install['cli'],
                 'ProcessId':45678,'Started':'1','CommandLine':subprocess.list2cmdline(
                     [self.install['cli'],'-p','default','gateway','restart','--detach'])}
        arguments=lambda command: ([self.install['cli'],'-p','default','gateway','restart','--detach']
            if command==pending['CommandLine'] else ['python.exe','-m','hermes_cli.main','gateway','run'])
        with patch.object(process_proxy,'records',return_value=[self.process,pending]),patch.object(process_proxy,'argv',side_effect=arguments):
            preview=connections.plan(self.record)
        self.assertFalse(preview['can_launch'])
        self.assertIn('上一项后台操作',preview['summary'])

    def test_shortcut_cancel_never_applies_and_uses_latest_saved_route(self):
        with patch.object(connections,'execute') as execute:
            result=app_shortcuts.launch_saved(self.root,self.record['key'],confirm=lambda _:False)
            self.assertTrue(result['cancelled']);execute.assert_not_called()
        with self.assertRaisesRegex(ValueError,'标识'):
            app_shortcuts.launch_saved(self.root,'../anything')

    def test_api_prepare_and_inspect_require_saved_program_not_request_overrides(self):
        service=Service(self.root,discover=False)
        try:
            added=service.catalog_add_app({'executable':str(self.exe),'name':'Hermes'})
            service.snapshot={'network_tools':[{'proxy_options':[{'protocol':'http','proxy_url':self.record['proxy_url']}]}]}
            self.assertIn('缺少',service.app_route_inspect({'app_id':added['app_id']})['summary'])
            with patch.object(connections,'execute',return_value={'pid':12345,'notice':'fixture'}) as execute:
                preview=service.app_route_prepare({'app_id':added['app_id']})
                service.app_route_launch({'app_id':added['app_id'],'ticket':preview['ticket'],'mode':'clear_environment'})
                self.assertEqual(execute.call_args.args[1]['mode'],'http_environment')
        finally:
            service.close()


@unittest.skipUnless(os.name=='nt','Windows process environment and shortcuts')
class WindowsConnectionFixtureTests(unittest.TestCase):
    def test_concurrent_helpers_preserve_the_mocked_process_dll_directory(self):
        launch=connections.app_launch
        current={'path':'fixture-bundle'}
        def get_directory(size,buffer):
            if buffer is not None:buffer.value=current['path'] or ''
            return len(current['path'] or '')
        def set_directory(value):
            current['path']=value
            return True
        kernel=Mock();kernel.GetDllDirectoryW.side_effect=get_directory;kernel.SetDllDirectoryW.side_effect=set_directory
        first=threading.Event();second_started=threading.Event();second_entered=threading.Event();release=threading.Event()
        failures=[]
        def helper(initial):
            try:
                if not initial:
                    first.wait(2);second_started.set()
                with launch._external_libraries():
                    self.assertIsNone(current['path'])
                    if initial:
                        first.set();release.wait(2)
                    else:second_entered.set()
            except BaseException as error:failures.append(error)
        with patch.object(sys,'frozen',True,create=True),patch.object(launch.ctypes,'WinDLL',return_value=kernel):
            workers=[threading.Thread(target=helper,args=(value,)) for value in (True,False)]
            for worker in workers:worker.start()
            try:
                self.assertTrue(second_started.wait(2))
                self.assertFalse(second_entered.wait(.05))
            finally:
                release.set()
                for worker in workers:worker.join(3)
        self.assertFalse(failures);self.assertTrue(second_entered.is_set())
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(current['path'],'fixture-bundle')

    def test_read_only_proxy_evidence_from_owned_fixture_process(self):
        environment={**os.environ,'HTTP_PROXY':'http://127.0.0.1:43210','FIXTURE_PRIVATE_TOKEN':'must-not-appear'}
        child=subprocess.Popen([sys.executable,'-I','-c','import sys; sys.stdin.read()'],env=environment,stdin=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            item=next(p for p in process_proxy.records() if p['ProcessId']==child.pid)
            values=process_proxy.proxy_values(item)
            self.assertEqual(values['HTTP_PROXY'],'http://127.0.0.1:43210')
            self.assertNotIn('must-not-appear',json.dumps(values))
            item['Started']='0'
            with self.assertRaises(ValueError):process_proxy.proxy_values(item)
        finally:
            child.communicate(b'',timeout=5)

    def test_shortcut_unicode_path_uses_argv_without_running_target(self):
        with tempfile.TemporaryDirectory(prefix='flowdesk-shortcut-') as folder:
            root=Path(folder)/'中文 with spaces';root.mkdir()
            executable=root/'fixture.exe';executable.write_bytes(b'fixture; never run')
            record={'key':route_key(str(executable)),'executable':str(executable)}
            created=app_shortcuts.create(root,record,'测试 app',directory=root)
            path=Path(created['path']);self.assertTrue(path.is_file())
            self.assertEqual(app_shortcuts.create(root,record,'测试 app',directory=root)['path'],str(path))
            other=root/'other.exe';other.write_bytes(b'fixture')
            second={'key':route_key(str(other)),'executable':str(other)}
            alternate=app_shortcuts.create(root,second,'测试 app',directory=root)['path']
            self.assertNotEqual(alternate,str(path))
            self.assertEqual(app_shortcuts.create(root,second,'测试 app',directory=root)['path'],alternate)


if __name__=='__main__':unittest.main()
