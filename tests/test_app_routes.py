from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from proxyworkbench.service import Service
from proxyworkbench import app_launch


class AppRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='app-routes-')
        self.root=Path(self.temp.name)
        self.exe=self.root/'Hermes-Setup.exe';self.exe.write_bytes(b'fixture; never run')
        self.service=Service(self.root,discover=False)
        added=self.service.catalog_add_app({'executable':str(self.exe),'name':'Hermes'})
        self.app_id=added['app_id']
        self.service.snapshot={'network_tools':[{'proxy_options':[{'proxy_url':'http://127.0.0.1:10808','protocol':'http'}]}]}
        self.service._catalog_cache=None

    def tearDown(self):self.service.close();self.temp.cleanup()

    def save(self,mode='http_environment',url='http://127.0.0.1:10808'):
        return self.service.app_route_save({'app_id':self.app_id,'mode':mode,'proxy_url':url})

    def test_save_is_persistent_and_does_not_start_apps_or_change_relay_plan(self):
        plan=deepcopy(self.service.plan)
        with patch('proxyworkbench.app_launch.launch') as launch:
            state=self.save();launch.assert_not_called()
        route=next(item for item in state['routes'] if item['app_id']==self.app_id)
        self.assertTrue(route['saved']);self.assertTrue(route['can_apply'])
        self.assertIn('Electron',route['notice'])
        self.service.close();self.service=Service(self.root,discover=False)
        route=next(item for item in self.service.app_routes_state()['routes'] if item['app_id']==self.app_id)
        self.assertEqual(route['proxy_url'],'http://127.0.0.1:10808')
        self.assertEqual(plan,self.service.plan);self.assertFalse(self.service.relay.status()['running'])

    def test_launch_uses_saved_route_and_ignores_supplied_overrides(self):
        self.save()
        with patch('proxyworkbench.app_launch.launch',return_value={'pid':12,'notice':'fixture'}) as launch:
            state=self.service.app_route_launch({'app_id':self.app_id,'proxy_url':'http://evil.example:999','mode':'inherit'})
            launch.assert_called_once_with(str(self.exe),'http://127.0.0.1:10808','http_environment')
        route=next(item for item in state['routes'] if item['app_id']==self.app_id)
        self.assertEqual(route['session']['pid'],12)

    def test_missing_save_changed_entrance_or_protected_target_refuses_launch(self):
        with self.assertRaisesRegex(ValueError,'先保存'):self.service.app_route_launch({'app_id':self.app_id})
        self.save();self.service.snapshot={'network_tools':[]}
        with patch('proxyworkbench.app_launch.launch') as launch:
            with self.assertRaisesRegex(ValueError,'入口已变化'):self.service.app_route_launch({'app_id':self.app_id})
            launch.assert_not_called()
        protected=self.root/'aTrustAgent.exe';protected.write_bytes(b'fixture')
        added=self.service.catalog_add_app({'executable':str(protected)})
        with self.assertRaisesRegex(ValueError,'受保护'):self.service.app_route_save({'app_id':added['app_id'],'mode':'inherit'})

    def test_default_and_clear_environment_persist_without_making_a_direct_routing_claim(self):
        for mode in ('inherit','clear_environment'):
            state=self.save(mode)
            route=next(item for item in state['routes'] if item['app_id']==self.app_id)
            self.assertEqual(route['mode'],mode);self.assertEqual(route['proxy_url'],'')
            self.assertIn('不保证',route['notice'])

    def test_failed_write_and_corrupt_file_are_not_silently_replaced(self):
        self.save();before=(self.root/'.local/app-routes.json').read_bytes()
        with patch.object(self.service.store,'write',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):self.save('inherit')
        self.assertEqual((self.root/'.local/app-routes.json').read_bytes(),before)
        (self.root/'.local/app-routes.json').write_text('invalid',encoding='utf-8')
        self.assertTrue(self.service.app_routes_state()['error'])
        with self.assertRaises(ValueError):self.save()
        self.assertEqual((self.root/'.local/app-routes.json').read_text(encoding='utf-8'),'invalid')

    def test_vpn_private_ports_and_unrecognized_loopback_ports_cannot_be_saved_as_proxies(self):
        for url in ('http://127.0.0.1:9993','http://127.0.0.1:60443','http://192.0.2.1:10808'):
            with self.subTest(url=url),self.assertRaises(ValueError):self.save(url=url)


class NativeAppModeTests(unittest.TestCase):
    def test_electron_download_proxy_replaces_conflicting_inherited_settings_only_in_child(self):
        with tempfile.TemporaryDirectory(prefix='electron-launch-') as folder:
            executable=Path(folder)/'Hermes-Setup.exe';executable.write_bytes(b'fixture')
            inherited={'https_proxy':'http://127.0.0.1:1111','electron_get_use_proxy':'0',
                       'global_agent_https_proxy':'http://127.0.0.1:2222',
                       'GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE':'OLD_',
                       'GLOBAL_AGENT_NO_PROXY':'*','UNRELATED_SETTING':'keep'}
            with patch.dict(os.environ,inherited,clear=True),patch.object(app_launch,'_running_images',return_value=[]),patch.object(app_launch.subprocess,'Popen',return_value=Mock(pid=42)) as spawn:
                before=dict(os.environ)
                app_launch.launch(str(executable),'http://[::1]:10808')
                environment=spawn.call_args.kwargs['env']
                self.assertEqual(environment['ELECTRON_GET_USE_PROXY'],'1')
                for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','GLOBAL_AGENT_HTTP_PROXY','GLOBAL_AGENT_HTTPS_PROXY'):
                    self.assertEqual(environment[name],'http://[::1]:10808')
                self.assertEqual(environment['GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE'],'GLOBAL_AGENT_')
                self.assertNotEqual(environment['GLOBAL_AGENT_NO_PROXY'],'*')
                self.assertEqual(environment['UNRELATED_SETTING'],'keep')
                self.assertNotIn('https_proxy',environment)
                self.assertEqual(dict(os.environ),before)

    def test_clear_removes_electron_proxy_overrides_and_inherit_preserves_them(self):
        with tempfile.TemporaryDirectory(prefix='electron-clear-') as folder:
            executable=Path(folder)/'Hermes-Setup.exe';executable.write_bytes(b'fixture')
            inherited={'HTTPS_PROXY':'http://127.0.0.1:1111','electron_get_use_proxy':'1',
                       'global_agent_http_proxy':'http://127.0.0.1:2222',
                       'GLOBAL_AGENT_HTTPS_PROXY':'http://127.0.0.1:3333',
                       'global_agent_no_proxy':'example.test',
                       'GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE':'OLD_','UNRELATED_SETTING':'keep'}
            with patch.dict(os.environ,inherited,clear=True),patch.object(app_launch,'_running_images',return_value=[]),patch.object(app_launch.subprocess,'Popen',return_value=Mock(pid=42)) as spawn:
                before=dict(os.environ)
                app_launch.launch(str(executable),'','clear_environment')
                self.assertEqual(spawn.call_args.kwargs['env'],{'UNRELATED_SETTING':'keep','PYINSTALLER_RESET_ENVIRONMENT':'1'})
                app_launch.launch(str(executable),'','inherit')
                self.assertEqual(spawn.call_args.kwargs['env'],{**before,'PYINSTALLER_RESET_ENVIRONMENT':'1'})
                self.assertEqual(dict(os.environ),before)

    def test_browser_flags_clear_and_inherit_are_applied_only_to_new_child(self):
        with tempfile.TemporaryDirectory(prefix='browser-launch-') as folder:
            executable=Path(folder)/'chrome.exe';executable.write_bytes(b'fixture')
            with patch.object(app_launch,'_running_images',return_value=[]),patch.object(app_launch.subprocess,'Popen',return_value=Mock(pid=42)) as spawn,patch.dict(os.environ,{'HTTPS_PROXY':'http://127.0.0.1:1111'}):
                app_launch.launch(str(executable),'http://127.0.0.1:10808')
                self.assertIn('--proxy-server=http://127.0.0.1:10808',spawn.call_args.args[0])
                app_launch.launch(str(executable),'','clear_environment')
                self.assertIn('--no-proxy-server',spawn.call_args.args[0]);self.assertNotIn('HTTPS_PROXY',spawn.call_args.kwargs['env'])
                app_launch.launch(str(executable),'','inherit')
                self.assertEqual(spawn.call_args.args[0],[str(executable)])
                self.assertEqual(spawn.call_args.kwargs['env']['HTTPS_PROXY'],'http://127.0.0.1:1111')
                self.assertEqual(os.environ['HTTPS_PROXY'],'http://127.0.0.1:1111')


if __name__=='__main__':unittest.main()
