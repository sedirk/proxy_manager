from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from proxyworkbench.network_tools import inventory
from proxyworkbench import app_launch
from proxyworkbench.service import Service
from proxyworkbench.troubleshoot import diagnose, problem_url


def option(protocol='http'):
    return {'id': 'ep-test', 'tool_id': 'v2rayn', 'tool_name': 'v2rayN', 'host': '127.0.0.1',
            'port': 10808, 'protocol': protocol, 'proxy_url': protocol+'://127.0.0.1:10808'}


def result(code=200, failed=None):
    return {'layers': [{'layer': failed, 'status': 'failed'}] if failed else [{'layer': 'http', 'status': 'passed', 'http_status': code}]}


class NetworkToolTests(unittest.TestCase):
    def setUp(self):
        self.apps = [
            {'id': 'v2rayn', 'name': 'v2rayN', 'running_processes': [{'pid': 10, 'name': 'v2rayN.exe', 'parent_pid': 1}]},
            {'id': 'xray', 'name': 'Xray', 'running_processes': [{'pid': 11, 'name': 'xray.exe', 'parent_pid': 10}]},
            {'id': 'uu', 'name': '网易 UU', 'running_processes': [{'pid': 20, 'name': 'uu.exe', 'parent_pid': 1}]},
            {'id': 'atrust', 'name': 'aTrust', 'running_processes': [{'pid': 30, 'name': 'aTrustAgent.exe', 'parent_pid': 1}]},
            {'id': 'zerotier', 'name': 'ZeroTier', 'running_processes': [{'pid': 40, 'name': 'zerotier-one_x64.exe', 'parent_pid': 1}]},
        ]
        self.endpoints = [{'id': 'ep-'+str(pid), 'pid': pid, 'app_id': app, 'address': '127.0.0.1', 'port': port,
                           'transport': 'tcp', 'declared_protocol': protocol, 'owner': app+'.exe'}
                          for pid, app, port, protocol in [(11,'xray',10808,'mixed'),(20,'uu',60443,None),
                                                         (30,'atrust',443,None),(40,'zerotier',9993,None)]]

    def test_core_is_grouped_with_observed_parent_and_private_ports_not_offered(self):
        found = inventory(self.apps,self.endpoints,[],{})
        self.assertEqual({tool['id'] for tool in found}, {'v2rayn','uu','atrust','zerotier'})
        manager = next(tool for tool in found if tool['id']=='v2rayn')
        self.assertEqual(manager['process_count'],2)
        self.assertEqual(manager['proxy_options'][0]['proxy_url'],'http://127.0.0.1:10808')
        self.assertTrue(all(not tool['proxy_options'] for tool in found if tool['id']!='v2rayn'))

    def test_no_common_port_guess_or_udp_or_lan_listener_as_generic_proxy(self):
        for protocol, address, transport in [(None,'127.0.0.1','tcp'),('http','192.0.2.1','tcp'),('mixed','0.0.0.0','udp')]:
            endpoint={**self.endpoints[0],'declared_protocol':protocol,'address':address,'transport':transport}
            with self.subTest(endpoint=endpoint):
                self.assertFalse(any(tool['proxy_options'] for tool in inventory(self.apps,[endpoint],[],{})))

    def test_explicit_system_proxy_requires_live_matching_listener_and_never_uu(self):
        system={'evidence_status':'observed','enabled':True,'proxy_server':'127.0.0.1:10808'}
        endpoint={**self.endpoints[0],'declared_protocol':None}
        self.assertTrue(next(tool for tool in inventory(self.apps,[endpoint],[],system) if tool['id']=='v2rayn')['proxy_options'])
        system['proxy_server']='127.0.0.1:60443'
        self.assertFalse(any(tool['proxy_options'] for tool in inventory(self.apps,[self.endpoints[1]],[],system)))
        self.assertFalse(any(tool['proxy_options'] for tool in inventory(self.apps,[],[],system)))

    def test_services_and_interfaces_recognize_not_running_tools_without_network_ids(self):
        found=inventory([],[],[{'name':'ZeroTier [PRIVATE_NETWORK_ID]','description':'ZeroTier Virtual Port','status':'Up','index':5}],{},
                        [{'Name':'aTrustService','State':'Running','DisplayName':'aTrust'}])
        self.assertEqual({tool['id'] for tool in found},{'atrust','zerotier'})
        self.assertNotIn('PRIVATE_NETWORK_ID',json.dumps(found))
        self.assertTrue(next(tool for tool in found if tool['id']=='atrust')['running'])

    def test_installed_only_and_unrelated_process_do_not_create_fabricated_port(self):
        found=inventory([{'id':'v2rayn','name':'v2rayN','installed_locations':[{'path':'fixture'}]}],[],[],{})
        self.assertFalse(found[0]['running'])
        self.assertTrue(found[0]['installed'])
        self.assertFalse(found[0]['proxy_options'])


class DiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.app={'id':'setup','name':'Hermes','launch_profile':{'available':True}}
        self.snapshot={'captured_at':'fixture','network_tools':[{'proxy_options':[option()]}]}
        self.value={'url':'https://example.com/install.ps1'}

    def test_extract_url_and_reject_credentials_queries_and_invalid_schemes(self):
        self.assertEqual(problem_url({'error_text':'GET https://example.com/install.ps1): failed'}),self.value['url'])
        for url in ('file:///private','https://user:secret@example.com','https://example.com/?token=private','http://example.com:99999','https://example.com/#private'):
            with self.subTest(url=url),self.assertRaises(ValueError):problem_url({'url':url})

    def test_recommend_only_successful_http_and_preserve_application_scope(self):
        report=diagnose(self.snapshot,self.app,self.value,lambda url,target,**kw: result(failed='tls') if target['type']=='direct' else result())
        self.assertEqual(report['recommendation']['status'],'proxy_recommended')
        self.assertEqual(report['recommendation']['profile']['proxy_url'],option()['proxy_url'])
        self.assertIn('尚未验证',report['scope'])
        self.assertNotIn('error_text',report)

    def test_protected_or_path_missing_app_cannot_get_restart_profile(self):
        for app in ({**self.app,'protected':True},{**self.app,'launch_profile':{'available':False}}):
            report=diagnose(self.snapshot,app,self.value,lambda url,target,**kw: result(failed='tls') if target['type']=='direct' else result())
            self.assertIsNone(report['recommendation']['profile'])

    def test_http_denials_are_not_recommended_as_working_proxy(self):
        for code in (401,403,404,405,429):
            report=diagnose(self.snapshot,self.app,self.value,lambda *args,**kw:result(code))
            self.assertEqual(report['recommendation']['status'],'http_response')
            self.assertIsNone(report['recommendation']['profile'])

    def test_direct_success_no_needless_proxy_change_and_socks_is_not_http(self):
        report=diagnose(self.snapshot,self.app,self.value,lambda *args,**kw:result())
        self.assertEqual(report['recommendation']['status'],'target_reachable')
        self.snapshot['network_tools'][0]['proxy_options']=[option('socks5')]
        report=diagnose(self.snapshot,self.app,self.value,lambda url,target,**kw:result(failed='tls') if target['type']=='direct' else result())
        self.assertEqual(report['recommendation']['status'],'socks_only')
        self.assertIsNone(report['recommendation']['profile'])

    def test_entrances_bounded_and_caller_cannot_inject_proxy(self):
        self.snapshot['network_tools'][0]['proxy_options']=[{**option(),'id':str(i)} for i in range(20)]
        runner=Mock(return_value=result(failed='tcp'))
        diagnose(self.snapshot,self.app,{**self.value,'proxy_url':'http://evil.example:123'},runner)
        self.assertEqual(runner.call_count,4)
        self.assertTrue(all(call.args[1].get('host','127.0.0.1')=='127.0.0.1' for call in runner.call_args_list))


class GuideServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guide-service-')
        self.root=Path(self.temp.name)
        self.exe=self.root/'setup.exe';self.exe.write_bytes(b'fixture; never executed')
        self.service=Service(self.root,discover=False)
        self.added=self.service.catalog_add_app({'executable':str(self.exe),'name':'Setup'})
        self.service.snapshot={'captured_at':'fixture','network_tools':[{'proxy_options':[option()]}]}
        self.service._catalog_cache=None

    def tearDown(self):
        self.service.close();self.temp.cleanup()

    def check(self):
        with patch.object(self.service,'discover',return_value={}),patch('proxyworkbench.service.probes.probe',side_effect=lambda url,target,**kw:result(failed='tls') if target['type']=='direct' else result()):
            return self.service.guide_check({'app_id':self.added['app_id'],'url':'https://example.com/'})

    def test_check_export_feedback_and_launch_bind_to_verified_app_without_changing_plan(self):
        before=deepcopy(self.service.plan)
        report=self.check()
        profile=self.service.guide_profile({'check_id':report['check_id']})
        self.assertIn(str(self.exe),profile['content'])
        self.assertIn('127.0.0.1:10808',profile['content'])
        with patch('proxyworkbench.app_launch.launch',return_value={'pid':123,'notice':'fixture'}) as launch:
            self.service.guide_launch({'check_id':report['check_id']})
            launch.assert_called_once_with(str(self.exe),option()['proxy_url'])
        self.assertEqual(self.service.guide_feedback({'check_id':report['check_id'],'outcome':'resolved'})['source'],'user_report')
        self.assertEqual(before,self.service.plan)
        self.assertFalse(self.service.relay.status()['running'])

    def test_expired_changed_or_removed_app_and_changed_entrance_refused(self):
        report=self.check();key=report['check_id']
        self.service.guide_checks[key]['at']-=601
        with self.assertRaisesRegex(ValueError,'过期'):self.service.guide_profile({'check_id':key})
        self.service.guide_checks[key]['at']=time.monotonic()
        self.service.snapshot['network_tools']=[]
        with self.assertRaisesRegex(ValueError,'入口已经变化'):self.service.guide_profile({'check_id':key})
        self.service.snapshot['network_tools']=[{'proxy_options':[option()]}]
        self.service.catalog_remove_app({'manual_id':next(app['manual_id'] for app in self.added['catalog']['apps'] if app['id']==self.added['app_id'])})
        with self.assertRaisesRegex(ValueError,'程序记录'):self.service.guide_profile({'check_id':key})


class AppLaunchTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows frozen DLL behavior')
    def test_frozen_dll_search_is_restored_even_when_child_creation_fails(self):
        kernel=Mock()
        def get_directory(length, buffer):
            if buffer is not None:buffer.value='test'
            return 4
        kernel.GetDllDirectoryW.side_effect=get_directory
        kernel.SetDllDirectoryW.return_value=True
        with patch.object(app_launch.sys,'frozen',True,create=True),patch.object(app_launch.ctypes,'WinDLL',return_value=kernel,create=True):
            with self.assertRaisesRegex(RuntimeError,'fixture'):
                with app_launch._external_libraries():raise RuntimeError('fixture')
        self.assertEqual([call.args[0] for call in kernel.SetDllDirectoryW.call_args_list],[None,'test'])

    def test_private_child_environment_existing_instance_and_protection(self):
        with tempfile.TemporaryDirectory(prefix='guide-launch-') as folder:
            path=Path(folder)/'setup.exe';path.write_bytes(b'fixture')
            environment=os.environ.copy()
            with patch.object(app_launch,'_running_images',return_value=[]),patch.object(app_launch.subprocess,'Popen',return_value=Mock(pid=123)) as spawn:
                self.assertEqual(app_launch.launch(str(path),option()['proxy_url'])['pid'],123)
                self.assertEqual(spawn.call_args.kwargs['env']['HTTPS_PROXY'],option()['proxy_url'])
                self.assertEqual(spawn.call_args.kwargs['env']['PYINSTALLER_RESET_ENVIRONMENT'],'1')
                self.assertEqual(spawn.call_args.args[0],[str(path)])
                self.assertEqual(dict(os.environ),environment)
            with patch.object(app_launch,'_running_images',return_value=[{'ExecutablePath':str(path)}]),patch.object(app_launch.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(ValueError,'还在运行'):app_launch.launch(str(path),option()['proxy_url'])
                spawn.assert_not_called()
            protected=Path(folder)/'aTrustAgent.exe';protected.write_bytes(b'fixture')
            with self.assertRaisesRegex(ValueError,'受保护'):app_launch.launch(str(protected),option()['proxy_url'])


if __name__=='__main__':unittest.main()
