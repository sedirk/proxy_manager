"""Built-in capabilities used by the shared inspect/plan/apply workflow.

Adapters provide facts, environment policy and supported lifecycle operations.
The orchestrator owns process reads, guards, approval tickets and verification.
There is no user-supplied executable plugin or arbitrary lifecycle command.
"""
import os
from pathlib import Path

from . import hermes_adapter
from .proxy_environment import child_environment


class ApplicationAdapter:
    id = 'process_environment'
    label = '普通应用 · 新进程环境'
    managed_backend = False
    supported = True
    explicit_proxy_arguments = False
    integration = None
    notice = '软件需要支持代理环境变量；清除变量不保证绕过软件私有代理、系统代理或 TUN。'
    backend_label = '独立后台'
    restart_scope = '通过适配的生命周期接口重启后台；同一后台承载的任务或窗口可能短暂重连。'
    identity_notice = '无法确认窗口的数据目录与后台身份一致，当前不能自动重配。'

    def __init__(self, executable):
        self.executable = executable

    @property
    def capabilities(self):
        return {'adapter_id': self.id, 'managed_backend': self.managed_backend,
                'can_apply': self.supported, 'proxy_environment': True,
                'explicit_proxy_arguments': self.explicit_proxy_arguments,
                'launch_label': '应用并打开' if self.managed_backend else '按此设置启动',
                'verification_scope': '代理环境与已适配后台状态；真实业务仍需原软件复测'}

    @property
    def description(self):
        return {'id': self.id, 'label': self.label, 'notice': self.notice,
                'can_apply': self.supported, 'capabilities': self.capabilities}

    @property
    def identity(self):
        return [self.id, self.executable]

    def environment(self, inherited, record):
        return child_environment(inherited, record['mode'], record['proxy_url'])

    def backend(self, items):
        return {'state': 'unsupported'}

    def context_matches(self, values):
        return True

    def lifecycle_pending(self, items):
        return False

    def checks(self):
        return []

    def apply_backend(self, environment, *, restart):
        """Concrete backends must preserve their own live-work guard and await readiness."""
        raise ValueError('该应用没有受支持的后台生命周期操作')


class ChromiumAdapter(ApplicationAdapter):
    id = 'chromium_arguments'
    label = '浏览器 · 显式参数与新进程环境'
    explicit_proxy_arguments = True
    notice = '启动时使用浏览器显式代理参数；组织策略、已有实例及实际请求仍需核对。'

    def checks(self):
        return [{'label': '显式代理参数', 'status': 'unknown',
                 'detail': '本次只核对进程代理环境，没有读取浏览器启动参数或组织策略；环境一致不能证明显式代理设置及实际请求已生效。'}]


class ManagedBackendAdapter(ApplicationAdapter):
    """Capability base; concrete adapters must provide verified backend facts."""
    managed_backend = True

    def backend(self, items):
        return {'state': 'unknown', 'detail': '此适配尚未提供可核对的后台身份'}

    def context_matches(self, values):
        return False


class HermesAdapter(ManagedBackendAdapter):
    id = 'hermes'
    label = 'Hermes 窗口与后台'
    notice = '请求由独立后台发送。旧窗口可能需正常退出；后台重启先预览，并保留进行中任务保护。'
    backend_label = '模型请求后台'
    restart_scope = '通过 Hermes 官方命令重启默认后台；它承载的所有 profile 会短暂重连。'
    identity_notice = 'Hermes 使用的数据目录与此安装不一致或不可确认；当前适配不支持自动重配。'

    def __init__(self, executable, install):
        super().__init__(executable)
        self.install = install
        self.integration = {'id': self.id, 'label': self.label, 'notice': self.notice,
                            'can_apply': True}

    @property
    def identity(self):
        return [self.id, self.executable, self.install]

    def environment(self, inherited, record):
        return hermes_adapter.environment(inherited, record['mode'], record['proxy_url'], self.install)

    def backend(self, items):
        result = hermes_adapter.backend(self.install, items)
        if result['state'] == 'running':
            # Normalize the vendor-specific field for shared task guards.
            result = {**result, 'active_tasks': result['active_agents']}
        return result

    def context_matches(self, values):
        return os.path.normcase(os.path.abspath(hermes_adapter.desktop_home(values))) == os.path.normcase(os.path.abspath(self.install['home']))

    def lifecycle_pending(self, items):
        return hermes_adapter.lifecycle_pending(self.install, items)

    def checks(self):
        return [{'label': '局域网与多配置', 'status': 'unknown',
                 'detail': 'HTTP 模式使本机与私网 IP 绕过代理；局域网主机名未自动覆盖。各 profile 私有配置仍可能覆盖，实际模型回复待验证。'}]

    def apply_backend(self, environment, *, restart):
        hermes_adapter.apply(self.install, environment, restart=restart)


class UnsupportedAdapter(ApplicationAdapter):
    supported = False

    def __init__(self, executable, description):
        super().__init__(executable)
        self.id = description['id']
        self.label = description['label']
        self.notice = description['notice']
        self.integration = {**description, 'can_apply': False}


def resolve(executable):
    """Resolve a built-in adapter; unknown software keeps the ordinary path."""
    install = hermes_adapter.installation(executable)
    if install:
        return HermesAdapter(executable, install)
    description = hermes_adapter.describe(executable)
    if description and description['id'] == 'hermes_unsupported':
        return UnsupportedAdapter(executable, description)
    if Path(executable).name.casefold() in {'chrome.exe', 'msedge.exe'}:
        return ChromiumAdapter(executable)
    adapter = ApplicationAdapter(executable)
    if description:
        adapter.integration = {**description, 'can_apply': True}
    return adapter
