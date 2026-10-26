"""Double-click launcher. Only local files and loopback HTTP are used at startup."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
import threading
import urllib.request
import webbrowser

from proxyworkbench.server import ControlServer
from proxyworkbench.system_proxy import atomic_json
from proxyworkbench.runtime import asset_root, data_root


def main(argv=None):
    parser = argparse.ArgumentParser(description='流向 · 本机代理工作台')
    parser.add_argument('--port', type=int, default=None, help='默认复用上次本机端口；0 表示随机端口')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--no-discovery', action='store_true', help='仅供隔离测试')
    parser.add_argument('--data-root', help='自定义持久数据根目录；数据保存在其 .local 子目录')
    parser.add_argument('--guardian', nargs=2, metavar=('JOURNAL', 'LEASE_ID'), help=argparse.SUPPRESS)
    parser.add_argument('--launch-app', metavar='SAVED_KEY', help='使用已保存的应用连接设置启动')
    args = parser.parse_args(argv)
    if args.guardian:
        from proxyworkbench.guardian import watch
        watch(*args.guardian)
        return
    root = data_root(args.data_root)
    if args.launch_app:
        from proxyworkbench.app_shortcuts import launch_saved
        launch_saved(root, args.launch_app)
        return
    local = root / '.local'
    local.mkdir(parents=True, exist_ok=True)
    # OS byte lock closes with the process, unlike a stale PID file.
    handle = (local / 'instance.lock').open('a+b')
    if handle.tell() == 0:
        handle.write(b'0')
        handle.flush()
    handle.seek(0)
    try:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        try:
            record = json.loads((local / 'server.json').read_text(encoding='utf-8'))
            port = int(record['port'])
            if not 1 <= port <= 65535:
                raise ValueError()
            url = f'http://127.0.0.1:{port}'
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url + '/api/health', timeout=3) as response:
                health = json.load(response)
            if health.get('app') != 'proxy-patchbay' or health.get('instance_id') != record['instance_id']:
                raise RuntimeError()
            if not args.no_browser:
                webbrowser.open(url)
            return
        except Exception:
            raise RuntimeError('工作台正在启动或无响应，请稍后重试；没有改动系统代理') from None
    selected_port = args.port
    if selected_port is None:
        try:
            selected_port = int(json.loads((local / 'server.json').read_text(encoding='utf-8'))['port'])
            if not 1 <= selected_port <= 65535:
                selected_port = 18743
        except (OSError, ValueError, KeyError):
            selected_port = 18743
    try:
        server = ControlServer(('127.0.0.1', selected_port), root, discover=not args.no_discovery, assets=asset_root())
    except OSError:
        if args.port is not None:
            raise
        # Another program owns the old port; never stop it or bind on the LAN.
        server = ControlServer(('127.0.0.1', 0), root, discover=not args.no_discovery, assets=asset_root())
    atomic_json(local / 'server.json', {'pid': os.getpid(), 'port': server.server_port, 'instance_id': server.instance_id})
    url = f'http://127.0.0.1:{server.server_port}'
    if sys.stdout:
        print(url, flush=True)
    if not args.no_browser:
        threading.Timer(.5, lambda: webbrowser.open(url)).start()
    try:
        while True:
            try:
                server.serve_forever(poll_interval=.3)
            except KeyboardInterrupt:
                try:
                    server.service.close()
                except Exception as error:
                    if sys.stderr:
                        print('退出已取消，入口保持运行：' + str(error), file=sys.stderr, flush=True)
                    continue
                break
            else:
                server.service.close()
                break
    finally:
        server.server_close()
        handle.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if sys.stderr:
            raise
        if os.name == 'nt':
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, str(error), '流向 · 启动未完成', 0x10)
