# Windows 单文件程序

面向 Windows 10 / 11 x64。下载 Release 中的 `FlowDesk-版本-windows-x64.exe`，双击后在默认浏览器使用本机界面。无需另装 Python，不需要管理员权限；关闭页面不退出后台，退出使用页面右上角的“退出后台”。

程序未使用商业代码签名证书。Release 同时提供 `SHA256SUMS.txt`，可用 PowerShell 的 `Get-FileHash 文件名.exe -Algorithm SHA256` 核对下载文件。

## 保存与迁移

- exe 版：`%LOCALAPPDATA%\FlowDesk\.local`。
- 源码版：项目目录的 `.local`。
- 从源码版迁移时，先在旧界面导出方案，再在 exe 界面导入。机器检测快照、系统代理恢复日志和运行入口不迁移。
- 更新 exe 前在旧界面退出后台，再替换文件。用户数据独立于 exe 和临时解压目录，不会因为替换程序而丢失。
- 高级参数 `--data-root 路径` 可为隔离测试指定数据根目录，状态写入其 `.local` 子目录。

## 从源码构建

构建机需要 Windows x64 和 Python 3.11 或更新版本；本次发布使用 Python 3.13.1 x64。用户运行成品不需要这些工具。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build_windows.ps1
```

脚本在项目的 `.build-venv` 安装锁定版本的构建依赖，读取 `FlowDesk.spec`，产出 `dist/FlowDesk.exe`。只有应用代码、Python 运行时和 `web` 界面会进入程序；`.local`、原始场景材料、诊断、测试和构建环境不打包。

验收命令：

```powershell
python -X utf8 -m unittest discover -s tests -v
python -X utf8 tools/smoke_exe.py dist/FlowDesk.exe
```

成品验收将 exe 复制到带中文和空格的临时目录，给子进程提供不含 Python 的 PATH，检查静态资源、重复启动、方案持久化、实际回环中继请求、独立守护入口与正常退出。只读取真实系统代理作前后对比，不接管真实系统代理。

## 打包实现

界面资源从程序内读取，用户状态独立保存；这是 PyInstaller [运行时路径说明](https://pyinstaller.org/en/stable/runtime-information.html)所区分的两类位置。

独立回退守护通过同一 exe 的内部入口启动，设置 `PYINSTALLER_RESET_ENVIRONMENT=1`，让它具有独立解压目录并可在主程序退出后继续工作。依据 [PyInstaller 子进程说明](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#using-sys-executable-to-spawn-subprocesses-that-outlive-the-application-process-implementing-application-restart)。守护启动失败时，不应用系统代理变更。

真实系统代理写入与恢复通过替身适配器测试；打包验收不会为了验证 exe 而切换正在使用的代理、UU 或 Codex 连接。
