# Windows 单文件程序

面向 Windows 10 / 11 x64。下载 Release 中的 `FlowDesk-版本-windows-x64.exe`，双击后在默认浏览器使用本机界面。无需另装 Python，不需要管理员权限；关闭页面不退出后台，退出使用页面右上角的“退出后台”。

程序未使用商业代码签名证书。Release 同时提供 `SHA256SUMS.txt`，可用 PowerShell 的 `Get-FileHash 文件名.exe -Algorithm SHA256` 核对下载文件。

## 保存与迁移

- 项目内 EXE 与源码版：有 `flowdesk-project.json` 标记时共用项目目录的 `.local`；项目启动脚本还会明确传入 `--data-root`。
- 单独放在项目外、没有标记的 EXE：`%LOCALAPPDATA%\FlowDesk\.local`。
- 不同数据位置迁移时，先导出或备份方案，再导入目标位置；手动清单存放于 `.local/custom-apps.json`。不要复制进程锁、正在使用的系统代理恢复事务或运行入口。
- 更新 exe 前在旧界面退出后台，再替换文件。用户数据独立于 exe 和临时解压目录，不会因为替换程序而丢失。
- 高级参数 `--data-root 路径` 可为隔离测试指定数据根目录，状态写入其 `.local` 子目录。

## 从源码构建

构建机需要 Windows x64 和 Python 3.11 或更新版本；本次发布使用 Python 3.13.1 x64。用户运行成品不需要这些工具。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build_windows.ps1
```

脚本默认在项目的 `.build-venv` 安装锁定版本的构建依赖，读取 `FlowDesk.spec`。构建始终先产出固定候选位置 `artifacts/release-staging/FlowDesk.exe`，中间文件位于 `artifacts/pyinstaller-work`，不会直接向正式 `dist` 写入半成品。

PyInstaller 正常退出后，脚本才串行调用 `tools/smoke_exe.py` 验证 staging EXE，报告写入 `artifacts/exe-smoke.json`。旧报告在构建前移除；原生命令的非零退出码、报告缺失、候选 SHA-256 不一致或烟雾测试失败都会停止，正式 `dist` 保持原样。

全部验证通过后，脚本检查 `dist/FlowDesk.exe` 是否正在运行或被占用。可安全发布时，先核对发布副本的 SHA-256，再原子替换正式 EXE；旧 EXE 备份到 `artifacts/release-previous`。如果正式 EXE 正在运行、被占用或不能安全检查，保留旧 `dist`，打印已验证候选及报告的完整路径，并以退出码 `2` 结束。脚本不会终止应用，也不会调整网络。需要更新时，先通过旧界面正常退出后台，再重新执行构建与验证；不要自动忽略退出码后继续复制 staging 文件。

已准备好 `.build-venv` 和构建依赖时，可以跳过依赖安装进行离线构建：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "tools/build_windows.ps1" -SkipDependencyInstall
```

这个选项不会创建缺失的构建环境，也不会执行 pip 安装；构建依赖缺失时会失败。默认调用仍保留原来的依赖安装行为。脚本根据自身路径定位项目，参数按独立参数传递，支持项目路径包含空格；成功或失败后都会恢复调用时的工作目录。运行 `-File` 时应给含空格的脚本路径加引号。

只有应用代码、Python 运行时和 `web` 界面会进入程序；`.local`、原始场景材料、诊断、测试和构建环境不打包。`artifacts/release-staging` 在构建过程中属于未完成候选，只有本次烟雾测试报告与候选散列对应且脚本输出已验证信息后，才能作为待发布候选。

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
