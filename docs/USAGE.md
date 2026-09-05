# 使用手册

[返回首页](../README.md) · [组件边界](COMPONENTS.md) · [诊断说明](DIAGNOSTICS.md)

本页收录分阶段操作、版本升级和排障细节。首次使用请先阅读首页的适用范围，并创建可恢复快照。
所有示例在完整解压目录的管理员终端执行；`.cmd` 入口会调用 64 位 Windows PowerShell 5.1。

## 下载与校验

从 [Releases](https://github.com/mihomoQ/ctyun-trim/releases) 下载所选版本的 `CTyunTrim-<版本>-Diagnostic.zip` 和同名 `.sha256` 文件。
使用 Release 上传的安装包，不要混用旧目录或把 GitHub 自动生成的 Source code 压缩包当作同一份校验对象。

在下载目录执行下面的示例，将版本号替换为实际下载的版本：

```powershell
Get-FileHash -LiteralPath '.\CTyunTrim-0.1.8-Diagnostic.zip' -Algorithm SHA256
Get-Content -LiteralPath '.\CTyunTrim-0.1.8-Diagnostic.zip.sha256'
```

两处 SHA-256 应一致。校验后完整解压，再打开管理员终端。脚本不会下载或静默执行远程代码，也不建议使用远程管道执行方式。

## 选择入口

| 需求 | 命令 | 行为 |
| --- | --- | --- |
| 盘点系统 | `.\Start-CTyunTrim.cmd -Mode Audit` | 只读；省略 Mode 时也默认 Audit |
| 查看动作计划 | `.\Start-CTyunTrim.cmd -Mode Plan` | 不执行精简 |
| 预览常用流程 | `.\Trim.cmd -WhatIf` | 不创建精简记录、不修改目标系统 |
| 自动准备与精简 | `.\Trim.cmd -Force` | 自动选择本机唯一可信记录；完成后只验证 |
| 分阶段准备 | `.\Start-CTyunTrim.cmd -Mode Prepare -Force` | 阻断已识别自愈入口、处理假 WSUS，建立备份与身份基线 |
| 指定任务续跑 | `.\Start-CTyunTrim.cmd -Mode Apply -RunId '<RunId>' -Force` | 继续指定记录 |
| 指定任务验证 | `.\Start-CTyunTrim.cmd -Mode Verify -RunId '<RunId>'` | 只读验证 |
| 独立修复电源菜单 | `.\Restore-PowerMenu.cmd -Force` | 只修复已识别菜单隐藏策略，不重做精简 |

`<RunId>` 必须替换为实际输出值。直接使用 `.ps1` 时，修改操作只能在 64 位 Windows PowerShell 5.1 中运行，不能使用 PowerShell 7。

### 常用参数

- `-Force`：明确授权执行修改，不会跳过身份、路径、签名或重启检查。
- `-WhatIf`：预览；额外请求 `-Diagnostic` 时仍会写诊断文件。
- `-Json`：输出机器可读结果；`-Diagnostic` 会增加诊断信息和导出结果。
- `-RunId`：手动阶段使用原任务标识；Trim 自动选择记录，不接受此参数。
- `-LgpoPath`：指定 LGPO 候选文件，仍必须通过固定身份校验。
- `-BackupRoot`：默认为 `%ProgramData%\CTyunTrim\Runs`，必须满足受保护路径要求；自定义后续跑也要使用同一位置，不要靠换目录绕过旧记录。
- `-ManifestPath`：选择本地清单文件的位置，但内容仍必须匹配内置清单，不是放开自定义移除规则。

推荐手动重启。Trim 明确拒绝 `-Restart`，且任何入口都不能同时使用 `-Diagnostic` 和 `-Restart`。
独立的 `Restore-PowerMenu.cmd` 只提供 `-Force`、`-WhatIf`、`-Confirm`、`-Json`，不接受精简任务参数或 `-Diagnostic`。

## 常用精简流程

先运行 Audit 和 WhatIf，审阅输出并确认快照后：

```powershell
.\Trim.cmd -Force
```

- 没有运行记录时，自动衔接 Prepare 和 Apply，并使用同一 RunId。
- 存在唯一可信的未完成任务时，自动继续该任务；多个记录、损坏记录或保护标记冲突不会被猜测处理。
- 返回 `PendingReboot` 时，重启后运行同一条命令。同一启动周期内重复执行不会绕过重启要求。
- 返回 `Applied` 后，再次运行会执行 Verify。验证失败会返回非零退出码；已经 Applied 的任务不重复删除组件。
- Trim 不接受手动指定 RunId，也不会自动重启。需要显式选择记录时使用 Apply 或 Verify。

不要删除 `%ProgramData%\CTyunTrim\Runs` 来强行重试：其中保存原有备份和任务身份，删除后不能靠新建记录恢复可信续跑关系。

## 与 ReviOS 分阶段使用

CTyunTrim 与 ReviOS 保持独立，不合并进官方 Playbook。若需要先解除预装的假 WSUS 更新策略，再更新 Windows 和应用 ReviOS，可按以下顺序操作。

### 1. 审计和准备

```powershell
.\Start-CTyunTrim.cmd -Mode Audit
.\Start-CTyunTrim.cmd -Mode Prepare -WhatIf
.\Start-CTyunTrim.cmd -Mode Prepare -Force
```

保存 Prepare 返回的 RunId。Prepare 会在 Cloudbase 服务仍可校验时存档账户、用户配置文件 SID 和精确服务映像证据。
如果先被其他工具删掉服务，后续不能仅凭账户名称猜测归属。

### 2. 更新 Windows，应用 ReviOS，重启

先确认 Prepare 的结果和警告。`Prepared` 只表示本轮准备完成，不保证重启后没有新的自愈活动。
按自己的 ReviOS 配置完成系统更新和 Playbook 操作，必要时重启。

### 3. 使用原 RunId 继续

```powershell
.\Start-CTyunTrim.cmd -Mode Apply -RunId '<Prepare返回的RunId>' -Force
```

如果返回 `PendingReboot`，重启后重复这条命令，仍使用同一 RunId。不要在执行过 Prepare 后无 RunId 地重新开始另一轮 Apply。
也可在只有一份可信记录时使用 `Trim.cmd -Force` 自动选择原任务。

### 4. 验证

```powershell
.\Start-CTyunTrim.cmd -Mode Verify -RunId '<同一个RunId>'
```

完整回滚依赖运行前的快照，组件备份不能代替快照。更多背景见 [ReviOS 配合说明](REVIOS.md)。

## LGPO 工具

处理清单内的假 WSUS 本地组策略时需要受信任的 Microsoft `LGPO.exe`。支持这些来源：

- 尚未被移除的预装路径：`C:\Program Files (x86)\ctyun\clink\Mirror\ScriptConfig\LGPO.exe`。
- `C:\ProgramData\LGPO\LGPO.exe`。
- 通过 `-LgpoPath` 指定的文件。

候选文件必须匹配内置版本、文件哈希、Microsoft 签名和路径权限要求。脚本将其复制到受保护的任务目录，再复验并使用该副本；不会随意执行同名程序。
本项目不分发或自动下载 LGPO。获取方式和固定哈希见 [辅助工具说明](../tools/README.md)。

## 常见阻断与升级

### Cloudbase 用户配置文件仍被占用

Prepare 只接受经过严格验证、唯一占用者为指定 `TaskAgentDetect.exe` 的情况；账户、SID、服务/任务主体、路径、签名、权限和进程身份都必须吻合。
Apply 的实际删除阶段仍要求用户配置文件与注册表 hive 已卸载，绝不强制卸载。

同一 RunId 续跑时，若只剩此占用问题、该 SID 没有进程，且精确 Cloudbase 服务处于已停止但自动启动的状态，
脚本可在验证后独立备份并禁用此服务启动，然后返回 `PendingReboot`。这一轮不删除账户、用户配置文件、任务或其他服务。
若重启后仍未卸载，会继续阻断，不通过放宽检查来完成删除。

此时保持原 RunId，使用[只读占用检查工具](../tools/README.md#cloudbase-profile-occupancy)补充证据，不要反复清空备份或盲目终止进程。
精确条件见 [Cloudbase 身份边界](COMPONENTS.md#loaded-cloudbase-profile-boundary)。

### 隔离目标已经存在

0.1.6 起，已隔离源目录重新生成时，新内容进入独立隔离位置，旧备份不覆盖、不合并。待处理的移动继续使用原日志中的目标。
遇到未知冲突或目标身份不一致时仍停止；不要自行合并隔离目录。升级应完整解压较新版本，并保持原任务记录，不在续跑中降级。

### 核心组件或清单不匹配

支持的 Windows build 只是必要条件，不是兼容承诺。当前配置还核对 `clipa 2.1.0.0`、核心映像路径、签名和文件基线。
预装 Balloon 的特殊证书只在精确文件和签名者匹配时被接受，不会安装为系统受信任根。
不要修改清单或信任策略来绕过错误；保留现场并提供诊断信息。完整规则见 [组件边界](COMPONENTS.md)。

## 验证结果怎么理解

指定 RunId 的 Verify 会检查保留核心、移除组件、任务、策略、证书、防火墙规则和原 SID 绑定的 Cloudbase 身份。
无 RunId 的 Verify 缺少身份基线，会明确判定验证不完整。Trim 会自动关联唯一可信记录。

六个带有本工具标记的 IFEO 防自愈项是有意保留的，不是遗漏；它们可能影响后续厂商升级。不能删除整个 CTyun、Clink、驱动、GroupPolicy 目录或整个证书存储区。

完成组件清理后，以下运行时数据可单独报告为 Warning：

- 完全为空、且存在可信隔离记录的 `mirror\FileCrypto` 目录。
- `mirror\PrinterJobLog` 中唯一的空白日志或严格识别的打印初始化日志。

这还要求核心正常、相关组件和身份已移除、没有执行引用、路径与内容检查完整。额外文件、链接、未知日志或查询不完整仍会使验证失败，移除清单没有放宽。

`Passed=false` 会产生失败退出码。`PrimarySucceeded=true` 只表示命令本轮成功返回，不代表精简已经完成；还需查看 `Status`、重启要求和最终验证。

### 人工验收

自动检查不能证明真实互通效果。完成精简后应检查：

- 官方客户端断开后重连，键鼠输入和分辨率。
- 双向文本剪贴板，以及 TXT、ZIP、图片和普通二进制文件互传。
- 所需音频和设备重定向；网络、DNS，以及符合所选 ReviOS 配置的 Windows Update 行为。
- 至少两次重启后的再次验证。

`.lnk` 快捷方式是已知的 cloudshare 特殊案例，不应作为普通文件互传的唯一判断依据。
已实际验证与尚未单独验证的项目见 [0.1.7 实机记录](TEST-RESULTS-0.1.7.md)，不要把验收清单当成全部项目均已测试的承诺。

## 诊断与隐私

```powershell
.\Start-CTyunTrim.cmd -Mode Audit -Diagnostic -Json
.\Trim.cmd -Force -Diagnostic -Json
```

诊断包不会自动上传。`-Diagnostic` 额外写入诊断 ZIP 和校验文件，即使与 WhatIf 一起使用也会写这份报告，但不会因此执行目标精简动作。
导出需要 64 位管理员 Windows PowerShell 5.1，固定写入 Windows CommonApplicationData 下的 `CTyunTrim\Diagnostics`。不能与 `-Restart` 一起使用。

诊断包使用固定字段，不复制整个运行目录；原始 Audit、备份与隔离内容仍可能包含敏感信息。提交 Issue 前检查内容，不上传密码、Token、私钥或完整系统镜像。
格式与排除项见 [诊断说明](DIAGNOSTICS.md)。

## 恢复与电源菜单

目前没有完整自动 Restore；需要完整还原时使用快照。精简日志、注册表和组件备份仅用于有证据的定点人工恢复，不能直接整包导入覆盖系统现状。
备份布局与恢复限制见 [备份与恢复](RECOVERY.md)。

`Restore-PowerMenu.cmd` 只恢复已识别的关机/重启菜单隐藏设置，不是精简回滚工具。已完成精简的系统使用它无需重做 Apply；
它不改旧精简日志，不直接关机、重启或强制结束资源管理器。它要求当前桌面账户的管理员会话，域/MDM 管理和相关策略冲突会阻断。
详情见 [电源菜单修复](POWER-MENU.md)。
