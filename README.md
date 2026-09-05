# CTyunTrim

0.1.8 新增恢复开始菜单关机/重启选项：后续 Apply 会自动处理；已经精简完成的系统运行 `Restore-PowerMenu.cmd -Force` 即可，不重做精简。详见 [电源菜单修复](docs/POWER-MENU.md)。

CTyunTrim 是一个非官方、审计优先、可重复执行的 Windows PowerShell 5.1 工具，用于缩减天翼云电脑 Windows 预装镜像中的客体侧附加管理面，同时保留已经验证的远程互通核心。

> [!CAUTION]
> CTyunTrim 会以管理员权限处理服务、驱动、计划任务、账户、证书、本地组策略和程序目录。识别错误可能导致天翼连接、键鼠、剪贴板、文件传输、网络、Windows Update 或系统启动失败。运行前必须创建可用的云主机快照、备份重要数据，并准备不依赖待处理组件的恢复入口。

当前状态：**Experimental / 0.1.8-Diagnostic**。针对已记录的 Windows 11/ReviOS 与天翼组件组合，保持已验证互通核心；其他镜像需要先核验。

0.1.7 已在用户提供初始快照的原厂＋ReviOS 系统上完成完整精简、三次重启、幂等与负向验证；用户确认重连、键鼠、双向文本剪贴板和普通 TXT/ZIP 互传正常。范围与限制见 [实机测试记录](docs/TEST-RESULTS-0.1.7.md)。

## 项目目标

- 保留官方连接、显示、输入、文本剪贴板和普通文件互通所需的最小运行层。
- 移除已验证的附加管理、自愈、更新、策略回填、镜像上报及外围功能。
- 完整移除本项目使用场景不需要的 `cloudbase-init` 服务、账户、Profile 和程序。
- 默认只审计；变更前备份；程序文件先移动到隔离区，而不是直接粉碎。
- 未识别环境、路径冲突、已有未知 IFEO、签名异常时停止，不猜测、不模糊删除。
- `Apply` 只接受内置清单的规范化 SHA-256，并核对核心服务/驱动的精确 `ImagePath`、来源 ACL、签名策略以及 `clipa 2.1.0.0` 指纹；Prepare 还会固化核心文件 SHA-256 和签名者，后续续跑不允许悄悄换件，不同镜像默认拒绝执行。

CTyunTrim 不是通用 Windows 精简工具，不替代 ReviOS，也不修改 ReviOS Playbook。

## 默认保留边界

默认配置文件为 `MinimalInterop`：

| 类别 | 保留对象 | 目的 |
|---|---|---|
| 远程会话 | `clink_service`、`clink_agent*` | 连接、显示、输入和数据通道 |
| 平台互通 | `clipa` | 当前已验证基线中的基础设施 Agent |
| 文件互通 | `cloudshare_service`、`cloudshare.exe`、`dokan2.dll` | 文本/文件通道 |
| 虚拟机协作 | `BalloonService` | Balloon 内存协作 |
| 必要驱动 | `CLINKAC`、`ClinkMouseFilter`、`WinDivertScanner`、`WinDivert64.sys` | 输入或网络辅助 |

“保留”仅表示功能需要，不表示这些高权限厂商组件可信、无风险或不具备管理能力。

参考镜像的 `BalloonService` 使用 Red Hat virtio-win 开发证书自签，Windows 返回不受信任根。CTyunTrim 不安装或信任该根证书，而只对这一服务接受内置的精确文件 SHA-256 与嵌入签名者组合；其他核心文件仍必须在清理前通过正常的 Authenticode 信任验证。建立受保护基线后，普通核心文件仍须保持 `Valid`，直到当前 RunId 已经留下完成移除至少一张清单内证书的持久日志；只有越过该边界后，才允许证书链降级，并且仍要求与基线逐字节、签名者完全一致且不存在 `HashMismatch`、`NotSigned` 等破坏状态。仅有写前 `Pending` 日志或未知证书目标都不能放宽信任。

以下对象有硬保护：

- `WinDivertProxy-Port.exe` 与 `WinDivertScanner` 被保留；独立的 `WinDivertProxy.exe` 才属于移除项。
- `cloudshare` 和它加载的 `dokan2.dll` 被保留；`dokan2` 驱动服务是另一对象。
- Windows 的 `FileCrypt.sys` 永不属于删除项；它不是天翼 `FileCrypto`。
- 绝不删除整个 `ctyun`、`clink`、`res`、`drivers`、`GroupPolicy` 或证书存储区。

详细依据见 [组件边界](docs/COMPONENTS.md)、[参考镜像证据](docs/REFERENCE-BASELINE.md) 和 [威胁模型](docs/THREAT-MODEL.md)。

## 使用

请下载完整 Release 并核验 SHA-256。不要使用 `irm ... | iex` 一类远程管道直接执行。

### 常用入口：同一条命令

在完成 ReviOS、已备份的测试系统上，以管理员身份运行：

```powershell
.\Trim.cmd -Force
```

首次执行会建立备份并自动衔接 Prepare/Apply。如果返回 `PendingReboot`，重启后再次运行同一条命令。它只会选择本机唯一可信的运行记录，不需要手动抄 RunId；若有多个记录或记录损坏会明确停止。已经完成的运行只做 Verify，不重新删除。

可加 `-Diagnostic -Json` 获取诊断结果，也可用 `-WhatIf` 预览。原有 Audit、Prepare、Apply、Verify 入口仍可用于分阶段排查或在 ReviOS 之前处理假 WSUS。

### 手动分阶段入口

打开 64 位管理员 PowerShell：

```powershell
# 1. 只读盘点；默认模式
.\CTyunTrim.ps1 -Mode Audit

# 2. 查看完整动作计划
.\CTyunTrim.ps1 -Mode Plan

# 3. PowerShell 原生 WhatIf，不产生系统修改
.\CTyunTrim.ps1 -Mode Apply -WhatIf

# 也可只预览 Prepare 将建立的 IFEO、任务移除、进程停止和策略动作
.\CTyunTrim.ps1 -Mode Prepare -WhatIf

# 4. 可选：在 ReviOS 前仅阻断自愈并清除假 WSUS
.\CTyunTrim.ps1 -Mode Prepare -Force

# 5. 确认已有快照并审阅输出后才运行完整精简
.\CTyunTrim.ps1 -Mode Apply -Force

# 6. 按 Apply 结果重启，然后用 Apply 返回的同一 RunId 只读验证
.\CTyunTrim.ps1 -Mode Verify -RunId <Apply返回的RunId>
```

如果执行了 Prepare，后续 Apply 必须使用 Prepare 返回的同一个 RunId，使 IFEO、LocalGPO 和完整精简共享一份恢复记录：

```powershell
.\CTyunTrim.ps1 -Mode Apply -RunId <Prepare返回的RunId> -Force
```

在 ReviOS 之前运行 Prepare 还有一个安全作用：它会在 Cloudbase 服务仍可核验时存档账户/Profile SID 与精确服务映像证据。若先由其他工具删掉服务，再直接运行 CTyunTrim，脚本不会仅凭用户名猜测并删除账户。

参考镜像可能由精确的 `TaskAgentDetect.exe` 以 `cloudbase-init` 身份挂载 Profile。Prepare 只在账户/Profile SID、安全本地 RID、服务或任务 Principal 的 SID 归属锚、进程 Owner SID、Session 0、精确任务映像路径、签名、ACL 和引用全部匹配时接受这一状态；它在变更边界复验后先建立 IFEO guard，再停止该进程并移除任务，但不会删除账户、Profile 或强制卸载 hive。Apply 仍要求 Profile 与 hive 已自然卸载，`Special=true` 或同 SID 的异常 Profile 路径在所有阶段均为硬阻断。

已观察到 0.1.4 在完整重启后仍有 Profile/hive 加载、三个 `check_report_img_*` 任务重新出现的情况，即使六个 IFEO guard 仍然匹配。`Prepared` 只证明该次准备执行完成，不能证明重启后的自愈入口已经全部阻断。若遇到此情况，保持原 RunId，使用独立的 [Cloudbase 占用检查](tools/README.md#cloudbase-profile-occupancy) 补充进程、登录关联和服务/任务主体证据；不要把重复重启或放宽 Profile 删除预检当作修复。

0.1.5 为这个已观察到的状态增加了受限的过渡步骤：仅在同 RunId 续跑、唯一预检错误是 Profile/hive 已加载、基线身份和互通核心有效、该 SID 没有进程，且精确 `cloudbase-init` 服务为 `Stopped / Auto` 并使用该 SID 时，Apply 才会独立备份服务配置、记录 `ServiceQuiesce` 操作并将此服务启动类型改为 `Disabled`。当次立即返回 `PendingReboot`，不会继续删除组件。账户、Profile、hive 和任务在此步骤均不修改。

重启后，用当前完整版本和原 RunId 再次运行 Apply；只有 Profile/hive 已自然卸载且所有原有预检通过，才会进入完整精简。如果停用服务并重启后仍加载，脚本继续阻断，不自动扩大停用范围。0.1.4/0.1.5 创建的 RunId 可直接续用，移除清单及其固定哈希未改变。续跑时不要降回旧版本。

0.1.6 支持已备份的源目录在重启后重新出现：新目录内容保存到独立的隔离子目录，旧备份保留原样，不会因备份位置已存在而卡住，也不会覆盖或合并备份。

如果 Apply 返回 `PendingReboot`，重启后必须使用同一个 RunId 续跑，避免把一次变更拆成多个无法统一恢复的备份：

```powershell
.\CTyunTrim.ps1 -Mode Apply -RunId 20260904-180000-a1b2c3d4 -Force
```

也可以使用 64 位启动器：

```cmd
Start-CTyunTrim.cmd -Mode Audit
```

如果系统存在假 WSUS LocalGPO，脚本需要微软签名的 `LGPO.exe`：

- 优先使用天翼预装目录中尚未删除的 `clink\Mirror\ScriptConfig\LGPO.exe`；
- 或把微软 Security Compliance Toolkit 中的 `LGPO.exe` 放到 `C:\ProgramData\LGPO\LGPO.exe`；
- 或显式传入 `-LgpoPath`。

脚本不会下载或静默执行任何远程代码，也不会携带或重新分发 `LGPO.exe`。
找到候选文件后，脚本会要求它逐字节匹配内置的微软 LGPO v3.0 SHA-256，再检查签名与父目录 ACL，把它复制到当前 RunId 的受保护目录并复验；实际执行的始终是该受保护副本。固定哈希与微软官方下载地址见 [tools/README.md](tools/README.md)。

### Diagnostic 版本

`-Diagnostic` 使用与正式执行完全相同的代码路径，只额外生成脱敏诊断包：

```powershell
# 只读盘点并生成诊断包
.\Start-CTyunTrim.cmd -Mode Audit -Diagnostic -Json

# Prepare/Apply 也可记录相同 RunId 的执行与中断状态
.\Start-CTyunTrim.cmd -Mode Prepare -Force -Diagnostic
.\Start-CTyunTrim.cmd -Mode Apply -RunId <RunId> -Force -Diagnostic

# WhatIf 仍不修改目标系统，但会写入明确请求的诊断 ZIP
.\Start-CTyunTrim.cmd -Mode Apply -WhatIf -Diagnostic -Json
```

诊断 ZIP 固定只包含 `summary.json`、`environment.json`、`events.jsonl` 和 `README.txt`，旁边生成 SHA-256 文件。它不会复制 RunId 目录，也不会包含注册表导出、任务 XML、证书、隔离文件、完整命令行、用户名、SID、IP/MAC/DNS、证书身份或凭据，更不会自动上传。

Diagnostic 导出要求 64 位管理员 Windows PowerShell 5.1，并固定写入 Windows `CommonApplicationData\CTyunTrim\Diagnostics` Known Folder。`-Diagnostic` 与 `-Restart` 不可同时使用，确保 ZIP 已完成、校验并关闭后再由用户决定是否重启。详细格式见 [诊断说明](docs/DIAGNOSTICS.md)。

### 恢复

Apply 会返回 `RunId` 和备份目录。0.1.5 暂不提供自动 Restore：安全审查确认，直接导入完整注册表键、任务或 `Registry.pol` 可能覆盖 Apply 后产生的合法变化。隔离区和导出文件用于取证式人工恢复；完整回滚必须使用运行前的云主机快照。

## 与 ReviOS 配合

建议保持两个项目独立：

```text
天翼预装系统
→ 创建快照
→ Audit/Plan
→ Prepare 并完成 Windows Update
→ 应用官方 ReviOS Playbook
→ 重启
→ CTyunTrim Apply
→ 重启
→ CTyunTrim Verify + 人工互通测试
```

不要把 CTyunTrim 直接合并到官方 ReviOS Playbook。这样 ReviOS 升级与天翼组件识别可以分别维护和排障。参见 [ReviOS 配合说明](docs/REVIOS.md)。

## 自动验证与人工验收

`Verify` 会检查：

- 四个核心服务仍存在并运行；
- 核心服务/驱动仍使用基线中的精确映像路径，签名未被破坏，必要驱动和受保护路径仍存在；
- 自愈任务、外围服务、额外驱动、假 WSUS、已知证书和死防火墙规则已消失；
- 六个有意创建的 IFEO 防自愈项仍匹配本工具标记；
- `cloudbase-init` 账户和 Profile 已消失。
- 已知失效程序路径的入站 Allow 防火墙规则已消失；Block 规则保留。

0.1.7 会单独报告两类已识别运行时数据：完成组件清理后重建的完全空 `mirror\FileCrypto`，以及 `mirror\PrinterJobLog` 中唯一的空白或已识别打印机初始化日志。只有核心正常、组件/证书/身份已清、已有可信隔离记录、没有路径执行引用且内容检查通过时，才计为 Warning 而非组件恢复。任何额外文件、链接、未知日志内容或查询不完整仍会使 Verify 失败；移除清单本身没有放宽。

必须向 `Verify` 传入对应 RunId，才能按 Prepare 时存档的 SID 检出后来被改名的 Cloudbase 账户；不传 RunId 的只读报告会明确判定为未完成验证。
只要 `Passed` 为 false，入口脚本也会返回失败退出状态，便于 CI 或批处理正确拦截。

自动检查无法替代真实功能验收。每次 Apply 后必须测试：

- 官方客户端断开后重新连接；
- 键盘、鼠标和分辨率；
- 双向文本剪贴板；
- 普通 TXT、ZIP、图片和中等体积二进制文件双向传输；
- 音频和需要保留的设备重定向；
- 网络、DNS 与 Windows Update；
- 至少两次重启后重新运行 Verify。

`.lnk` 快捷方式是已知的 cloudshare 特殊案例，不能作为普通文件传输是否正常的唯一判断依据。

## 安全与隐私

Audit 报告可能含主机名、用户名、本地路径、IP、DNS、软件版本和证书指纹。提交 Issue 前必须脱敏；不要上传系统镜像、完整注册表、隔离文件、Token、密码或私钥。

安全问题请参阅 [SECURITY.md](SECURITY.md)。开发要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 非官方及能力边界

本项目与中国电信、天翼云、ReviOS、AME、Cloudbase Solutions 及其关联方没有隶属、合作、支持或认可关系。

CTyunTrim 只能缩减 Windows 客体内可观察到的管理面，无法检查或约束云厂商对 Hypervisor、虚拟磁盘、快照、虚拟网络、启动介质、管理控制台或服务端系统的控制。详见 [免责声明](DISCLAIMER.md)。

## License

[MIT](LICENSE)
