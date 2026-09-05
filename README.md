<div align="center">
  <h1>CTyunTrim</h1>
  <p>天翼云电脑预装组件精简工具</p>
  <p>
    <a href="https://github.com/mihomoQ/ctyun-trim/releases">下载</a> ·
    <a href="#快速开始">快速开始</a> ·
    <a href="docs/USAGE.md">使用文档</a> ·
    <a href="https://github.com/mihomoQ/ctyun-trim/issues">问题反馈</a>
  </p>
  <p>
    <a href="https://github.com/mihomoQ/ctyun-trim/actions/workflows/powershell.yml"><img src="https://github.com/mihomoQ/ctyun-trim/actions/workflows/powershell.yml/badge.svg?branch=main" alt="PowerShell checks"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-blue.svg" alt="GPL-3.0-only"></a>
  </p>
  <p><strong>简体中文</strong> · <a href="README.en.md">English</a></p>
</div>

CTyunTrim 用于精简天翼云电脑 Windows 预装镜像中已识别的管理、自愈和附加组件，同时保留官方连接、键鼠、文本剪贴板和普通文件互传所需的核心。它是独立的 PowerShell 工具，可与 ReviOS 配合使用，不是通用 Windows 优化器。

> [!WARNING]
> 本项目仍处于实验性预发布阶段，操作可能影响远程连接或系统启动。运行前请创建并确认可恢复的系统快照，备份重要数据，并准备独立的恢复入口。组件备份不等于完整回滚，目前不提供自动 Restore。

## 功能

- **精简预装组件**：处理清单内的 AI 助手、应用市场、云打印、自愈更新链，以及 `cloudbase-init` 服务、账户、用户配置文件和程序。
- **保留必要互通**：保留已核验的 Clink、cloudshare、clipa、Balloon 及配套驱动；不按厂商名称或目录通配删除。
- **一条命令续跑**：自动衔接准备与精简，重启后重复同一条命令即可继续。完成后再次运行只做验证。
- **先检查、后修改**：支持只读审计和预览，变更前备份，识别不匹配时停止；可导出脱敏诊断包。
- **恢复电源菜单**：恢复开始菜单中被预装策略隐藏的关机、重启选项，也可在已精简系统上单独运行。

## 适用范围

需要 **Windows 11 x64、管理员权限和 Windows PowerShell 5.1**；`.cmd` 入口会自动选择 64 位 Windows PowerShell，不能用 PowerShell 7 直接执行修改。

当前配置针对 build **26100 / 26200**、`clipa 2.1.0.0` 等已记录组件组合。系统版本号相同并不代表兼容，实际文件与服务还必须通过校验。已在原厂镜像＋ReviOS 组合上测试；其他镜像请先审计，不要绕过预检查。详见[参考镜像](docs/REFERENCE-BASELINE.md)和[实机测试记录](docs/TEST-RESULTS-0.1.7.md)。

## 快速开始

### 1. 下载并解压

从 [Releases](https://github.com/mihomoQ/ctyun-trim/releases) 下载所选版本的 `CTyunTrim-<版本>-Diagnostic.zip` 和同名 `.sha256` 文件，核验后完整解压。不要混用不同版本的脚本，也不要通过远程管道直接执行。校验方法见[使用文档](docs/USAGE.md#下载与校验)。

如果搭配 ReviOS，以下流程适用于已经应用 ReviOS、天翼组件仍可被核验的系统。需要先解除预装更新策略再安装 ReviOS 时，请使用[分阶段流程](docs/USAGE.md#与-revios-分阶段使用)。

### 2. 查看系统和计划

在解压目录打开管理员终端，依次运行：

```powershell
.\Start-CTyunTrim.cmd -Mode Audit
.\Trim.cmd -WhatIf
```

审阅输出并确认已有可用快照后，再继续下一步。

### 3. 执行精简

```powershell
.\Trim.cmd -Force
```

提示 `PendingReboot` 时，重启后再次运行同一条命令。无需手填 RunId，脚本不会自动重启。任务完成后再运行一次会验证结果，不会重复删除。

完成后，请通过天翼客户端测试重连、键鼠、双向文本剪贴板和普通文件互传；自动验证不能替代实际功能检查。

<details>
<summary>已精简系统：只恢复关机和重启选项</summary>

使用正在操作桌面的同一账户打开管理员终端：

```powershell
.\Restore-PowerMenu.cmd -Force
```

无需重新精简，不会直接关机或重启。范围和管理策略限制见[电源菜单修复](docs/POWER-MENU.md)。

</details>

## 文档

| 我想了解… | 文档 |
| --- | --- |
| 参数、分阶段操作、升级和常见阻断 | [完整用法](docs/USAGE.md) |
| 如何搭配 ReviOS | [ReviOS 配合说明](docs/REVIOS.md) |
| 哪些组件保留，哪些移除 | [组件边界](docs/COMPONENTS.md) |
| 如何提供诊断信息 | [诊断包说明](docs/DIAGNOSTICS.md) · [辅助工具](tools/README.md) |
| 备份保存在哪里，如何恢复 | [备份与恢复](docs/RECOVERY.md) |
| 已验证哪些功能，仍有哪些限制 | [测试记录](docs/TEST-RESULTS-0.1.7.md) · [威胁模型](docs/THREAT-MODEL.md) |

## 反馈与贡献

遇到问题请提交 [Issue](https://github.com/mihomoQ/ctyun-trim/issues)，说明版本、运行模式和报错。可使用 `-Diagnostic` 生成诊断包，分享前请检查内容；不要上传完整运行备份、隔离文件、账户凭据或私钥。

欢迎提交组件证据、测试反馈和改进建议。请先阅读[贡献指南](CONTRIBUTING.md)；安全问题按 [SECURITY.md](SECURITY.md) 处理。

## 声明与许可

本项目与天翼云、ReviOS、AME 等相关方无隶属或认可关系。保留厂商组件仅表示功能需要，不代表其安全可信；本工具也无法约束云平台对虚拟机、磁盘、快照和网络的控制。详见[免责声明](DISCLAIMER.md)。

采用 [GNU General Public License v3.0](LICENSE)，仅限第 3 版（`GPL-3.0-only`）。历史发布包保留各自附带的许可证。
