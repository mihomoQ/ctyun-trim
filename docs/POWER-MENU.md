# 恢复开始菜单关机和重启

适用问题：预装系统的开始菜单只剩锁定，关机和重启被隐藏。实机观察到
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoClose=DWORD 1`。

## 使用

0.1.8 的 Apply 在完成组件精简时自动执行此修复。已经通过旧版本精简的系统无需重新 Apply，
解压新版后，以正在使用桌面的同一账户打开管理员终端，运行：

```powershell
.\Restore-PowerMenu.cmd -Force
```

只预览、不写入：`Restore-PowerMenu.cmd -WhatIf`。机器可读输出：
`Restore-PowerMenu.cmd -Force -Json`。此独立入口不支持 `-Diagnostic`，不创建新的精简 RunId，
不修改已完成的精简日志。已完成的 `Trim.cmd -Force` 继续保持只读验证，升级不会偷偷改设置。

修复不会执行关机或重启，也不会强制结束资源管理器。完成后重新打开开始菜单；
若 Windows 缓存旧菜单，可在保存工作后注销再登录，或正常重启。`RefreshRequired` 表示本轮
改过策略、可能需要刷新桌面，不代表已经重启。`Passed` 是策略读回验证，不替代人工菜单检查。

## 精确范围

仅处理以下三个现有的 DWORD 1，将其设为 DWORD 0；缺失值不创建，现有 0 不改：

| 范围 | 注册表键 | 值 |
| --- | --- | --- |
| 机器，观察到的 OEM/遗留隐藏位 | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoClose |
| 执行脚本的当前用户 | HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoClose |
| 机器，标准策略 | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | HidePowerOptions |

Microsoft 文档的 NoClose 映射为用户级，机器级标准名称是 HidePowerOptions；机器级 NoClose
只作为本次镜像中观察到的兼容修复项。参见 [NoClose](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#noclose)
和 [HidePowerOptions](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#hidepoweroptions)。

不修改账户的关机权限、登录屏幕安全设置、电源计划、休眠/睡眠独立策略或
`PolicyManager\default` 模板。如果检测到设备级 [Start CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start)
隐藏策略，或 Machine/User、GroupPolicyUsers 中的 Registry.pol 含相关设置，会在写入前明确停止，要求先调整来源策略。
已加入企业域或通过 Windows 管理注册 API 检测到 MDM 注册的设备，也会停止自动修复；状态查询失败时不写入。
检测使用 [IsDeviceRegisteredWithManagement](https://learn.microsoft.com/en-us/windows/win32/api/mdmregistration/nf-mdmregistration-isdeviceregisteredwithmanagement)
的空 UPN 缓冲区形式，只取布尔状态、不读取管理账户身份。确认及备份之后、首次写入之前再次检查策略来源。
不重置整个 GroupPolicy 目录，仍需人工确认菜单并观察策略是否被第三方软件重新下发。

HKCU 始终指执行脚本的账户，不自动加载其他账户的配置文件。以其他管理员账户提权不会代替
原桌面用户修改 HKCU；应使用目标桌面用户的管理员会话。

## 备份与重复运行

每次有实际变更时，原始键名、值名、类型、值和执行账户 SID 保存到受保护的
`%ProgramData%\CTyunTrim\PowerMenuBackups\<时间-随机标识>\before.json`。
备份目录不能通过重解析点跳转，旧备份不会被覆盖。备份完成并验证后才修改值，写后检查类型和值。
没有待修复项时不新建备份。备份仅供人工定点恢复，不自动导入整个注册表键。

若发生部分写入后失败，保留已完成修改与原始备份，修复原因后可再次运行；不会自动回滚其他设置。

## 2026-09-05 实机验证

测试机已完成 0.1.7 精简且安装 ReviOS。本次只命中机器 NoClose 一项，将 DWORD 1 改为 0；
原值正确保存在独立备份中。WhatIf 未修改设置，重复运行 ChangedCount=0、未产生额外备份。
邻接 Explorer/ReviOS 设置、Machine/User Registry.pol 和原精简日志保持不变；4 个互通核心服务运行正常，设备错误为 0。
计算机组策略刷新后 NoClose 仍为 0，原精简 Verify 继续通过。用户确认开始菜单已经同时出现关机和重启。
本次未实际执行关机或重启，未改变原有的睡眠/休眠独立策略。
