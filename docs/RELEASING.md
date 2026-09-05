# 发布说明规范

GitHub Release 面向使用者，说明“这一版新增或修复了什么”。技术实现细节记录在 CHANGELOG，
完整操作步骤放在 README 或功能文档，测试过程放在测试记录中。

## 标题与正文

- 显示标题统一为 `v0.1.8` 这样的版本号。预发布状态由 GitHub 的 Pre-release 标记表达，不在标题重复项目名、Diagnostic 或 Archive。
- 开头用一句话说明本版重点，不重复版本标题，不写空泛的发布宣言。
- 摘要下提供一行导航：加粗的 Windows x64 ZIP 下载链接、SHA-256 校验文件、对应版本的使用文档。直接链接已经存在的附件，不增加图片徽章、伪按钮、平台矩阵或长哈希表。
- 导航下放置 `<details>` / `<summary><strong>English</strong></summary>`，包含完整英文摘要、导航、变更、提示和链接。中文默认展示，英文入口无需翻到正文末尾；不用中英混排标题冒充翻译。
- 小版本默认只有一个 `### 更新内容` 标题，英文使用 `### What's changed`，下面平铺变更；多个类型用行内 `**新增：**` / `**修复：**` / `**改进：**` 标识。若全是同类修复，直接列条目，不重复标签。不把两三条内容拆成多个大标题。
- 中英两版逐条对应，功能、限制、升级操作、已知问题、命令和链接均保持一致。英文版不是摘要，不遗漏安全提醒；代码标识符和文件名保持原样。
- 每条说明一个用户可感知的变化。小修复版可以只有一两条，不为了统一长度而填充文字。
- 必须采取的升级操作放在一个 GitHub 原生 `[!NOTE]` 提示框；影响使用的已知缺陷用 `[!WARNING]`。没有必要提醒时不加提示框，不新增教程章节。
- 不在正文重复标题、粘贴终端输出或长哈希，也不放测试计数、实机排障对话、补档过程、自我评价或完整教程。
- 不捏造贡献者、Issue/PR 编号、性能提升或兼容性承诺。安全边界若影响升级选择，简短说明并链接细节。
- 文末仅保留完整更新日志，以及确有需要的归档说明。相邻标签有祖先关系时可以用 Compare；重建归档等特殊历史使用固定版本 CHANGELOG，避免误导。

发布正文的唯一维护源为 `docs/releases/<版本>.md`。编辑已发布文案时同步修改这里的文件，
再使用 `gh release edit <已有标签> --title v<版本> --notes-file docs/releases/<版本>.md`。

## 发布流程

1. 在 main 完成修改并通过相关测试，提交、推送源码，不为每个小版本创建分支或 PR。
2. 更新版本号时构建对应安装包，验证包内容及 SHA-256，并等候该提交的 CI 通过。
3. 按上述规范编写发布说明，创建指向该提交的版本标签和 Prerelease，上传安装包与 `.sha256` 文件。
4. 读回 GitHub 元数据，确认正文、标签、目标提交、附件和摘要正确。常规提交但未更新版本号时，不额外发版本。

只修改发布说明时，不提升软件版本、不重新打包、不重新上传既有附件、不移动标签、不重建 Release，
也不将预发布改为正式版。显示标题不带 Diagnostic，不意味着现有 `v0.1.x-diagnostic` 标签和附件名称需要重命名。

## 简短示例

```markdown
修复重启后源目录重新生成导致的续跑失败。

**[下载 Windows x64 · ZIP](release-zip-url)** · [SHA-256](checksum-url) · [使用文档](version-docs-url)

<details>
<summary><strong>English</strong></summary>

Fix resuming cleanup when a source directory is recreated after a reboot.

**[Download Windows x64 · ZIP](release-zip-url)** · [SHA-256](checksum-url) · [Documentation](version-docs-url)

### What's changed

- Fixed cleanup being interrupted when a quarantined source directory is recreated after a reboot.

> [!NOTE]
> Extract the new package in full before resuming the original task. Do not mix scripts from different versions.

[Full changelog](version-comparison-url)

</details>

### 更新内容

- 修复重启后续跑时，已隔离目录重新生成导致任务中断的问题。

> [!NOTE]
> 请完整解压新版后继续原任务，不要混用不同版本的脚本。

[完整更新日志](version-comparison-url)
```

写法参考：[MAA](https://github.com/MaaAssistantArknights/MaaAssistantArknights/releases)、
[Sandboxie](https://github.com/sandboxie-plus/Sandboxie/releases)、
[Reynard](https://github.com/minh-ton/reynard-browser/releases)、
[LocalSend](https://github.com/localsend/localsend/releases)、
[PowerToys](https://github.com/microsoft/PowerToys/releases)、
[v2rayN](https://github.com/2dust/v2rayN/releases)。只借鉴组织方式，不复制其项目内容。
