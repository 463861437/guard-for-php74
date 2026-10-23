# CentOS 7 / Remi PHP 7.4.34 源码配方核验

核验日期：2026-10-23。

本次路线使用 Remi 原生 `php-*` 打包结构，并替换为固定宝塔 PHP 7.4.34 源码。
不是宝塔面板安装器，也不把 AL2 RPM 安装到 CentOS。

## 固定输入

- 宝塔源码：`https://download.bt.cn/src/php-7.4.34.tar.gz`
- 源码 SHA256：`343fe09e745ff4eacdd4e223b45085620ffd0e9a85eb467fc33eb361ab34ddf9`
- Remi 官方打包仓库：`https://git.remirepo.net/git/rpms/php/php74.git/`
- Remi EL7 最后发布的普通 `php` 基线：`7.4.33-15.el7.remi`。
- 固定打包提交：`d3fb24595d6bcebd6bd29477bc59916f333f5233`。
- 固定 SPEC SHA256：`26cba4921765723a0dc30662e0a8c349a121c8f8f869829fbd85eab38bc94586`。
- `el7-inputs.json` 记录实际下载并核验的 47 个打包文件。

Remi 官方 EL7 二进制列表：
<https://rpms.remirepo.net/enterprise/7/php74/x86_64/repoview/php.html>。
该页面列出 `7.4.33-15.el7.remi`，对应 2024-06-05 的最后更新。
官方历史源码 RPM `https://rpms.remirepo.net/SRPMS/php-7.4.33-15.remi.src.rpm`
本次获取返回 HTTP 404，因此实现使用固定官方 Git 提交的文件，并逐文件校验 SHA256。
这是 HTTPS 来源与固定内容核验，**没有把它报告为 Remi 签名 SRPM 验证**。

## 旧验证记录已撤销

原 macOS `patch --batch -F0` 的“28 个补丁全部成功”结论无效。
Apple patch 2.0 会在这里静默反向应用已经存在的修复，仍返回 0；检查退出码及
日志中没有 fuzz/offset 不能证明安全代码被保留。`patchstack-el7-validation.json`
已标为 `validation_valid=false`、`clean=false`，只保留历史记录，不能用于构建验收。

原生 CentOS 7 的 GNU patch 2.7.1 / RPM 4.11.3 确认：固定宝塔源码已经包含
PHP 提交 `8ec78d28d20c82c75c4747f44c52601cfdb22516` 的 multipart 部件数量限制，
但还没有 `3a2fdef1ae38881110006616ee1f0534b082ca45` 的上传数量重复警告限制。
原 Patch203 重复应用前者时退出；不能跳过整个安全补丁或忽略错误。

新兼容补丁只移除已包含的那一个子提交，保留上传警告限制和两段 NEWS 更新。
原 Remi 补丁及其 SHA256 仍保留作为来源；SPEC 在 Patch203 前和完整补丁栈后
检查两个源文件的精确 SHA256，防止移除、反转或意外更改现有防护。
详见 `cve-2023-0662-source-overlap.json`。正式 v1.8.1 配方已通过完整原生
`rpmbuild -bp`，旧目录迁移和重复执行均通过，旧失败日志未改变。记录和原生日志见
`native-prep-1.8.1.json` / `native-prep-1.8.1.log`；原配方失败日志保留为
`native-prep-original.log`。完整编译、源码测试和两项真实 CGI 限额回归是独立的后续门禁。

## 历史验证范围（不作为当前通过证明）

1. 从上述固定提交下载打包文件，固定 SHA256。
2. 在宝塔源码上按原 SPEC 顺序应用 EL7 所需的 27 个 Remi 补丁，包括原有安全补丁。
3. 再应用工具的 PHP 回归测试补丁，共 28 个补丁；当时的成功结论已因上述静默反向行为撤销。
4. 真实运行本工具 `prepare`，确认固定输入与生成 SPEC 可以通过校验。
5. 执行构建边界与失败路径单元测试。

`patchstack-el7-validation.json` 保留了该次验证的原始输出及失效原因。

**本次没有在 CentOS 7 实际编译 RPM、安装软件或运行 PHP/业务测试。**
工具在构建机上必须依次通过原生 `rpmbuild -bp`、`rpmbuild -ba`、完整 PHP
测试结果解析、CLI 版本/OOM 回归检查与 RPM 产物身份检查，才生成可接受的构建记录。

## SPEC 调整

保留原 Remi 包名、文件路径、配置模板、依赖、ABI 检查、全部功能及安全修复；
Patch203 使用上述固定兼容版本，避免重复或反向应用已经内置的修复。
修改源码版本为 `7.4.34`，Release 为 `15.el7.remi.phpguard.baota20261023.1`。
原 PHP 7.4.33 的 `.asc` 签名不能认证宝塔归档，因此替换为固定源码 SHA256 检查。
从 `configure.ac` 读取源码版本，保留原 `buildconf --force`，生成文件须在编译后报告 7.4.34。
添加严格的测试失败退出，并保留已修正的关键时区测试。

原 Remi `with_zip=0` 由独立 PECL zip 包提供；不改变它的安装方式。
原 OCI8 可选构建默认关闭，此配方不自动删除/替换已有 OCI8 包；安装事务必须单独校验兼容性。

## 适用边界

配方只支持 CentOS 7 / RHEL 7 x86_64 上的普通 Remi `php-*` 系列。
`php74-php-*` SCL、IUS、系统 PHP 5.4、其他 EL 版本和 CPU 架构不共用此配方。
CentOS 7 已结束维护，缺失的历史依赖仓库不会被脚本自动切换为 Vault，仓库错误必须明确报告。
本配方延续 Remi 15 已有安全修复并增加此次两个 CVE 的源码补丁；不是对所有其他 PHP 或操作系统漏洞的修复承诺。

## 未采用的输入

另下载并试验了当前 Remi `php-7.4.33-31.remi.src.rpm`。
在宝塔最小回补源码上直接应用其完整补丁栈时，`php-cve-2026-7258.patch`
在 `main/rfc1867.c` 有 3 个 hunk 失败，记录见 `patchstack31.json`。
因此没有把 EL8+ 的新版打包配方直接移植到 EL7，也没有为消除失败而丢掉安全补丁。
