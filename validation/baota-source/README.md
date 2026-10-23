# 宝塔 PHP 7.4.34 源码及 AL2 补丁栈验证（2026-10-23）

本目录只做公开源码获取、文件级比较和补丁应用验证；没有访问远程服务器，没有编译 RPM，也没有修改工具源码。

## 输入

- `php-7.4.34.tar.gz`：宝塔官方 https://download.bt.cn/src/php-7.4.34.tar.gz ，15,610,547 字节，SHA256 `343fe09e745ff4eacdd4e223b45085620ffd0e9a85eb467fc33eb361ab34ddf9`。SHA256 为此次实际下载计算，并非厂商发布的签名。
- `php-upstream-712e60f9.tar.gz`：PHP 官方 commit `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2` 的 GitHub archive；SHA256 `c85c8cae6cd97c8688eb0bb2385d2341b74606153d19c3c8688183c3bc760d47`。
- `php-7.4.33-1.amzn2.src.rpm`：AWS 官方固定 SRPM，SHA256 `7d1cd66b0c150054d15e83154e6d5eb5a25285056b33a765fbec4befeffe8795`。该 SHA 与既有仓库元数据相符；本次 macOS 本机未执行 rpm --checksig。
- `inputs.json` 保存 URL、SHA256 和大小；`amazon-srpm/` 是从已校验 SRPM 新提取的原厂输入。

## 源码对比

`source-comparison.json` 记录所有差异及 17 个 CVE 补丁涉及文件的 SHA256：

- 官方 GitHub archive 含 19,170 个文件，其中 19,168 个与宝塔包完全相同。
- 共同文件仅两处不同：`configure.ac` 把 `7.4.34-dev` 改为 `7.4.34`；`NEWS` 没有开发版占位标题。精确差异见 `upstream-text-differences.patch`。
- 宝塔包另外含 25 个 GitHub archive 不带的生成文件/PEAR phar；它们全部与 AWS SRPM 内 PHP 官方原始 7.4.33 tar.xz 对应文件逐字一致，详见 `generated-files-comparison.json`。
- 两项 CVE 补丁涉及的 17 个源文件全部与固定的 PHP 官方修复 commit 逐字一致，无需再次应用同一安全补丁。

## AL2 patchstack 实测

`patchstack-check.log` 为实际命令输出；`patchstack-validation.json` 为结构化结果；`patchstack-source/` 为应用完成的源码树。

按 AWS SPEC 顺序应用 Patch5/6/8/42/43/45/46/47（包含条件 ldap_r），再应用 Patch300，最后应用现有工具 v1.3.2 的 `php74-backport-tests.patch`。10 个 patch 均以 `patch -f -p1 -F0` 退出 0，日志无 fuzz/offset。未应用原厂仅声明但未启用的 Patch100，未重复应用已在宝塔包中的安全补丁。

## 必须处理的生成版本文件

宝塔包的 `configure.ac` 声明 `7.4.34`，但 `main/php_version.h` 仍是 `7.4.31-dev`，预生成 `configure` 仍是 `7.4.33`。AL2 原 SPEC 在 `%prep` 校验 `main/php_version.h`，而 `%build` 才执行 `buildconf --force`，所以只替换 Source0/upver 会在 `%prep` 失败。

可在宝塔专用 recipe 中，将 `%prep` 的版本来源校验改为严格读取 `configure.ac` 的唯一 `AC_INIT` 值，仍要求等于 7.4.34，保留 PHP/Zend/PDO ABI 检查。原 SPEC `%build` 的 `buildconf --force` 会生成 configure，后续 configure.ac 约第 136–149 行会重生成 `main/php_version.h`。最终 CLI/FPM 二进制必须额外验证报告 7.4.34。

此适配来自已核实源码生成流程，不需要手动把旧二进制或源码版本头改成新版本。是否能完整生成 RPM、通过全部测试与业务验证，仍需在 AL2 构建机执行。

本发布包仅附验证记录，未包含源码归档和已提取目录。构建工具下载并核对固定输入。
