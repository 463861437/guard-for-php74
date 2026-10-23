# Guard for PHP 7.4

一键检测并修复 **CVE-2026-109618 / CVE-2026-109619**，保留 PHP 7.4 分支和已有 yum/apt 原生安装布局。

自动识别系统与包来源 → 选择可信修复包或匹配的源码配方 → 补齐构建依赖 → 普通用户编译与测试 → 配置备份 → 原生 RPM/DEB 升级 → 服务重启与复查。

**当前版本 v1.5.0 为预发布。** 已通过 445 项离线逻辑及故障路径测试、源码核对和补丁应用检查；尚未在各目标系统完成新版 7.4.34 的全量编译、安装和业务验收。这是针对指定漏洞的补丁工具，不是所有 PHP 漏洞的扫描器，也不保证任意 Linux/PHP 安装方式都能自动修复。

## 快速使用

从 [Releases](https://github.com/463861437/guard-for-php74/releases) 下载单文件脚本及 SHA256 校验文件，或执行：

```bash
curl -fLO https://github.com/463861437/guard-for-php74/releases/download/v1.5.0/php74-patch-1.5.0.sh
curl -fLO https://github.com/463861437/guard-for-php74/releases/download/v1.5.0/php74-patch-1.5.0.sh.sha256
sha256sum -c php74-patch-1.5.0.sh.sha256
sudo bash php74-patch-1.5.0.sh --yes
```

`--yes` 会安装所需构建依赖、安装补丁并重启相关 PHP 服务，可能造成短暂中断。没有 `--yes` 时只生成路径和服务计划。

先检查、查看计划或添加业务健康检查：

```bash
sudo bash php74-patch-1.5.0.sh audit
sudo bash php74-patch-1.5.0.sh plan
sudo bash php74-patch-1.5.0.sh --yes --jobs 2 --lock-wait 300 \
  --health-url http://127.0.0.1/healthz
```

克隆仓库后可直接使用 `sudo bash php74-patch.sh --yes`。单文件脚本已内嵌程序和补丁规则，不需要 pip；需要目标系统提供 Python 3.6+ 或 Python 2.7 及原生包管理器绑定。

## 适配范围

| 系统与来源 | 修复路线 |
|---|---|
| Amazon Linux 2 x86_64，AWS `7.4.33-1.amzn2` 包族 | 宝塔 7.4.34 源码 + AWS 打包规则，原生 RPM |
| CentOS 7 / RHEL 7 x86_64，Remi 系统 `7.4.33-15.el7.remi` 包族 | 宝塔源码 + 固定 Remi EL7 打包规则，原生 RPM；不覆盖 SCL `php74-php-*` |
| Ubuntu 20.04 amd64，Ondřej PPA `1:7.4.33-…+ubuntu20.04.1+deb.sury.org+…` | 宝塔源码 + 经核对的 Ondřej 打包规则，本机重建 DEB |
| Ubuntu 20.04 官方 PHP 7.4.3 | 已配置并授权的 Ubuntu Pro/ESM 修复源，最低核实版本 `7.4.3-4ubuntu2.29+esm5` |
| 其他 yum/dnf/apt 系统或来源 | 仅在有策略已核实的同分支修复包时更新；没有匹配配方则停止 |
| ARM、apk/pacman/zypper、宝塔面板 PHP、手工编译、容器 | 无本版自动源码修复适配；不会用其他发行版的包强行覆盖 |

Ubuntu 本地配方使用固定 **jammy -31 源码打包归档**，经逐项补丁核对后在 focal 构建，不是 Ondřej 官方 focal 二进制发行。官方 PHP 7.4.3 不会自动切换到 PPA 体系。

完整行为、路径、退出码和独立构建/部署细节见 [使用说明](PHP74一键补丁说明.md)。多 PHP 分支并存、未知 PHP 进程或无法确认服务范围时，一键入口会明确阻止部署。

## 部署与验证规则

- 已有可信修复包优先；源码构建前先检查配置、服务和运行时覆盖。
- 构建工具及依赖通过原生包管理器解析，已有依赖不重复安装；构建以普通用户运行。可用 `--build-user` 指定账户，没有可用普通账户时在 `--yes` 下创建专用账户。
- 固定源码输入及 SHA256；AWS 原 SRPM 另验签名。完整 PHP 测试与关键回归必须通过才能部署。
- 只升级已安装的相关 PHP 子包，拒绝降级、删除、未批准的依赖变化或不兼容来源，不使用 `--nodeps`。
- 本地重建包没有厂商签名；固定输入和本地测试记录不等同于厂商签名。`--yes` 接受内置配方生成的本地产物。
- 未映射到服务的 PHP 后台进程会阻止安装。自定义队列可显式指定 `--service example-worker.service`；指定 Supervisor 会重启整个单元。
- 配置备份不等于整机/业务数据备份；失败时保留真实阶段和日志，不承诺自动回滚。
- 总报告通常位于 `/var/log/php-cve-guard/build-env-*/oneclick.json`。重复运行会核对安装回执和实际文件内容，不仅比较版本号。

## 开发与测试

```bash
python3 -m unittest discover -s tests -q
python3 assemble.py
python3 tools/verify_manifest.py
```

测试与组装不安装 PHP 或修改服务。`src/` 是维护入口；`assemble.py` 生成 `php_guard.py`、`php-cve-guard.sh` 和 `php74-patch.sh`，并把许可文本带入单文件。修改后重新生成载荷和 SHA256 清单；CI 会检查生成文件是否与源码一致。

`python3 tools/package_release.py` 从 Git 已跟踪文件制作 `dist/` 发布包及单文件校验文件，同时刷新仓库的 `SHA256SUMS`。发布检查证据见 [validation](validation)。Linux CI 运行离线逻辑测试，**不执行原生 RPM/DEB 构建或生产安装**。

## 许可与来源

原创工具代码采用 [MIT](LICENSE)；PHP 补丁片段与其他第三方材料保留各自许可，具体见 [NOTICE.md](NOTICE.md)。独立脚本内也包含相关许可与致谢。

本项目是独立兼容工具，没有 PHP、宝塔、AWS、Canonical、Fedora、Remi 或 Ondřej 的官方背书。历史命令文件名保留兼容。

This product includes PHP software, freely available from <http://www.php.net/software/>.

This product includes software developed by the Apache Group for use in the Apache HTTP server project (http://www.apache.org/).
