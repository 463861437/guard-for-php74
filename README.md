# Guard for PHP 7.4

一键检测并修复 **CVE-2026-109618 / CVE-2026-109619**，保留 PHP 7.4 分支和已有 yum/dnf/apt 原生安装布局。

自动识别系统与包来源 → 选择可信修复包或匹配的源码配方 → 补齐构建依赖 → 普通用户编译与测试 → 配置备份 → 原生 RPM/DEB 升级 → 服务重启与复查。

**当前版本 v1.7.0 为预发布。** 统一入口可以自动识别发行版、补齐缺少的启动依赖，再选择已适配的修复路线。它针对两个指定漏洞；兼容范围同时取决于系统版本、架构、PHP 包来源和已有仓库。

## 一条命令运行

```sh
curl -fL --proto '=https' --proto-redir '=https' https://github.com/463861437/guard-for-php74/releases/download/v1.7.0/install.sh -o guard-install.sh && sh guard-install.sh --yes
```

已经是 root 时直接运行；普通用户会通过 sudo 执行需要权限的步骤。`--yes` 会安装缺少的依赖、应用补丁，并重启相关 PHP 服务，可能短暂中断业务。

下载启动器固定引用 **v1.7.0** 的单文件及内置 SHA256，校验通过后才执行主程序。它使用 POSIX `sh`，不要求预先安装 Bash/Python；最少启动依赖由系统已有的可信软件源补齐。安装器不改写软件源、不切换 PHP 分支。

后续检测、查看计划和实际修复分别使用：

```sh
sh guard-install.sh --check                 # 只检查启动环境，不联网、不提权
sh guard-install.sh audit                   # 检测当前 PHP
sh guard-install.sh plan                    # 查看修复计划
sh guard-install.sh --yes --lock-wait 300    # 执行修复
```

`audit` / `plan` 不安装缺少的启动依赖；如依赖不足会列出缺项。已有 Bash/Python 和原生绑定时，也可直接下载 [单文件主程序](https://github.com/463861437/guard-for-php74/releases/download/v1.7.0/php74-patch-1.7.0.sh)，或克隆后执行 `sudo bash php74-patch.sh --yes`。`bash php74-patch.sh --support` 可离线查看完整支持规则。

只有 wget 时，可用 `wget --https-only https://github.com/463861437/guard-for-php74/releases/download/v1.7.0/install.sh -O guard-install.sh && sh guard-install.sh --yes`。内置下载器接受 curl 或 GNU Wget，拒绝绕过 HTTPS 证书校验。

## 遇到 cron 和后台队列阻止时

v1.7.0 增加显式调度维护。Amazon Linux 2 使用 `crond.service`，Ubuntu/Debian 通常使用 `cron.service`。下载本版启动器后，按实际服务范围执行，例如：

```sh
sh guard-install.sh --yes --pause-scheduler crond.service --drain-wait 300 \
  --service supervisord.service --service example-worker.service
```

该选项会在补丁构建和测试完成后，暂停**整个指定 cron 调度器**，等待已发现的任务自然结束，重新检查服务范围，再安装并恢复调度。等待超时则不安装、不强杀任务，并尝试恢复调度。`--service supervisord.service` 会重启整个 Supervisor 单元及其管理的任务；示例中的业务服务名须替换成你实际要重启的服务。

只读预演可将 `--yes` 换为 `plan`，保留相同参数。未指定维护范围时仍会阻止未知后台进程。维护只覆盖可核实归属的任务及其记录的 systemd scope；工具运行前已经脱离 cron 进程树、尚未启动 PHP 的后台延时任务不保证被识别。自定义调度器、容器或无法验证的停止配置会阻止自动维护。详细边界、恢复方法见[后台任务说明](PHP74一键补丁说明.md#后台任务与业务检查)。

## 适配范围

| 系统与来源 | 修复路线 |
|---|---|
| Amazon Linux 2 x86_64，AWS `7.4.33-1.amzn2` 包族 | 宝塔 7.4.34 源码 + AWS 打包规则，原生 RPM |
| CentOS 7 / RHEL 7 x86_64，Remi 系统 `7.4.33-15.el7.remi` 包族 | 宝塔源码 + 固定 Remi EL7 打包规则，原生 RPM；不覆盖 SCL `php74-php-*` |
| Ubuntu 20.04 amd64，Ondřej PPA `1:7.4.33-…+ubuntu20.04.1+deb.sury.org+…` | 宝塔源码 + 经核对的 Ondřej 打包规则，本机重建 DEB |
| Ubuntu 20.04 官方 PHP 7.4.3 | 已配置并授权的 Ubuntu Pro/ESM 修复源，最低核实版本 `7.4.3-4ubuntu2.29+esm5` |
| Ubuntu 22.04 / 24.04，已有 Ondřej PHP PPA | 使用已核实的 `7.4.33-31` 或更高同系回补包，验证 APT Origin / 站点 / suite / codename |
| Ubuntu 22.04 / 24.04 / 26.04，已有 DEB.SURY.ORG | 使用同系统、同来源的已核实 `7.4.33-31` 或更高包 |
| Debian 11 / 12 / 13，已有 DEB.SURY.ORG | 使用同系统、同来源的已核实 `7.4.33-31` 或更高包；不自动把 Debian 官方包换成 Sury |
| RHEL / CentOS Stream / Rocky / AlmaLinux / Oracle Linux 8 / 9 / 10，已有 Remi PHP 7.4 | 同源原生 RPM 升级，支持系统包及 SCL `php74-php-*`；固定 Remi 公钥隔离验签 |
| 其他 yum/dnf/apt 系统或来源 | 仅在有策略已核实的同分支修复包时更新；没有匹配配方则停止 |
| Alpine/apk、Arch/pacman、openSUSE/zypper、宝塔面板 PHP、手工编译、容器 PHP | 识别并说明未适配；本版不自动修改这些 PHP 安装 |

仓库升级使用本机已有架构的候选包；APT 由原生仓库和已安装架构约束，Remi 路线接受 x86_64 / aarch64。三条本地源码构建路线仍限于 x86_64/amd64。Amazon Linux 2023 可启动检测，但没有 PHP 7.4 的 AL2 兼容构建路线；不会按 `ID_LIKE` 冒充其他发行版。

Ubuntu 本地配方使用固定 **jammy -31 源码打包归档**，经逐项补丁核对后在 focal 构建，不是 Ondřej 官方 focal 二进制发行。官方 PHP 7.4.3 不会自动切换到 PPA 体系。

完整行为、路径、退出码和独立构建/部署细节见 [使用说明](PHP74一键补丁说明.md)。多 PHP 分支并存、未知 PHP 进程或无法确认服务范围时，一键入口会明确阻止部署。

## 部署与验证规则

- 已有可信修复包优先；源码构建前先检查配置、服务和运行时覆盖。
- 构建工具及依赖通过原生包管理器解析，已有依赖不重复安装；构建以普通用户运行。可用 `--build-user` 指定账户，没有可用普通账户时在 `--yes` 下创建专用账户。
- Remi 回补包以固定官方公钥在隔离 RPM 数据库中验签，候选、事务预览、安装及安装后状态分别复核；不把版本字符串或 Vendor 标签当成签名证明。
- 固定源码输入及 SHA256；AWS 原 SRPM 另验签名。完整 PHP 测试与关键回归必须通过才能部署。
- 只升级已安装的相关 PHP 子包，拒绝降级、删除、未批准的依赖变化或不兼容来源，不使用 `--nodeps`。
- 本地重建包没有厂商签名；固定输入和本地测试记录不等同于厂商签名。`--yes` 接受内置配方生成的本地产物。
- 未映射到服务的 PHP 后台进程会阻止安装；可核实的 cron 任务可显式选择调度维护。自定义队列可显式指定 `--service example-worker.service`；指定 Supervisor 会重启整个单元。
- 配置备份不等于整机/业务数据备份；失败时保留真实阶段和日志，不承诺自动回滚。
- 总报告通常位于 `/var/log/php-cve-guard/build-env-*/oneclick.json`。重复运行会核对安装回执和实际文件内容，不仅比较版本号。

## 开发与测试

```bash
python3 -m unittest discover -s tests -q
python3 assemble.py
python3 tools/verify_manifest.py
```

测试与组装不安装 PHP 或修改服务。`src/` 是维护入口；`assemble.py` 生成 `php_guard.py`、`php-cve-guard.sh` 和 `php74-patch.sh`，并把许可文本带入单文件。修改后重新生成载荷和 SHA256 清单；CI 会检查生成文件是否与源码一致。

`python3 tools/package_release.py` 从 Git 已跟踪文件制作 `dist/` 发布包、固定版本启动器及各自 SHA256 校验文件，同时刷新仓库的 `SHA256SUMS`。发布检查证据见 [validation](validation)。Linux CI 包含离线逻辑测试、发行版容器启动检查、APT/Remi 来源检查，以及专用 GitHub 托管虚拟机上的 cron 维护演练。容器验证的详细范围见 workflow 与执行日志；**不等于完整源码构建、生产服务重启或业务验收**。三条本地宝塔 7.4.34 配方尚未完成全部目标系统的构建和部署验收。

上一版实测记录（v1.6.0）：504 项离线测试通过；[13 项启动矩阵](https://github.com/463861437/guard-for-php74/actions/runs/39892837227)通过（12 个可启动系统及 1 个 Alpine 拒绝用例）；[6 个 APT 容器](https://github.com/463861437/guard-for-php74/actions/runs/39892837206)与 [3 个 Remi 容器](https://github.com/463861437/guard-for-php74/actions/runs/39892837364)的原生来源/签名检查通过。Debian 11 已结束常规支持，测试夹具使用官方签名安全归档；生产脚本不自动改写失效的软件源。详细原始证据见 `validation/apt-native/` 和 `validation/remi-native/`。

## 许可与来源

原创工具代码采用 [MIT](LICENSE)；PHP 补丁片段与其他第三方材料保留各自许可，具体见 [NOTICE.md](NOTICE.md)。独立脚本内也包含相关许可与致谢。

本项目是独立兼容工具，没有 PHP、宝塔、AWS、Canonical、Fedora、Remi 或 Ondřej 的官方背书。历史命令文件名保留兼容。

This product includes PHP software, freely available from <http://www.php.net/software/>.

This product includes software developed by the Apache Group for use in the Apache HTTP server project (http://www.apache.org/).
