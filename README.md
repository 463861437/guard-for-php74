# Guard for PHP

一键检测并修复 **CVE-2026-109618 / CVE-2026-109619**，保留已有 PHP 分支和 yum/dnf/apt 原生安装布局；支持既有 PHP 7.4 路线及指定 Remi EL7 PHP 8.2 包。

自动识别系统与包来源 → 选择可信修复包或匹配的源码配方 → 补齐构建依赖 → 普通用户编译与测试 → 配置备份 → 原生 RPM/DEB 升级 → 服务重启与复查。

**当前版本 v1.8.0 为预发布。** 统一入口可以自动识别发行版、补齐缺少的启动依赖，再选择已适配的修复路线。它针对两个指定漏洞；兼容范围同时取决于系统版本、架构、PHP 包来源和已有仓库。

## 一条命令运行

```sh
curl -fL --proto '=https' --proto-redir '=https' https://github.com/463861437/guard-for-php74/releases/download/v1.8.0/install.sh -o guard-install.sh && sh guard-install.sh --yes
```

已经是 root 时直接运行；普通用户会通过 sudo 执行需要权限的步骤。`--yes` 会安装缺少的依赖、应用补丁，并重启相关 PHP 服务，可能短暂中断业务。

下载启动器固定引用 **v1.8.0** 的单文件及内置 SHA256，校验通过后才执行主程序。它使用 POSIX `sh`，不要求预先安装 Bash/Python；最少启动依赖由系统已有的可信软件源补齐。安装器不改写软件源、不切换 PHP 分支。

后续检测、查看计划和实际修复分别使用：

```sh
sh guard-install.sh --check                 # 只检查启动环境，不联网、不提权
sh guard-install.sh audit                   # 检测当前 PHP
sh guard-install.sh plan                    # 查看修复计划
sh guard-install.sh --yes --lock-wait 300    # 执行修复
```

`audit` / `plan` 不安装缺少的启动依赖；如依赖不足会列出缺项。已有 Bash/Python 和原生绑定时，也可直接下载 [单文件主程序](https://github.com/463861437/guard-for-php74/releases/download/v1.8.0/php74-patch-1.8.0.sh)，或克隆后执行 `sudo bash php74-patch.sh --yes`。`bash php74-patch.sh --support` 可离线查看完整支持规则。

只有 wget 时，可用 `wget --https-only https://github.com/463861437/guard-for-php74/releases/download/v1.8.0/install.sh -O guard-install.sh && sh guard-install.sh --yes`。内置下载器接受 curl 或 GNU Wget，拒绝绕过 HTTPS 证书校验。

## 遇到 cron 和后台队列阻止时

从 v1.7.0 起支持显式调度维护。Amazon Linux 2 使用 `crond.service`，Ubuntu/Debian 通常使用 `cron.service`。下载本版启动器后，按实际服务范围执行，例如：

```sh
sh guard-install.sh --yes --pause-scheduler crond.service --drain-wait 300 \
  --service supervisord.service --service example-worker.service
```

该选项会在补丁构建和测试完成后，暂停**整个指定 cron 调度器**，等待已发现的任务自然结束，重新检查服务范围，再安装并恢复调度。等待超时则不安装、不强杀任务，并尝试恢复调度。`--service supervisord.service` 会重启整个 Supervisor 单元及其管理的任务；示例中的业务服务名须替换成你实际要重启的服务。

每台服务器的自定义服务可能不同，不能直接沿用其他机器的 `--service` 列表。遇到服务阻止时，先只读核实（替换示例名）：

```sh
systemctl show example-worker.service --no-pager -p LoadState -p ActiveState -p FragmentPath
```

仅当 `LoadState=not-found` 且确认该业务服务不属于当前机器时，删除多余的 `--service example-worker.service`；服务名称错误则改为正确名称。`inactive`、`failed`、`masked` 或属性无法核实时，先排查服务状态，不应仅为通过检查而删除参数。v1.7.3 起明确区分这些情况，仍阻止未通过服务预检的部署。

v1.7.5 新增可重复的 `--service-if-present`，适合多台机器共用命令。例如，有些机器使用 Supervisor、有些没有：

```sh
sh guard-install.sh fix --yes --pause-scheduler crond.service --drain-wait 300 \
  --service-if-present supervisord.service --jobs 2 --lock-wait 300
```

只有成功读取 systemd、核对服务身份并明确得到 `LoadState=not-found`，且没有相矛盾的 PHP 进程或活动服务记录时才跳过。服务存在时仍须通过活动状态检查；Supervisor 存在时仍会重启其管理的整个任务组。不存在的可选服务记录在 `optional_service_selection.skipped`；一旦选中的服务在后续阶段消失，部署仍会停止。`--service` 继续表示必须存在且需要重启的服务；同名同时使用两个参数时，严格请求优先。该选项不会跳过定时调度维护检查，也不会自动批准其他未知后台服务。

只读预演可将 `--yes` 换为 `plan`，保留相同参数。未指定维护范围时仍会阻止未知后台进程。维护只覆盖可核实归属的任务及其记录的 systemd scope；工具运行前已经脱离 cron 进程树、尚未启动 PHP 的后台延时任务不保证被识别。自定义调度器、容器或无法验证的停止配置会阻止自动维护。详细边界、恢复方法见[后台任务说明](PHP74一键补丁说明.md#后台任务与业务检查)。

## CentOS 7 的 PHP-FPM 属性检查

v1.7.6 兼容 systemd 219 的单数 `EnvironmentFile=` 输出。Remi EL7 默认 PHP-FPM 单元引用 `/etc/sysconfig/php-fpm`；当该文件仅含注释和空白时，新版会核实文件及父目录的所有者、权限和文件类型，再按原服务参数测试 FPM 配置，不需要删除服务配置。

每个环境文件都必须通过检查，部署前会再次验证。有效变量设置（包括 `PHPRC`）、续行、未知路径格式、符号链接、不可安全读取或正在变化的文件继续阻止自动部署；不执行环境文件，也不回显内容。此兼容只证明配置预检可以使用相同的空环境设置，不代表目标服务器的补丁已完成安装。

## 腾讯云 CentOS 7 构建依赖

v1.7.7 支持腾讯云基础仓库名 `os`，与 `base` 使用相同的签名和事务检查。仓库必须已配置、启用且开启 GPG 校验；工具不更改仓库文件。构建依赖不可用时，报告记录选中和排除的仓库 ID，便于判断是否遗漏镜像仓库。

Remi EL7 的 `oniguruma5php-devel` 等开发包位于 `remi` 主仓库，`remi-safe` 仅提供对应运行库。v1.8.0 可用 `--build-repo remi` 在本次依赖事务中临时使用已配置且 GPG 校验开启的 `remi` 仓库，默认不启用禁用仓库，不改写配置文件，也不会借依赖安装升级 PHP 或受保护服务包：

```sh
sh guard-install.sh fix --yes --build-repo remi \
  --pause-scheduler crond.service --drain-wait 300 \
  --service-if-present supervisord.service --jobs 2
```

仓库未配置、签名未通过或包不可用时仍停止；环境报告会一次列出所有无法满足的构建需求，而不只显示第一项。

## 构建进度与等待时间

本地 RPM/DEB 构建每 15 秒显示运行时间、当前阶段、日志增长、可读取的测试计数及资源状态。完整编译和测试可能耗时较长；阶段与测试计数来自实际日志，不提供虚构的整体完成百分比。

```sh
sh guard-install.sh --yes --progress-interval 15 --build-timeout 21600
```

`--build-timeout` 限制每个受监控的本地构建命令，默认 21600 秒（6 小时），可设 60–86400；`--progress-interval` 可设 5–300 秒。日志 5 分钟没有变化会提示检查，继续受总时限约束。超时或收到 INT/TERM/HUP 时，工具停止本次构建进程组并记录失败，不进入 PHP 安装。已有业务 PHP 进程不属于这个构建进程组。

完整日志仍在 `build-*/build.log`，旁边的 `build.log.progress.json` 保存最近进度、退出原因与清理结果。该进度文件不是补丁通过证明；完整测试、产物校验和安装门禁保持不变。已修复的机器通过安装回执与实际文件检查后不会重新构建。

## 构建测试与服务器 PHP 配置

v1.7.4 在 RPM/DEB 构建子进程内固定 `PHPRC=/dev/null` 和 `PHP_INI_SCAN_DIR=/dev/null`。PHP 的 `make test` 会复制默认 INI 到临时测试配置；直接继承服务器的 `disable_functions` 等设置可能让扩展探测失败，出现 `/SPL.so` 加载警告和大量扩展测试被跳过。

隔离只影响构建子进程；服务器 PHP 配置、函数限制和服务配置不变。构建出的扩展仍由原生 Makefile 加载，用例自己的 `-c` / `-d` 配置继续生效。所有原有源码测试和关键回归仍需通过，不能把失败用例改成跳过来完成部署。

遇到这一类旧版构建失败，下载 v1.7.4 后按原参数重跑即可。已核实的源码准备目录可以复用；工具会创建新的构建目录重新编译和完整测试，旧失败日志会保留。不能将本地回归测试通过等同于目标服务器已经安装补丁。

## 适配范围

| 系统与来源 | 修复路线 |
|---|---|
| Amazon Linux 2 x86_64，AWS `7.4.33-1.amzn2` 包族 | 宝塔 7.4.34 源码 + AWS 打包规则，原生 RPM |
| CentOS 7 / RHEL 7 x86_64，Remi 系统 `7.4.33-15.el7.remi` 包族 | 宝塔源码 + 固定 Remi EL7 打包规则，原生 RPM；不覆盖 SCL `php74-php-*` |
| CentOS 7 / RHEL 7 x86_64，Remi `php` / `php82-php` `8.2.20-1.el7.remi` 包族 | PHP 官方签名 8.2.35 源码 + 固定 EL7 打包规则，系统及 SCL 两套原生 RPM；保持原包名、目录和服务布局 |
| Ubuntu 20.04 amd64，Ondřej PPA `1:7.4.33-…+ubuntu20.04.1+deb.sury.org+…` | 宝塔源码 + 经核对的 Ondřej 打包规则，本机重建 DEB |
| Ubuntu 20.04 官方 PHP 7.4.3 | 已配置并授权的 Ubuntu Pro/ESM 修复源，最低核实版本 `7.4.3-4ubuntu2.29+esm5` |
| Ubuntu 22.04 / 24.04，已有 Ondřej PHP PPA | 使用已核实的 `7.4.33-31` 或更高同系回补包，验证 APT Origin / 站点 / suite / codename |
| Ubuntu 22.04 / 24.04 / 26.04，已有 DEB.SURY.ORG | 使用同系统、同来源的已核实 `7.4.33-31` 或更高包 |
| Debian 11 / 12 / 13，已有 DEB.SURY.ORG | 使用同系统、同来源的已核实 `7.4.33-31` 或更高包；不自动把 Debian 官方包换成 Sury |
| RHEL / CentOS Stream / Rocky / AlmaLinux / Oracle Linux 8 / 9 / 10，已有 Remi PHP 7.4 | 同源原生 RPM 升级，支持系统包及 SCL `php74-php-*`；固定 Remi 公钥隔离验签 |
| 其他 yum/dnf/apt 系统或来源 | 仅在有策略已核实的同分支修复包时更新；没有匹配配方则停止 |
| Alpine/apk、Arch/pacman、openSUSE/zypper、宝塔面板 PHP、手工编译、容器 PHP | 识别并说明未适配；本版不自动修改这些 PHP 安装 |

仓库升级使用本机已有架构的候选包；APT 由原生仓库和已安装架构约束，Remi 路线接受 x86_64 / aarch64。本地源码构建路线仍限于 x86_64/amd64。Amazon Linux 2023 可启动检测，但没有 PHP 7.4 的 AL2 兼容构建路线；不会按 `ID_LIKE` 冒充其他发行版。

Ubuntu 本地配方使用固定 **jammy -31 源码打包归档**，经逐项补丁核对后在 focal 构建，不是 Ondřej 官方 focal 二进制发行。官方 PHP 7.4.3 不会自动切换到 PPA 体系。

完整行为、路径、退出码和独立构建/部署细节见 [使用说明](PHP74一键补丁说明.md)。多 PHP 分支并存、未知 PHP 进程或无法确认服务范围时，一键入口会明确阻止部署。

## PHP 8.2 的 EL7 原生升级

v1.8.0 新增指定 Remi EL7 PHP 8.2.20 基线到 8.2.35 的构建路线。统一入口识别系统包 `php-*` 和 SCL `php82-php-*`；两者并存时分别构建、统一预演事务。只有已安装的核心子包进入升级，PECL 扩展及集合包装包保留并复查，不把 `/opt/remi/php82` 覆盖到 `/usr`。

源码固定 SHA256 并验证 PHP 官方发布签名；使用原 Remi EL7 SPEC，保留配置、模块 ABI 和服务布局，更新两份已不适配新源码的 Remi 补丁。完整源码测试、五项指定安全回归、产物身份及安装后文件验证全部通过才可报告成功。新版本号不能代替有效安装回执。

本地生成的 RPM 没有 Remi 厂商签名，不是 Remi 官方 EL7 发行。只有指定包基线、x86_64 和已配置的签名仓库可使用此构建路线；不会将 PHP 7.4 升到 8.2。独立构建与部署命令、布局及验证边界见 [PHP 8.2 EL7 说明](PHP82-EL7原生构建说明.md)。

## 部署与验证规则

- 已有可信修复包优先；源码构建前先检查配置、服务和运行时覆盖。
- 构建工具及依赖通过原生包管理器解析，已有依赖不重复安装；构建以普通用户运行。可用 `--build-user` 指定账户，没有可用普通账户时在 `--yes` 下创建专用账户。
- AL2 已安装 Apache 且缺少 `httpd-devel` 时，选择与现有 `httpd` 完整版本、架构一致的开发包，保留原始版本依赖约束。仓库没有匹配包或求解仍需变更受保护服务包时停止；环境报告保留选择证据。
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
