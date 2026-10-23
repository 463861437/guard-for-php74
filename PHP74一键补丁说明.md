# Guard for PHP 7.4 · 1.7.3 一键补丁工具（预发布）

推荐的一条命令及最新适配矩阵见 [README](README.md)。下载启动器会自动补齐最少运行依赖。

也可以上传单文件 `php74-patch-1.7.3.sh` 到服务器 `/tmp`，运行一次：

```bash
sudo bash /tmp/php74-patch-1.7.3.sh --yes
```

该命令针对 **CVE-2026-109618 / CVE-2026-109619**。自动识别 Linux 系统、架构、PHP 包来源和运行服务；优先使用可信仓库修复包，没有可用包时匹配内置源码配方，补齐构建依赖，以普通用户编译并运行测试，然后备份配置、安装原生 RPM/DEB、重启相关服务和复查。保留 PHP 7.4 分支。没有 `--yes` 时只生成路径与服务计划，不安装依赖、PHP 包或重启服务。

也可以先检测和查看计划：

```bash
sudo bash /tmp/php74-patch-1.7.3.sh audit
sudo bash /tmp/php74-patch-1.7.3.sh plan
sudo bash /tmp/php74-patch-1.7.3.sh --yes --jobs 2 --lock-wait 300
```

使用完整 ZIP 时，解压后执行其中的 `php74-patch.sh`；`php-cve-guard.sh php74-patch --yes` 是等效入口。不要把旧版普通 `fix --yes` 与这一自动构建入口混淆。

## 本版适配范围

| 系统与 PHP 安装来源 | 自动修复路径 |
|---|---|
| Amazon Linux 2 x86_64，AWS `php-7.4.33-1.amzn2` 包族 | 沿用 AWS 打包规则，宝塔 7.4.34 源码重建原生 RPM |
| CentOS 7 / RHEL 7 x86_64，Remi 系统 `php-7.4.33-15.el7.remi` 包族 | 沿用固定 Remi EL7 打包规则，重建原生 RPM；不适用于 `php74-php-*` SCL |
| Ubuntu 20.04 amd64，Ondřej PPA `1:7.4.33-…+ubuntu20.04.1+deb.sury.org+…` 包族 | 固定 Ondřej 打包规则在本机重建 DEB，保持 `php7.4-*` 原生布局 |
| Ubuntu 20.04 官方 PHP 7.4.3 | 使用已配置、已授权的 Ubuntu Pro/ESM 修复源，最低规则 `7.4.3-4ubuntu2.29+esm5`；没有修复候选则停止 |
| Ubuntu 22.04/24.04 Ondřej PPA；Ubuntu 22.04/24.04/26.04 与 Debian 11/12/13 Sury | 已配置且认证的同来源仓库升级；严格匹配已核实回补版本与发行版，不自动换源 |
| RHEL/CentOS Stream/Rocky/AlmaLinux/Oracle Linux 8/9/10 Remi | 固定 Remi 公钥验证原生 RPM；支持系统及 SCL PHP 7.4 包，同架构升级 |
| 其他使用 yum/dnf/apt 的发行版、架构或来源 | 检测后仅接受策略已核实的同分支修复包；没有精确匹配的源码配方时停止 |
| Alpine/apk、Arch/pacman、openSUSE/zypper、宝塔面板安装目录、手工编译、容器 | 本版不自动修改这些 PHP 安装；输出未覆盖/未适配，不会报告修复成功 |

**统一入口不代表所有 Linux、所有来源和架构都已有可用补丁。** 不会用 AL2 RPM 覆盖 Ubuntu/CentOS，也不会把 Ubuntu 官方 7.4.3 强行替换为 PPA 打包体系。多 PHP 分支并存时统一入口会阻止扩大更新/重启范围；已有多分支原仓库工具仍可分别出计划。

源码来源为宝塔发布的 PHP 7.4.34，安装位置与服务名由原生打包规则决定，不安装宝塔面板。Ubuntu 配方使用固定的 Ondřej **jammy -31 源码打包归档**，经补丁核对后在 focal 本机构建；生成包是本地兼容构建，不是 Ondřej 发布的 focal 官方二进制。Remi 配方使用固定 EL7 Git 打包提交，不假称已下载不存在的旧 SRPM。

## 自动补齐环境与部署行为

- 主程序需要 Linux root/sudo，以及系统 Python 3.6+ 或 Python 2.7；`install.sh --yes` 可按需补齐最少运行依赖。YUM/DNF/APT 原生 Python 绑定用于解析真实版本依赖和事务。
- 首先检查包完整性、PHP 运行进程、FPM/Apache 配置和服务范围，未通过时不会先安装一大批构建依赖。
- 通过原生包管理器解析固定构建依赖，只在现有仓库中安装缺失项；必要时会升级共享开发库。删除、降级、替换、PHP 运行时及受保护服务包变化会阻止事务。不会自动导入未知仓库密钥、切换模块或系统版本、改写源为 Vault、开通付费 ESM。
- AL2 的 `httpd-devel` 缺失而 `httpd` 已安装时，工具选择与已安装 Apache 完整版本和架构一致的开发包，并核实其满足原始 SRPM 构建要求。无法找到匹配候选时停止；不能通过放开 `httpd` 保护来解决依赖。该规则不处理其他发行版的 Apache 打包差异。
- 自动选择 sudo 的普通用户、ec2-user 或 ubuntu；没有可用用户时，在 `--yes` 下创建专用普通账户 `phpguard-build`。可用 `--build-user` 指定账户。编译源码和打包脚本不以 root 执行。
- 使用固定输入 SHA256；AWS 原始 SRPM 另验 RPM 签名。全套测试汇总、关键回归和编译后版本/行为测试必须通过，才能进入安装。
- root 将构建产物复制到私有目录后重新核对元数据、哈希和日志，只升级本机已经安装的 PHP 核心子包。扩展依赖必须满足原生事务检查，不使用 `--nodeps` 或强制覆盖。
- 本地重建 RPM/DEB **没有 AWS、Remi、Ondřej 或宝塔的厂商签名**；`--yes` 接受这一固定配方的本地构建。DEB 仅在本次 root 私有目录使用本地 APT 索引，不写入系统软件源。
- 安装前备份配置；包的安装脚本和随后服务复查可能重启 PHP-FPM/Apache。事务失败可能留下部分变更，报告保留实际阶段，不承诺自动回滚。配置备份不是整机或业务数据备份。
- 同一已安装构建经回执、包内容和运行时校验通过后，重复运行不重新编译或重装。

编译耗时取决于 CPU 和内存，`--jobs` 默认为 2，可用 1–32。需要可用软件源和源码下载网络。源码工作目录可通过 `--work-dir` 指定；默认位于构建用户家目录下 `php74-patch-<配方>-1.5.0`。完整构建日志位于该目录的 `build-*/build.log`。

从 1.7.1 起，构建每 15 秒输出耗时、阶段、日志大小与最近更新间隔；测试日志包含 `TEST X/Y` 时显示真实测试计数。Linux 上同时显示可读取的构建进程数量、采样 CPU 和可用内存/磁盘；CPU 为采样区间观察值，短命子进程可能未被采到。编译不提供整体百分比，也不能仅凭日志暂时没有变化判定卡死。

可加 `--progress-interval 15 --build-timeout 21600`：输出间隔 5–300 秒，每个受监控构建命令的总时限 60–86400 秒（默认 6 小时）。预处理和正式编译分别计时，该参数不改变包管理事务的等待规则。连续 300 秒无日志更新只发提示，正常链接或安静测试仍可继续。

进度保存到日志旁的 `.progress.json`；完整日志保留。超时、非零退出或 INT/TERM/HUP 会清理本次独立构建进程组，普通用户 worker 清理结束后入口返回失败，不开始安装 PHP。强制 SIGKILL、掉电或内核不可中断状态不保证自动清理，需依据报告检查；不会以进度文件代替完整源码测试和产物验证。

## 后台任务与业务检查

普通 PHP-FPM/Apache 会自动识别。自定义 systemd PHP 队列需明确指定其服务：

```bash
sudo bash /tmp/php74-patch-1.7.3.sh --yes \
  --service example-worker.service \
  --health-url http://127.0.0.1/healthz
```

`--service supervisord.service` 会重启整个 Supervisor 单元及所管理的任务，需按实际范围使用。终端或其他管理器启动的未映射 PHP 进程会阻止自动部署；工具不会杀掉未知任务。cron 任务可使用下面的显式维护参数。`--health-url` 必须是你自己的无副作用健康接口，修复前后均要求返回 200/204。未提供地址时只验证组件与服务，不代表业务验收通过。

### cron 自动维护

```bash
sudo bash /tmp/php74-patch-1.7.3.sh --yes \
  --pause-scheduler crond.service --drain-wait 300 \
  --service supervisord.service --service example-worker.service
```

Ubuntu/Debian 通常将 `crond.service` 改为 `cron.service`；业务服务名按实际情况替换。`plan` 携带相同参数只读检查。`--drain-wait` 可设 0–3600 秒，默认 300；0 表示不等待仍在运行的任务。

1. 核实主机 systemd、准确的调度器单元、MainPID、真实可执行文件及停止配置。只有标准 `cron.service` / `crond.service` 且 `KillMode=process`、SIGTERM、无自定义启动/停止钩子等条件通过时才自动处理；不修改单元配置来绕过限制。
2. 构建依赖准备、源码编译和测试期间照常调度。产物准备好后重新核实任务身份，短暂冻结调度器主进程以记录其子任务和受保护的 systemd scope，再停止调度器。业务任务继续运行。
3. 等待已发现的任务和所记录 scope 内的任务自然结束；超时或检查不完整则不开始补丁安装。安装前再核对 PHP 包、进程和服务范围。
4. 原生包安装、指定服务重启及复查结束后恢复维护前运行的调度器；失败时也尝试恢复。原来 inactive 的调度器不会被启动。

**影响范围是整个 cron 调度器，不仅是 PHP 定时任务。** 暂停期间其他 cron 任务也不能按时启动，不能保证恢复后补跑。Supervisor 参数重启该单元管理的所有任务；请安排相应维护窗口。此流程只排空已发现且可归属的任务及记录的 scope；运行工具前已脱离调度树且尚未表现为 PHP 的延时后台任务不保证被识别，应由业务自己的停止/排空流程处理。

维护明细位于总报告同目录的 `maintenance.json`，包含等待任务、恢复状态和恢复命令。收到 INT/TERM/HUP 时，会等待已开始的原生包操作返回并尝试恢复调度后退出；强制 SIGKILL、机器掉电等情况下无法执行恢复。遇到恢复失败，按报告核实状态后执行对应的 `systemctl start cron.service` 或 `systemctl start crond.service`；若记录显示主进程仍被冻结，必须先验证 PID 和 start_ticks 再按报告恢复，不能对复用的 PID 发信号。

## 报告与退出码

总报告路径会直接显示，通常为 `/var/log/php-cve-guard/build-env-*/oneclick.json`；构建环境、包事务和服务校验另有子报告。退出码 `0`：本次 audit/fix 范围校验通过，或 plan 生成成功；`10`：未覆盖、缺包、服务/依赖阻止或仍待处理；`20`：操作失败或可能发生部分变更；`2`：参数或执行环境错误。维护被信号中断时返回 `128 + 信号编号`；恢复失败返回 `20`，即使包安装已经完成。必须结合运行模式和报告中的 `result`、`deployment_result`、`maintenance_restore` 判断，不把 plan 的 `0` 当成漏洞已修复。

重新检查本地构建使用 `php74-patch.sh audit`；普通 `php-cve-guard.sh audit` 只按原仓库策略判定，不会单凭自定义版本号信任本地补丁。

## 交付验证范围

此次已实际完成宝塔修复源码与上游提交核对、AL2/Remi/Ubuntu 源码准备及补丁兼容性检查；Remi 原有 27 个补丁保留，另加回归测试补丁；Ubuntu 164 个补丁中 162 个应用、2 个经完整反向检查确认源码已包含，2 处上下文重定位有固定校验与核对记录。源码配方的历史检查及本版来源研究见 `validation/`。当前离线测试与容器检查结果见 GitHub Actions；新增仓库规则按完整发行版身份、原生版本与认证来源判定。

**本次没有在目标 Ubuntu/CentOS/AL2 上完成新版 7.4.34 的全量编译、安装及业务验收。** 交付的是带强制构建和安装校验的工具，不能把源码准备和离线测试等同于各系统实机修复已经成功。旧版 AL2 的实机测试记录不代表这三条新版构建路径已验证。

来源：[宝塔公告](https://docs.bt.cn/notices/php-nodejs-security-update-2026-10-21/)、[PHP 官方回补提交](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2)、[Ubuntu USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)、[Remi EL7 包索引](https://rpms.remirepo.net/enterprise/7/php74/x86_64/repoview/php.html)、[Ondřej PHP PPA](https://launchpad.net/~ondrej/+archive/ubuntu/php)。
