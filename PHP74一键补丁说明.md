# Guard for PHP 7.4 · 1.5.0 一键补丁工具（预发布）

上传单文件 `php74-patch-1.5.0.sh` 到服务器 `/tmp`，运行一次：

```bash
sudo bash /tmp/php74-patch-1.5.0.sh --yes
```

该命令针对 **CVE-2026-109618 / CVE-2026-109619**。自动识别 Linux 系统、架构、PHP 包来源和运行服务；优先使用可信仓库修复包，没有可用包时匹配内置源码配方，补齐构建依赖，以普通用户编译并运行测试，然后备份配置、安装原生 RPM/DEB、重启相关服务和复查。保留 PHP 7.4 分支。没有 `--yes` 时只生成路径与服务计划，不安装依赖、PHP 包或重启服务。

也可以先检测和查看计划：

```bash
sudo bash /tmp/php74-patch-1.5.0.sh audit
sudo bash /tmp/php74-patch-1.5.0.sh plan
sudo bash /tmp/php74-patch-1.5.0.sh --yes --jobs 2 --lock-wait 300
```

使用完整 ZIP 时，解压后执行其中的 `php74-patch.sh`；`php-cve-guard.sh php74-patch --yes` 是等效入口。不要把旧版普通 `fix --yes` 与这一自动构建入口混淆。

## 本版适配范围

| 系统与 PHP 安装来源 | 自动修复路径 |
|---|---|
| Amazon Linux 2 x86_64，AWS `php-7.4.33-1.amzn2` 包族 | 沿用 AWS 打包规则，宝塔 7.4.34 源码重建原生 RPM |
| CentOS 7 / RHEL 7 x86_64，Remi 系统 `php-7.4.33-15.el7.remi` 包族 | 沿用固定 Remi EL7 打包规则，重建原生 RPM；不适用于 `php74-php-*` SCL |
| Ubuntu 20.04 amd64，Ondřej PPA `1:7.4.33-…+ubuntu20.04.1+deb.sury.org+…` 包族 | 固定 Ondřej 打包规则在本机重建 DEB，保持 `php7.4-*` 原生布局 |
| Ubuntu 20.04 官方 PHP 7.4.3 | 使用已配置、已授权的 Ubuntu Pro/ESM 修复源，最低规则 `7.4.3-4ubuntu2.29+esm5`；没有修复候选则停止 |
| 其他使用 yum/dnf/apt 的发行版、架构或来源 | 检测后仅接受策略已核实的同分支修复包；没有精确匹配的源码配方时停止 |
| Alpine/apk、Arch/pacman、openSUSE/zypper、宝塔面板安装目录、手工编译、容器 | 本版不自动修改这些 PHP 安装；输出未覆盖/未适配，不会报告修复成功 |

**统一入口不代表所有 Linux、所有来源和架构都已有可用补丁。** 不会用 AL2 RPM 覆盖 Ubuntu/CentOS，也不会把 Ubuntu 官方 7.4.3 强行替换为 PPA 打包体系。多 PHP 分支并存时统一入口会阻止扩大更新/重启范围；已有多分支原仓库工具仍可分别出计划。

源码来源为宝塔发布的 PHP 7.4.34，安装位置与服务名由原生打包规则决定，不安装宝塔面板。Ubuntu 配方使用固定的 Ondřej **jammy -31 源码打包归档**，经补丁核对后在 focal 本机构建；生成包是本地兼容构建，不是 Ondřej 发布的 focal 官方二进制。Remi 配方使用固定 EL7 Git 打包提交，不假称已下载不存在的旧 SRPM。

## 自动补齐环境与部署行为

- 需要 Linux root/sudo，以及系统 Python 3.6+ 或 Python 2.7。YUM/APT 原生 Python 绑定用于解析真实版本依赖和事务。
- 首先检查包完整性、PHP 运行进程、FPM/Apache 配置和服务范围，未通过时不会先安装一大批构建依赖。
- 通过原生包管理器解析固定构建依赖，只在现有仓库中安装缺失项；必要时会升级共享开发库。删除、降级、替换、PHP 运行时及受保护服务包变化会阻止事务。不会自动导入未知仓库密钥、切换模块或系统版本、改写源为 Vault、开通付费 ESM。
- 自动选择 sudo 的普通用户、ec2-user 或 ubuntu；没有可用用户时，在 `--yes` 下创建专用普通账户 `phpguard-build`。可用 `--build-user` 指定账户。编译源码和打包脚本不以 root 执行。
- 使用固定输入 SHA256；AWS 原始 SRPM 另验 RPM 签名。全套测试汇总、关键回归和编译后版本/行为测试必须通过，才能进入安装。
- root 将构建产物复制到私有目录后重新核对元数据、哈希和日志，只升级本机已经安装的 PHP 核心子包。扩展依赖必须满足原生事务检查，不使用 `--nodeps` 或强制覆盖。
- 本地重建 RPM/DEB **没有 AWS、Remi、Ondřej 或宝塔的厂商签名**；`--yes` 接受这一固定配方的本地构建。DEB 仅在本次 root 私有目录使用本地 APT 索引，不写入系统软件源。
- 安装前备份配置；包的安装脚本和随后服务复查可能重启 PHP-FPM/Apache。事务失败可能留下部分变更，报告保留实际阶段，不承诺自动回滚。配置备份不是整机或业务数据备份。
- 同一已安装构建经回执、包内容和运行时校验通过后，重复运行不重新编译或重装。

编译耗时取决于 CPU 和内存，`--jobs` 默认为 2，可用 1–32。需要可用软件源和源码下载网络。源码工作目录可通过 `--work-dir` 指定；默认位于构建用户家目录下 `php74-patch-<配方>-1.5.0`。完整构建日志位于该目录的 `build-*/build.log`。

## 后台任务与业务检查

普通 PHP-FPM/Apache 会自动识别。自定义 systemd PHP 队列需明确指定其服务：

```bash
sudo bash /tmp/php74-patch-1.5.0.sh --yes \
  --service example-worker.service \
  --health-url http://127.0.0.1/healthz
```

`--service supervisord.service` 会重启整个 Supervisor 单元及所管理的任务，需按实际范围使用。cron、终端或其他管理器启动的未映射 PHP 进程会阻止自动部署；工具不会杀掉未知任务。`--health-url` 必须是你自己的无副作用健康接口，修复前后均要求返回 200/204。未提供地址时只验证组件与服务，不代表业务验收通过。

## 报告与退出码

总报告路径会直接显示，通常为 `/var/log/php-cve-guard/build-env-*/oneclick.json`；构建环境、包事务和服务校验另有子报告。退出码 `0`：本次 audit/fix 范围校验通过，或 plan 生成成功；`10`：未覆盖、缺包、服务/依赖阻止或仍待处理；`20`：操作失败或可能发生部分变更；`2`：参数或执行环境错误。必须结合运行模式和报告中的 `result` 判断，不把 plan 的 `0` 当成漏洞已修复。

重新检查本地构建使用 `php74-patch.sh audit`；普通 `php-cve-guard.sh audit` 只按原仓库策略判定，不会单凭自定义版本号信任本地补丁。

## 交付验证范围

此次已实际完成宝塔修复源码与上游提交核对、AL2/Remi/Ubuntu 源码准备及补丁兼容性检查；Remi 原有 27 个补丁保留，另加回归测试补丁；Ubuntu 164 个补丁中 162 个应用、2 个经完整反向检查确认源码已包含，2 处上下文重定位有固定校验与核对记录。445 项离线测试通过，完整结果及发布检查包含在 ZIP 的 `validation/`。

**本次没有在目标 Ubuntu/CentOS/AL2 上完成新版 7.4.34 的全量编译、安装及业务验收。** 交付的是带强制构建和安装校验的工具，不能把源码准备和离线测试等同于各系统实机修复已经成功。旧版 AL2 的实机测试记录不代表这三条新版构建路径已验证。

来源：[宝塔公告](https://docs.bt.cn/notices/php-nodejs-security-update-2026-10-21/)、[PHP 官方回补提交](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2)、[Ubuntu USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)、[Remi EL7 包索引](https://rpms.remirepo.net/enterprise/7/php74/x86_64/repoview/php.html)、[Ondřej PHP PPA](https://launchpad.net/~ondrej/+archive/ubuntu/php)。
