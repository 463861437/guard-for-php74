# PHP 8.2 · Remi EL7 原生构建与升级

该路线针对 CVE-2026-109618 / CVE-2026-109619，使用 PHP 官方签名的 **8.2.35** 源码，在本机按 Remi EL7 的打包布局重建 RPM。它不是 Remi 官方 EL7 更新，也不是全部 PHP 漏洞扫描器。

## 支持的安装基线

仅接受 CentOS 7 / RHEL 7、x86_64、YUM 原生安装的 `8.2.20-1.el7.remi` 包族，以及本工具已验证的目标构建。

| 布局 | 核心包 | 程序与配置目录 | FPM 单元 |
|---|---|---|---|
| system | `php`、`php-cli`、`php-common` 等 | `/usr`、`/etc/php.ini`、`/etc/php.d` | `php-fpm.service` |
| scl | `php82-php`、`php82-php-cli`、`php82-php-common` 等 | `/opt/remi/php82`、`/etc/opt/remi/php82` | `php82-php-fpm.service` |

两套布局可以并存。即使 SCL 只安装了 `php82-php-common` 和某个扩展，该核心子包也必须处理；不会因为它没有 CLI/FPM 就跳过。

`php82-runtime` 等固定集合包装包不包含 PHP 引擎，已有包装包和 PECL 扩展保留。构建依赖需要 SCL RPM 宏时，仅允许从签名 Remi 仓库首次安装固定 `php82-build` / `php82-runtime` `8.2-5.el7.remi`；不以此例外升级任何现有 PHP 服务包。

其他版本、发行版、架构、混合 PHP 分支或未知来源会停止。PHP 7.4 继续使用既有路线，不升级成 PHP 8.2。

## 一键入口

```sh
curl -fL --proto '=https' --proto-redir '=https' \
  https://github.com/463861437/guard-for-php74/releases/download/v1.8.0/install.sh \
  -o guard-install.sh &&
sh guard-install.sh plan --build-repo remi
```

计划核对后，把 `plan` 改为 `fix --yes`。`--build-repo remi` 仅在本次构建依赖事务中临时使用**本机已配置且 GPG 校验开启**的 Remi 主仓库；不创建源、不改写 repo 文件、不影响 PHP 升级事务的选择。该仓库包含 `oniguruma5php-devel` 等 `remi-safe` 没有的开发包。

有 cron 和 Supervisor 任务的机器可以使用：

```sh
sh guard-install.sh fix --yes --build-repo remi \
  --pause-scheduler crond.service --drain-wait 300 \
  --service-if-present supervisord.service \
  --jobs 2 --lock-wait 300 --progress-interval 15 --build-timeout 21600
```

服务参数按本机业务选择。Supervisor 存在时会重启整个单元及其任务组；明确不存在时跳过。构建期间保持业务调度，产物就绪后才暂停选定调度器、等待在途任务结束、安装并恢复。

root 负责依赖安装与部署，源码编译以普通用户运行。入口自动选择可用账户，没有时创建专用构建账户；不依赖 `ec2-user`。可以用 `--build-user builder` 指定已有账户。

## 独立构建与部署

在源码仓库目录运行以下命令，`builder` 替换为已有普通用户。`setup` 补齐依赖和准备源码但不编译；`all` 继续完整构建，不部署 PHP。`--layout` 可以重复，默认只构建 system。

```sh
sudo bash php-cve-guard.sh build-remi-el7-php82 all --yes \
  --build-user builder --build-repo remi \
  --work-dir /home/builder/php82-el7 \
  --layout system --layout scl --jobs 2
```

每个布局在独立子目录中生成 `build-*/build.json`。只接受实际完成的报告，不自动寻找或采用旧失败目录。部署传入每个已安装布局对应的报告：

```sh
sudo bash php-cve-guard.sh remi-el7-php82 plan \
  --build-report /home/builder/php82-el7/system/build-EXAMPLE/build.json \
  --build-report /home/builder/php82-el7/scl/build-EXAMPLE/build.json
```

将示例路径替换为实际报告。独立部署没有自动 cron 维护入口，需先按业务安排调度/后台任务；统一一键入口会处理显式指定的维护范围。没有 SCL 包时不传 SCL 报告。`fix --yes` 仍会重验固定输入、官方源码签名、测试日志、RPM 元数据、包清单、服务和事务；只有计划通过才能安装。

修复后用统一入口 `audit` 或 `sudo bash php-cve-guard.sh remi-el7-php82 audit` 检查。安装回执位于 `/var/lib/php-cve-guard/upstream-remi-el7-php82.json`，必须与当前 RPM 头和非配置文件内容吻合；仅出现 8.2.35 版本号不足以认定本地包已验证。

## 构建与验证边界

- 源码、签名、公钥、SPEC、打包配置和补丁固定 SHA256。源码额外验证 PHP 发布者签名；EL7 GnuPG 2.0 使用私有临时 keyring，不修改系统钥匙环。
- 复用签名 PHP 8.2.35 源码已有的旧 OpenSSL ASN.1 访问器，让 EL7 的 OpenSSL 1.0.2 可编译 TLS 流模块；额外核实 IP 证书匹配与通配符处理回归，不修改证书匹配规则。
- 保留 Remi 的原生配置路径、`%config(noreplace)`、服务及 RPM scriptlet。保持 PHP API、Zend/PDO ABI 检查；不把新库文件直接复制覆盖到线上路径。
- 运行完整源码测试并解析汇总，另独立运行七项指定安全回归；测试失败、缺失或关键用例跳过都会阻止产物接受。
- 测试环境补齐 `tzdata >= 2022b`，只在 FPM 构建目录编译共享 `zend_test` 测试扩展；二进制 RPM 在构建和安装验收时均禁止携带该模块。
- 保留上游已声明的预期失败记录。仅精确认可固定 FPM 日志用例的“预期失败但实际通过”，保留其原始告警计数；其他告警和专项测试告警仍拒绝。[上游间歇性失败说明](https://github.com/php/php-src/commit/c4639a2debbdf6ac84ee334b9382d113a4862a52)
- 只升级当前已安装的核心子包。原生 YUM 事务复查禁止新增 PHP SAPI、删除、降级或未批准依赖变化；PECL 扩展及包装包在安装前后核对 RPM 头。
- 依赖准备也保护现有 PHP 和服务包。若 `httpd-devel` 需要变更 Apache 而无法保持现有版本，则停止；可以在同系统的独立构建机制作 RPM，随后复制完整构建目录并验证部署。
- 两种布局都需要时，任一构建失败都不会进入安装。超时、磁盘/内存不足和缺失仓库会保留阶段及日志。
- 本地生成 RPM 无厂商签名。固定来源和测试记录不等同于独立二进制可重复构建证明；构建用户、构建机及产物来源仍需可信。
- 自动服务复查不能替代业务验收；可通过 `--health-url` 加入业务健康检查。失败不承诺自动回滚。

源码发布说明：[PHP 8.2.35](https://www.php.net/archive/2026.php#2026-10-21-5)。详细实际验证证据以 `validation/` 中本版记录及 CI 运行结果为准；未记录的环境不表示已验证。
