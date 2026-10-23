# 原生 APT 容器验证

对应源码提交：`cd288465de90fc148bc2789c1e7e0ed74b21fd32`。

[GitHub Actions 实际运行记录](https://github.com/463861437/guard-for-php74/actions/runs/39892837206)：2026-10-23，6 项全部通过。

覆盖 Ubuntu 22.04 / 24.04 的 Ondřej PPA、Ubuntu 26.04 的 Sury，以及 Debian 11 / 12 / 13 的 Sury。这里保留运行产生的原始 JSON；`index.json` 记录文件 SHA256、来源提交和运行链接。

每个测试使用独立 Linux 容器，核对固定公钥指纹并配置 `signed-by` 后安装 PHP 7.4 CLI 作为测试样本，验证真实 python-apt 的来源、站点、套件、发行代号及原生 dpkg 版本比较，确认旧版本、伪造来源和跨厂商升级被拒绝。

这些结果没有验证生产升级、PHP-FPM / Apache 重启、源码编译或业务行为。Debian 11 的最终安全包已迁至官方归档；只有该一次性测试容器调整了安全仓库 URI，签名和有效期检查保持启用。生产安装器和修复工具不会改写系统仓库。
