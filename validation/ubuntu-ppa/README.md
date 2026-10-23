# Ubuntu 20.04 / Ondrej PHP 7.4 原生 DEB 构建配方验证

本目录记录 2026-10-23 的源码准备验证。未在 Ubuntu 20.04 实际编译、安装或运行 PHP；这些记录不等于生产验收。

固定输入：

- 宝塔 `php-7.4.34.tar.gz`，SHA256 `343fe09e745ff4eacdd4e223b45085620ffd0e9a85eb467fc33eb361ab34ddf9`。
- Launchpad Ondrej `1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1` 的 Debian packaging 归档，SHA256 `9bb6273e01ea4c127ebe95cedd0cedf6bc3f6658b4ac5e7c830f91ae7e7e3749`。
- 这是从已发布 Jammy 源码规则派生、供 Ubuntu 20.04 amd64 本机构建的本地配方；输出版本 `1:7.4.34-0phpguard1~ubuntu20.04.1` 不冒充 Canonical 或 Ondrej 官方 Focal 二进制包。

实际源码检查：

1. Ubuntu 官方 Focal `7.4.3-4ubuntu2.29` 共 113 项补丁：62 项正向可应用，27 项完整反向可证明已有，24 项仍冲突。没有跳过这些冲突制作官方源替换包；官方 7.4.3 使用已核实 ESM 安全包路线。
2. 当前 Ondrej -31 规则共 164 项补丁。原始栈有两个冲突：0136 ctype 修复与 0164 本次安全补丁都涉及 `main/rfc1867.c`。
3. 0136 调整上传解析的新上下文，保留所有六处 unsigned-char 修复，其中一处已存在于宝塔源码。`0136-context-rebase.diff` 展示调整，其他 54 个文件原补丁不变。
4. 0164 的完整反向检查只差宝塔源码中的一个空行；`0164-context-rebase.diff` 只添加这行用于等价证明。没有反向修改源码或移除修复。
5. 调整后 164 项全部核实：162 项完整正向应用，2 项完整反向 dry-run 成功证明已包含。全部 `-F0`，未丢弃任何冲突安全补丁。
6. 工具自带 13 个关键回归测试 fixture 补丁可完整应用。
7. Debian rules 原默认关闭测试；新配方开启完整测试并修正其 CGI 测试路径为 `cgi-build/sapi/cgi/php-cgi`（PHP 自身 config9.m4 定义）。构建后还必须通过完整摘要验证和 CLI/FPM 构建的 OOM 退出检查。
8. 构建依赖字面清单与固定 `.dsc`、`debian/control` 正规化后完全一致；保留版本、替代依赖和体系结构限制。

原始来源：

- https://download.bt.cn/src/php-7.4.34.tar.gz
- https://api.launchpad.net/1.0/~ondrej/+archive/ubuntu/php/+sourcepub/18891783
- https://launchpad.net/~ondrej/+archive/ubuntu/php/+sourcefiles/php7.4/1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1/php7.4_7.4.33-31+ubuntu22.04.1+deb.sury.org+1.debian.tar.xz
- https://api.launchpad.net/1.0/ubuntu/+archive/primary/+sourcepub/17131414
- https://ubuntu.com/security/notices/USN-8948-2

Focal PPA 的历史发布 -20/-18/-16 元数据可见，但 Launchpad `sourceFileUrls` 返回空；没有将空来源当成可下载的固定输入。
