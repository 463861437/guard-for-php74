#!/bin/sh
# Guard for PHP 7.4 launcher. Original code: MIT; see LICENSE.
# Downloads one pinned release only; never sources os-release or remote code.
set -u

PG_VERSION='1.7.1'
PG_ASSET='php74-patch-1.7.1.sh'
PG_URL='https://github.com/463861437/guard-for-php74/releases/download/v1.7.1/php74-patch-1.7.1.sh'
PG_SHA256='e9a4761dfa174655d8b92103e1116b6a96bef775e8c09ccf3ecc1fbfd156b6b3'
PG_TMP=''

pg_error() { printf '%s\n' "$*" >&2; }
pg_have() { command -v "$1" >/dev/null 2>&1; }
pg_help() {
    cat <<'HELP'
Guard for PHP 7.4：统一 Linux 下载启动器
用法：sh install.sh [audit|plan|fix] [--yes] [主脚本选项]
      sh install.sh --check | --help | --version
默认只生成修复计划；--yes 才允许补齐启动依赖和执行修复。
显式 audit / plan 即使附带 --yes 也不安装启动依赖。
--check 仅检查本机系统和启动依赖，不联网、不安装、不提权。
支持启动：Debian 10+、Ubuntu 18.04+、Amazon Linux 2/2023、
          CentOS/RHEL 7+、Rocky/AlmaLinux/Oracle Linux 8+、Fedora。
识别 apk / pacman / zypper，但尚无自动修复后端，不安装依赖。
启动兼容不代表有对应 PHP 补丁配方；主程序会核实来源和支持范围。
源安装、容器内 PHP 与不受支持的包来源不会被强行替换。
完整参数：--build-user、--work-dir、--jobs、--lock-wait、--service、
          --health-url、--health-host、--scan-root；值原样传入主脚本。
调度维护：--pause-scheduler crond.service（Ubuntu 为 cron.service）
          --drain-wait 300；部署前暂停整个调度器，等待在途任务后恢复。
额外后台服务须明确指定 --service；不会自动杀死等待超时的任务。
构建进度：--progress-interval 15；每个构建命令最长 --build-timeout 21600 秒。
HELP
}

# Accept only literal ID/VERSION_ID values. Never execute shell syntax in this file.
pg_read_os() {
    PG_OS='unknown'; PG_OS_VERSION='unknown'
    while IFS= read -r pg_line || [ -n "$pg_line" ]; do
        case "$pg_line" in
            ID=*) pg_key=ID; pg_value=${pg_line#ID=} ;;
            VERSION_ID=*) pg_key=VERSION_ID; pg_value=${pg_line#VERSION_ID=} ;;
            *) continue ;;
        esac
        case "$pg_value" in
            \"*\") pg_value=${pg_value#\"}; pg_value=${pg_value%\"} ;;
            \'*\') pg_value=${pg_value#\'}; pg_value=${pg_value%\'} ;;
        esac
        case "$pg_value" in ''|*[!a-zA-Z0-9._-]*) continue ;; esac
        case "$pg_key" in ID) PG_OS=$pg_value ;; VERSION_ID) PG_OS_VERSION=$pg_value ;; esac
    done < "$1"
}
pg_detect_os() {
    if [ -r /etc/os-release ]; then pg_read_os /etc/os-release
    elif [ -r /usr/lib/os-release ]; then pg_read_os /usr/lib/os-release
    else PG_OS='unknown'; PG_OS_VERSION='unknown'
    fi
}
pg_detect_manager() {
    PG_MANAGER='unknown'; PG_SUPPORTED=0
    # Match the declared platform first, so a foreign package-manager binary
    # cannot cause installation into the wrong package database.
    case "$PG_OS" in
        ubuntu|debian) pg_have apt-get && PG_MANAGER=apt ;;
        amzn) if [ "$PG_OS_VERSION" = 2 ]; then pg_have yum && PG_MANAGER=yum
              elif [ "$PG_OS_VERSION" = 2023 ]; then pg_have dnf && PG_MANAGER=dnf; fi ;;
        centos|rhel|rocky|almalinux|ol|fedora)
            if pg_have dnf; then PG_MANAGER=dnf; elif pg_have yum; then PG_MANAGER=yum; fi ;;
        alpine) pg_have apk && PG_MANAGER=apk ;;
        arch|manjaro) pg_have pacman && PG_MANAGER=pacman ;;
        opensuse*|sles|sled) pg_have zypper && PG_MANAGER=zypper ;;
        *)
            for pg_candidate in apt-get dnf yum apk zypper pacman; do
                if pg_have "$pg_candidate"; then PG_MANAGER=$pg_candidate; break; fi
            done ;;
    esac
    pg_major=${PG_OS_VERSION%%.*}
    case "$pg_major" in ''|*[!0-9]*) return 0 ;; esac
    case "$PG_OS:$PG_MANAGER" in
        ubuntu:apt) [ "$pg_major" -ge 18 ] && PG_SUPPORTED=1 ;;
        debian:apt) [ "$pg_major" -ge 10 ] && PG_SUPPORTED=1 ;;
        amzn:yum) [ "$PG_OS_VERSION" = 2 ] && PG_SUPPORTED=1 ;;
        amzn:dnf) [ "$PG_OS_VERSION" = 2023 ] && PG_SUPPORTED=1 ;;
        centos:yum|rhel:yum) [ "$pg_major" -eq 7 ] && PG_SUPPORTED=1 ;;
        centos:dnf|rhel:dnf|rocky:dnf|almalinux:dnf|ol:dnf)
            [ "$pg_major" -ge 8 ] && PG_SUPPORTED=1 ;;
        fedora:dnf) [ "$pg_major" -ge 28 ] && PG_SUPPORTED=1 ;;
    esac
    return 0
}
pg_python_ready() {
    for pg_python in /usr/bin/python3 /usr/libexec/platform-python /usr/bin/python2.7 /usr/bin/python2 /usr/bin/python; do
        if [ -x "$pg_python" ] && "$pg_python" -E -s -c 'import sys; v=sys.version_info; sys.exit(0 if v >= (3,6) or ((2,7) <= v < (3,0)) else 1)' >/dev/null 2>&1; then return 0; fi
    done
    return 1
}
pg_binding_ready() {
    case "$PG_MANAGER" in
        apt) pg_import='import apt, apt_pkg' ;;
        yum) pg_import='import rpm, yum' ;;
        dnf) pg_import='import rpm, dnf' ;;
        *) return 1 ;;
    esac
    for pg_python in /usr/libexec/platform-python /usr/bin/python3 /usr/bin/python2.7 /usr/bin/python2 /usr/bin/python; do
        if [ -x "$pg_python" ] && "$pg_python" -E -s -c "import sys; sys.path = [p for p in sys.path if p]; $pg_import" >/dev/null 2>&1; then return 0; fi
    done
    return 1
}
pg_download_tool() {
    PG_DOWNLOADER=''
    if pg_have curl; then PG_DOWNLOADER=curl; return 0; fi
    if pg_have wget; then
        # GNU Wget has explicit HTTPS-only redirect enforcement; BusyBox wget
        # is not assumed to support these options or verify peer certificates.
        pg_wget_help=$(wget --help 2>/dev/null) || pg_wget_help=''
        case "$pg_wget_help" in *'GNU Wget'*) PG_DOWNLOADER=wget; return 0 ;; esac
    fi
    return 1
}
pg_hash_tool() {
    PG_HASHER=''
    if pg_have sha256sum; then PG_HASHER=sha256sum
    elif pg_have shasum; then PG_HASHER=shasum
    elif pg_have openssl; then PG_HASHER=openssl
    else return 1
    fi
}
pg_certificates_ready() {
    [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] ||
        [ -s /etc/ssl/ca-bundle.pem ]
}
pg_add_package() {
    case " $PG_PACKAGES " in *" $1 "*) ;; *) PG_PACKAGES="${PG_PACKAGES:+$PG_PACKAGES }$1" ;; esac
}
pg_dependencies() {
    PG_PACKAGES=''
    [ -x /bin/bash ] || pg_add_package bash
    if ! pg_python_ready; then
        if [ "$PG_MANAGER" = yum ]; then pg_add_package python; else pg_add_package python3; fi
    fi
    if ! pg_binding_ready; then
        case "$PG_MANAGER" in
            apt) pg_add_package python3-apt ;;
            yum) pg_add_package yum; pg_add_package rpm-python ;;
            dnf) pg_add_package python3-dnf; pg_add_package python3-rpm ;;
        esac
    fi
    pg_download_tool || pg_add_package curl
    pg_hash_tool || pg_add_package coreutils
    pg_certificates_ready || pg_add_package ca-certificates
}
pg_as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    elif pg_have sudo; then sudo -- "$@"
    else pg_error '需要 root 权限；请以 root 执行，或安装并配置 sudo 后重试。'; return 2
    fi
}
pg_bootstrap() {
    # Package words are fixed literals selected above, never user input.
    set -- $PG_PACKAGES
    [ "$#" -gt 0 ] || return 0
    printf '仅安装缺少的启动依赖：%s\n' "$PG_PACKAGES"
    case "$PG_MANAGER" in
        apt)
            # Minimal official images commonly have empty APT indexes. Refresh
            # metadata only in the already-authorized bootstrap path. Older APT
            # may ignore Error-Mode, so also reject partial-fetch warnings.
            pg_update_log=$(LC_ALL=C pg_as_root apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Update::Error-Mode=any update 2>&1)
            pg_update_code=$?
            printf '%s\n' "$pg_update_log"
            [ "$pg_update_code" -eq 0 ] || return "$pg_update_code"
            case "$pg_update_log" in
                *'Failed to fetch'*|*'Some index files failed'*|*'E: '*)
                    pg_error 'APT 索引未完整刷新，拒绝使用残留索引安装启动依赖。'; return 2 ;;
            esac
            pg_as_root apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -y --no-remove --no-install-recommends install "$@" ;;
        dnf) pg_as_root dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --setopt=install_weak_deps=False install "$@" ;;
        yum) pg_as_root yum -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install "$@" ;;
        *) pg_error '本系统没有经过适配的启动依赖安装路径。'; return 10 ;;
    esac
}
pg_fetch() {
    case "$PG_DOWNLOADER" in
        curl) curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 2 --output "$1" "$PG_URL" ;;
        wget) wget --https-only --secure-protocol=TLSv1_2 --timeout=30 --tries=3 -O "$1" "$PG_URL" ;;
        *) return 2 ;;
    esac
}
pg_verify() {
    [ -s "$1" ] || { pg_error '下载文件为空。'; return 2; }
    case "$PG_SHA256" in ''|*[!0-9a-f]*) pg_error '启动器尚未写入正式发布文件的 SHA256，拒绝执行。'; return 2 ;; esac
    [ "${#PG_SHA256}" -eq 64 ] || { pg_error '内置 SHA256 长度错误，拒绝执行。'; return 2; }
    case "$PG_HASHER" in
        sha256sum) pg_digest=$(sha256sum "$1") || return 2; pg_digest=${pg_digest%% *} ;;
        shasum) pg_digest=$(shasum -a 256 "$1") || return 2; pg_digest=${pg_digest%% *} ;;
        openssl) pg_digest=$(openssl dgst -sha256 "$1") || return 2; pg_digest=${pg_digest##* } ;;
        *) return 2 ;;
    esac
    [ "$pg_digest" = "$PG_SHA256" ] || { pg_error 'SHA256 不匹配，文件可能截断或不属于固定发布版本；未执行。'; return 2; }
}
pg_cleanup() {
    if [ -n "$PG_TMP" ]; then rm -rf -- "$PG_TMP"; PG_TMP=''; fi
}
pg_main() {
    # Ignore caller-controlled PATH and Python import environment.
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    umask 077
    PG_YES=0; PG_MODE=fix; PG_CHECK=0; pg_value_pending=0; pg_mode_seen=0
    for pg_arg in "$@"; do
        if [ "$pg_value_pending" -eq 1 ]; then pg_value_pending=0; continue; fi
        case "$pg_arg" in
            --help|-h) pg_help; return 0 ;;
            --version) printf '%s\n' "$PG_VERSION"; return 0 ;;
            --check) PG_CHECK=1 ;;
            --yes) PG_YES=1 ;;
            audit|plan|fix)
                [ "$pg_mode_seen" -eq 0 ] || { pg_error '只能指定一个运行模式。'; return 2; }
                PG_MODE=$pg_arg; pg_mode_seen=1 ;;
            --build-user|--work-dir|--jobs|--lock-wait|--service|--health-url|--health-host|--scan-root|--pause-scheduler|--drain-wait|--build-timeout|--progress-interval) pg_value_pending=1 ;;
            --build-user=*|--work-dir=*|--jobs=*|--lock-wait=*|--service=*|--health-url=*|--health-host=*|--scan-root=*|--pause-scheduler=*|--drain-wait=*|--build-timeout=*|--progress-interval=*) ;;
            *) pg_error "未知参数：${pg_arg}；使用 --help 查看用法。"; return 2 ;;
        esac
    done
    [ "$pg_value_pending" -eq 0 ] || { pg_error '最后一个选项缺少参数值。'; return 2; }
    [ "$(uname -s)" = Linux ] || { pg_error '仅支持 Linux 目标主机；未下载或安装任何内容。'; return 10; }
    pg_detect_os
    pg_detect_manager
    printf '系统：%s %s；架构：%s；包管理器：%s\n' "$PG_OS" "$PG_OS_VERSION" "$(uname -m)" "$PG_MANAGER"
    if [ "$PG_SUPPORTED" -ne 1 ]; then
        pg_error '此系统目前仅能识别，尚无适配的自动修复后端；未下载或安装任何内容。'
        return 10
    fi
    pg_dependencies
    if [ -n "$PG_PACKAGES" ]; then printf '缺少启动依赖：%s\n' "$PG_PACKAGES"
    else printf '%s\n' '启动依赖已具备；PHP 包来源及补丁配方仍需主程序检查。'
    fi
    [ "$PG_CHECK" -eq 0 ] || return 0
    if [ -n "$PG_PACKAGES" ]; then
        if [ "$PG_YES" -ne 1 ] || [ "$PG_MODE" != fix ]; then
            pg_error '当前是只读模式，未安装依赖。使用 --yes 执行时可自动补齐以上启动依赖。'
            return 10
        fi
        pg_bootstrap || { pg_error '启动依赖安装失败；请检查已有仓库和包管理器日志，未下载或执行补丁。'; return 2; }
        pg_dependencies
        [ -z "$PG_PACKAGES" ] || { pg_error "依赖安装后仍未通过检查：$PG_PACKAGES"; return 2; }
    fi
    PG_TMP=$(mktemp -d /tmp/guard-for-php74.XXXXXXXX) || { pg_error '无法创建私有临时目录。'; return 2; }
    trap 'pg_cleanup' 0
    trap 'exit 130' 2
    trap 'exit 143' 15
    trap 'exit 129' 1
    pg_file=$PG_TMP/$PG_ASSET
    printf '正在下载固定版本 v%s 并校验内置 SHA256……\n' "$PG_VERSION"
    if ! pg_fetch "$pg_file"; then pg_error '下载失败；未执行补丁。'; pg_cleanup; return 2; fi
    if ! pg_verify "$pg_file"; then pg_cleanup; return 2; fi
    chmod 500 "$pg_file" || { pg_cleanup; return 2; }
    # --yes without an explicit mode preserves the main program's fix mode.
    # An empty invocation is made an explicit plan; all supplied values retain
    # their original argument boundaries (including whitespace).
    if [ "$PG_YES" -eq 0 ] && [ "$pg_mode_seen" -eq 0 ]; then set -- plan "$@"; fi
    pg_as_root /bin/bash "$pg_file" "$@"
    pg_result=$?
    pg_cleanup
    return "$pg_result"
}

pg_main "$@"
exit $?
