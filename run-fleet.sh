#!/usr/bin/env bash
# Sequential SSH runner. Uses existing SSH config/agent; contains no credentials.
set -u
umask 077
usage() {
    echo '用法: bash run-fleet.sh hosts.txt [audit|plan|fix] [--yes]'
    echo 'hosts.txt 每行一个 SSH 主机别名或 user@host；fix --yes 会更新并重启服务。'
}
if [ "${1:-}" = '--help' ] || [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then usage; exit 2; fi
guard_hosts=$1
guard_mode=${2:-audit}
guard_confirm=${3:-}
case "$guard_mode" in audit|plan|fix) ;; *) usage; exit 2 ;; esac
if [ -n "$guard_confirm" ] && [ "$guard_confirm" != '--yes' ]; then usage; exit 2; fi
if [ "$guard_mode" = 'fix' ] && [ "$guard_confirm" != '--yes' ]; then
    echo '批量修复必须显式传入 fix --yes；建议先 audit / plan。' >&2
    exit 2
fi
guard_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 2
guard_script="$guard_dir/php-cve-guard.sh"
if [ ! -r "$guard_hosts" ] || [ ! -r "$guard_script" ]; then
    echo '主机清单或 php-cve-guard.sh 不可读。' >&2
    exit 2
fi
guard_logdir="./php-guard-fleet-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -m 700 "$guard_logdir" || exit 2
printf 'host\texit_code\tlog\n' > "$guard_logdir/status.tsv"
guard_failed=0
guard_count=0
while IFS= read -r guard_host || [ -n "$guard_host" ]; do
    guard_host=${guard_host%$'\r'}
    case "$guard_host" in ''|\#*) continue ;; esac
    if [[ ! "$guard_host" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$ ]]; then
        echo '主机清单含不支持的格式；每行只能有 SSH 别名或 user@host。' >&2
        guard_failed=1
        continue
    fi
    guard_count=$((guard_count+1))
    guard_log="$guard_logdir/$guard_count.log"
    printf '[%s] %s\n' "$guard_mode" "$guard_host"
    # mode and confirmation are validated above; the destination is one argv.
    ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 \
        -o ServerAliveInterval=30 -o ServerAliveCountMax=3 "$guard_host" \
        "sudo -n bash -s -- $guard_mode $guard_confirm" < "$guard_script" > "$guard_log" 2>&1
    guard_status=$?
    printf '%s\t%s\t%s\n' "$guard_host" "$guard_status" "$guard_log" >> "$guard_logdir/status.tsv"
    printf '退出码 %s；日志 %s\n' "$guard_status" "$guard_log"
    if [ "$guard_status" -ne 0 ]; then guard_failed=1; fi
done < "$guard_hosts"
if [ "$guard_count" -eq 0 ]; then echo '没有可用主机。' >&2; exit 2; fi
printf '汇总：%s/status.tsv\n' "$guard_logdir"
if [ "$guard_failed" -ne 0 ]; then exit 10; fi
exit 0
