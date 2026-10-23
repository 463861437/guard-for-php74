#!/bin/sh
# Disposable official-image startup tests; never build/install PHP or run fix.
set -eu
if [ "${1:-}" = --help ]; then
    printf '%s\n' 'Usage: tools/container_smoke.sh IMAGE supported|unsupported' 
    printf '%s\n' 'Installs launcher prerequisites only inside a disposable Linux amd64 container.'
    exit 0
fi
[ "$#" -eq 2 ] || { printf '%s\n' 'Expected IMAGE and supported|unsupported.' >&2; exit 2; }
image=$1
expected=$2
case "$expected" in supported|unsupported) ;; *) exit 2 ;; esac
case "$image" in
    ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:11|debian:12|debian:13|amazonlinux:2|amazonlinux:2023|rockylinux:8|rockylinux:9|rockylinux/rockylinux:10|alpine:3.22) ;;
    *) printf 'Image is not in the explicit smoke-test matrix: %s\n' "$image" >&2; exit 2 ;;
esac
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
printf 'Container smoke: %s (%s); bootstrap/native bindings only, no PHP build or repair.\n' "$image" "$expected"
docker run --rm --interactive --pull always --platform linux/amd64 \
    --mount "type=bind,source=$repo,target=/workspace,readonly" \
    --env "GUARD_SMOKE_EXPECTED=$expected" \
    "$image" /bin/sh -s <<'CONTAINER'
set -eu
cd /workspace
# This is the production POSIX entry point before installing any prerequisite.
set +e
/bin/sh ./install.sh --check
initial_code=$?
set -e
if [ "$GUARD_SMOKE_EXPECTED" = unsupported ]; then
    [ "$initial_code" -eq 10 ] || { printf 'Unsupported image unexpectedly returned %s\n' "$initial_code"; exit 1; }
    printf '%s\n' 'PASS: unsupported platform identified without bootstrap, download, or PHP changes.'
    exit 0
fi
[ "$initial_code" -eq 0 ] || { printf 'Supported startup check failed: %s\n' "$initial_code"; exit 1; }

# Load only the checked-in launcher's functions in this disposable container.
# There is no production environment override or call to its download/fix path.
sed '/^pg_main "\$@"$/,$d' ./install.sh > /tmp/guard-installer-library.sh
. /tmp/guard-installer-library.sh
pg_detect_os
pg_detect_manager
[ "$PG_SUPPORTED" -eq 1 ]
if [ "$PG_OS" = debian ] && [ "$PG_OS_VERSION" = 11 ]; then
    # A fixture prerequisite, not behavior of the production installer:
    # Debian 11's final security packages moved off the default image mirror.
    # Keep archive signatures and validity checks enabled; never weaken APT.
    printf '%s\n' 'CI fixture: Debian 11 security URI points to the official archive; production install.sh never rewrites sources.'
    for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        if [ -f "$source_file" ]; then
            sed -i 's@deb.debian.org/debian-security@archive.debian.org/debian-security@g; s@security.debian.org/debian-security@archive.debian.org/debian-security@g' "$source_file"
        fi
    done
fi
pg_dependencies
if [ -n "$PG_PACKAGES" ]; then pg_bootstrap; fi
pg_dependencies
[ -z "$PG_PACKAGES" ] || { printf 'Missing after bootstrap: %s\n' "$PG_PACKAGES"; exit 1; }
/bin/sh ./install.sh --check
/bin/bash ./php74-patch.sh --version

smoke_python=''
for candidate in /usr/bin/python3 /usr/libexec/platform-python /usr/bin/python2.7 /usr/bin/python2 /usr/bin/python; do
    if [ -x "$candidate" ] && "$candidate" -E -s -c 'import sys; v=sys.version_info; sys.exit(0 if v >= (3,6) or ((2,7) <= v < (3,0)) else 1)' 2>/dev/null; then
        smoke_python=$candidate
        break
    fi
done
[ -n "$smoke_python" ] || { printf '%s\n' 'No supported system Python after bootstrap.'; exit 1; }
"$smoke_python" -E -s - <<'PYTHON'
from __future__ import print_function
import json
import sys
namespace = {'__name__': 'platform_smoke', '__file__': '/workspace/php_guard.py'}
with open('/workspace/php_guard.py', 'rb') as source:
    exec(compile(source.read(), '/workspace/php_guard.py', 'exec'), namespace)
assert namespace['branch_of']('1:7.4.33-1') == '7.4'
assert namespace['upstream_status']('7.4.34') != 'fixed'
inv = namespace['collect_inventory']([])
manager = inv.get('package_manager')
assert manager in ('apt', 'yum', 'dnf'), inv
assert namespace['native_compare']('7.4.33-1', '7.4.33-2', manager) == -1
if manager in ('yum', 'dnf'):
    backend = namespace['_rpm_system_backend'](manager)
    assert backend[1] in ('yum', 'dnf'), backend
else:
    result = namespace['worker_call']('''import json, sys, apt, apt_pkg
with open(sys.argv[2], 'w') as output:
    json.dump({'native_apt_loaded': True, 'version': apt_pkg.VERSION}, output)
''', {}, ['apt', 'apt_pkg'])
    assert result['native_apt_loaded'], result
assert not [p for p in inv.get('packages', []) if namespace['is_core_package'](p)], 'Base image unexpectedly contains PHP'
print(json.dumps({'result': 'startup_and_native_bindings_passed',
                  'python': sys.version.split()[0], 'os': inv.get('os'),
                  'package_manager': manager, 'tool_version': namespace['VERSION'],
                  'php_build_tested': False, 'php_install_tested': False,
                  'business_tested': False}, sort_keys=True))
PYTHON
# Real short-lived Python children exercise progress, stdin EOF and timeout
# cleanup on each image's actual system Python; no PHP compilation or changes.
"$smoke_python" -E -s /workspace/tools/build_monitor_smoke.py
# Read-only audit of the empty-PHP image must clearly report no managed PHP 7.4.
set +e
/bin/bash ./php74-patch.sh audit
check_code=$?
set -e
[ "$check_code" -eq 10 ] || { printf 'Expected no-PHP audit exit 10, received %s\n' "$check_code"; exit 1; }
printf '%s\n' 'PASS: prerequisites, system Python, native package bindings, build-monitor child-process checks and empty-PHP audit; no native PHP build/install or business validation.'
CONTAINER
