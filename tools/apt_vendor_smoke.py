#!/usr/bin/env python3
"""Read real APT metadata in a disposable CI container; never run a repair.

The caller installs php7.4-cli and the vendor key in a fresh container. This
checks authenticated metadata, native dpkg comparison, and policy selection.
It does not test upgrades, PHP-FPM/Apache restarts, source builds, or applications.
"""
import argparse
import copy
import json
import os
from pathlib import Path


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--os', required=True, choices=['ubuntu', 'debian'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--codename', required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    check(os.environ.get('PHPGUARD_DISPOSABLE_CONTAINER') == '1' and
          (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()),
          'This smoke check is restricted to explicitly marked disposable containers')
    root = Path(__file__).resolve().parents[1]
    namespace = {'__name__': 'apt_vendor_smoke'}
    for module in ('common', 'inventory', 'apt_backend'):
        exec(compile((root / 'src' / (module + '.py')).read_text(), module, 'exec'), namespace)
    policy = json.loads((root / 'vendor-policy.json').read_text())
    host = namespace['_inv_os']()
    check(host.get('id') == args.os and host.get('version_id') == args.version,
          'Container OS does not match the workflow matrix')
    check(host.get('version_codename') == args.codename, 'Container codename mismatch')
    worker = {'__name__': 'apt_vendor_smoke_worker'}
    prefix = namespace['APT_WORKER'].split('\ntry:\n    with open(sys.argv[1])', 1)[0]
    exec(compile(prefix, 'APT_WORKER', 'exec'), worker)
    result = worker['work']({'action': 'candidates', 'names': ['php7.4-cli'], 'codename': args.codename})
    check(result.get('ok'), 'Native APT candidate query failed')
    cache = worker['apt'].Cache()
    installed = cache['php7.4-cli'].installed
    check(installed is not None, 'The container must have vendor php7.4-cli installed')
    package = worker['record'](installed, args.codename)
    package['name'] = 'php7.4-cli'
    inv = dict(os=host, package_manager='apt', packages=[package])
    check(package['official_origin'] is False, 'Third-party origin was mislabeled as Ubuntu official')
    check(any(row['trusted'] and row['origin'] == args.origin and row['site'] == args.site and
              row['archive'] == args.codename and row['codename'] == args.codename
              for row in package['origins']), 'APT did not provide the exact authenticated vendor Release identity')
    status, reason = namespace['package_status'](package, inv, policy)
    check(status == 'fixed', 'Vendor backport was not recognized: ' + reason)
    rules = [r for r in policy['entries'] if r.get('os_id') == args.os and r.get('os_version') == args.version and
             namespace['apt_vendor_rule_matches'](package, inv, r)]
    check(len(rules) == 1, 'Expected exactly one matching vendor rule')
    rule = rules[0]
    older = rule['min_version'].replace('7.4.33-31+', '7.4.33-30+', 1)
    check(older != rule['min_version'], 'Reviewed revision boundary changed')
    previous = dict(package, version=older, source_version=older)
    check(namespace['package_status'](previous, inv, policy)[0] != 'fixed',
          'A previous vendor revision was incorrectly accepted')
    check(namespace['vendor_candidate_same_lineage'](previous, package, inv, policy),
          'Same-vendor update was rejected')
    foreign = dict(previous, version='7.4.33-1+local1', source_version='7.4.33-1+local1')
    check(not namespace['vendor_candidate_same_lineage'](foreign, package, inv, policy),
          'Automatic vendor migration was accepted')
    negative_checks = []
    for field, value in [('trusted', False), ('site', 'wrong.example'), ('codename', 'wrong-suite')]:
        changed = copy.deepcopy(package)
        for row in changed['origins']:
            row[field] = value
        check(namespace['package_status'](changed, inv, policy)[0] != 'fixed',
              'Altered Release identity was accepted: ' + field)
        negative_checks.append(field)
    report = dict(state='native_apt_metadata_smoke_passed', os=host, package=package,
                  reason=reason, negative_checks=negative_checks,
                  native_dpkg_version_comparison=True, install_or_upgrade_tested=False,
                  service_restart_tested=False, source_build_tested=False,
                  business_tested=False, scope='Metadata/policy validation only; php7.4-cli was installed by the disposable-container fixture')
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print('%s %s / %s: %s' % (args.os, args.version, args.origin, report['state']))


if __name__ == '__main__':
    main()
