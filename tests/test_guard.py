"""Regression tests: fake inventories/commands only, never update the host.

Run with Python 3 after assembling php_guard.py:
    python3 -m unittest discover -s work/php-guard/tests -v
"""

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "php_guard.py"
SPEC = importlib.util.spec_from_file_location("php_guard_under_test", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def package(name="php8.2-cli", version="8.2.34-1", upstream="8.2.34",
            source="php8.2", arch="amd64"):
    return dict(name=name, version=version, upstream=upstream,
                source=source, arch=arch)


def inventory(packages=(), **extra):
    result = dict(os=dict(id="debian", version_id="12", pretty_name="Debian 12"),
                  package_manager="apt", packages=list(packages), runtimes=[],
                  services=[], processes=[], containers=[], warnings=[])
    result.update(extra)
    return result


def candidate(name="php8.2-cli", version="8.2.35-1", upstream="8.2.35",
              source="php8.2", arch="amd64", **extra):
    item = package(name, version, upstream, source, arch)
    item.update(trusted=True, official_origin=True, repo="security",
                source_version=version)
    item.update(extra)
    return item


VERSION_ORDER = ["8.2.34-1", "8.2.35-1", "8.2.35-2", "8.2.36-1",
                 "8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13",
                 "8.3.35-1", "8.3.36-1", "8.3.36-2"]


def fake_native_compare(a, b, manager):
    """Only compare explicitly enumerated fixture versions, never host versions."""
    if a == b:
        return 0
    left, right = VERSION_ORDER.index(a), VERSION_ORDER.index(b)
    return (left > right) - (left < right)


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        self.command_guard = mock.patch.object(
            guard, "run_cmd", side_effect=AssertionError("unexpected host command"))
        self.command_guard.start()
        self.addCleanup(self.command_guard.stop)
        self.comparator = mock.patch.object(guard, "native_compare", side_effect=fake_native_compare)
        self.comparator.start()
        self.addCleanup(self.comparator.stop)


class VersionTests(unittest.TestCase):
    def test_each_supported_branch_has_an_exact_fix_boundary(self):
        for before, fixed in [("8.2.34", "8.2.35"), ("8.3.35", "8.3.36"),
                              ("8.4.26", "8.4.27"), ("8.5.11", "8.5.12")]:
            with self.subTest(version=before):
                self.assertEqual("affected", guard.upstream_status(before))
            with self.subTest(version=fixed):
                self.assertEqual("fixed", guard.upstream_status(fixed))

    def test_future_minor_and_unparseable_versions_are_unknown(self):
        for version in ["8.6.0", "9.0.0", "", "not-a-version", None]:
            with self.subTest(version=version):
                self.assertEqual("unknown", guard.upstream_status(version))

    def test_prerelease_is_not_a_final_security_release(self):
        for version in ["8.2.35RC1", "8.3.36alpha1", "8.4.27beta2", "8.5.12-dev"]:
            with self.subTest(version=version):
                self.assertNotEqual("fixed", guard.upstream_status(version))

    def test_parse_known_and_invalid_versions(self):
        self.assertEqual((8, 2, 35), guard.version_tuple("8.2.35"))
        self.assertIsNone(guard.version_tuple("garbage"))
        self.assertIsNone(guard.version_tuple(None))


class AssessmentTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        with (SCRIPT.parent / "vendor-policy.json").open() as handle:
            self.policy = json.load(handle)
        self.ubuntu = inventory(os=dict(id="ubuntu", version_id="24.04"))
        self.backport = package(name="php8.3-cli", version="8.3.6-0ubuntu0.24.04.13",
                                upstream="8.3.6", source="php8.3")
        self.backport.update(official_origin=True, trusted=True)

    def test_old_upstream_version_with_verified_vendor_backport_is_fixed(self):
        self.ubuntu["packages"] = [self.backport]
        findings = guard.assess_inventory(self.ubuntu, self.policy)
        self.assertEqual("fixed", findings[0]["status"])
        self.assertIn("USN-8948-1", findings[0]["reason"])

    def test_package_before_vendor_fixed_revision_remains_affected(self):
        self.backport["version"] = "8.3.6-0ubuntu0.24.04.12"
        self.ubuntu["packages"] = [self.backport]
        self.assertEqual("affected", guard.assess_inventory(self.ubuntu, self.policy)[0]["status"])

    def test_custom_origin_cannot_inherit_official_vendor_rule(self):
        self.backport["official_origin"] = False
        self.backport["changelog"] = "Fixed CVE-2026-109618 and CVE-2026-109619"
        self.ubuntu["packages"] = [self.backport]
        self.assertNotEqual("fixed", guard.assess_inventory(self.ubuntu, self.policy)[0]["status"])

    def test_vendor_rule_does_not_match_another_os_release_or_source_prefix(self):
        cases = [("22.04", "php8.3"), ("24.04", "php8.3-custom")]
        for release, source in cases:
            with self.subTest(release=release, source=source):
                host = inventory(os=dict(id="ubuntu", version_id=release))
                item = dict(self.backport, source=source)
                status, _ = guard.package_status(item, host, self.policy)
                self.assertNotEqual("fixed", status)

    def test_vendor_comparison_failure_is_unknown(self):
        self.ubuntu["packages"] = [self.backport]
        with mock.patch.object(guard, "native_compare", side_effect=RuntimeError("no rpm/dpkg comparator")):
            self.assertEqual("unknown", guard.assess_inventory(self.ubuntu, self.policy)[0]["status"])

    def test_unmanaged_runtime_and_container_never_disappear_behind_fixed_packages(self):
        host = inventory([package(version="8.2.35-1", upstream="8.2.35")],
                         runtimes=[dict(path="/opt/custom/php", package=None, version="8.2.35")],
                         containers=[dict(name="web", image="php:old")])
        findings = guard.assess_inventory(host, self.policy)
        unknown = {item["kind"] for item in findings if item["status"] == "unknown"}
        self.assertIn("unmanaged_runtime", unknown)
        self.assertIn("container", unknown)

    def test_empty_inventory_and_failed_coverage_do_not_report_safe(self):
        for host in [inventory(), inventory([package(version="8.2.35-1", upstream="8.2.35")],
                                            warnings=["package inventory incomplete"] )]:
            with self.subTest(host=host):
                findings = guard.assess_inventory(host, self.policy)
                self.assertTrue(any(item["status"] == "unknown" for item in findings), findings)


class PlanTests(OfflineTestCase):
    def plan(self, packages, candidates):
        host = inventory(packages)
        findings = guard.assess_inventory(host, {})
        return guard.build_plan(host, findings, candidates, {})

    def test_complete_cli_fpm_build_can_update_together(self):
        installed = [package(), package("php8.2-fpm")]
        choices = {name: [candidate(name)] for name in ("php8.2-cli", "php8.2-fpm")}
        result = self.plan(installed, choices)
        self.assertEqual([], result["blockers"])
        self.assertEqual({"php8.2-cli", "php8.2-fpm"}, {item["name"] for item in result["updates"]})

    def test_partial_core_candidates_block_whole_source_group(self):
        result = self.plan([package(), package("php8.2-fpm")],
                           {"php8.2-cli": [candidate()]})
        self.assertEqual([], result["updates"])
        self.assertTrue(result["blockers"])
        self.assertIn("php8.2-fpm", result["blockers"][0]["packages"])

    def test_core_candidates_from_different_source_builds_are_rejected(self):
        result = self.plan([package(), package("php8.2-fpm")],
                           {"php8.2-cli": [candidate()],
                            "php8.2-fpm": [candidate("php8.2-fpm", version="8.2.35-2")]})
        self.assertEqual([], result["updates"])
        self.assertTrue(result["blockers"])

    def test_two_installed_minor_branches_keep_separate_candidates_and_blockers(self):
        installed = [package(), package("php8.3-cli", "8.3.35-1", "8.3.35", "php8.3")]
        result = self.plan(installed, {"php8.2-cli": [candidate()]})
        self.assertEqual(["php8.2-cli"], [item["name"] for item in result["updates"]])
        self.assertEqual(["8.3"], [item["branch"] for item in result["blockers"]])

    def test_candidate_must_match_branch_arch_source_and_trust(self):
        invalid = [candidate(version="8.3.36-1", upstream="8.3.36"),
                   candidate(arch="arm64"), candidate(source="php8.2-custom"),
                   candidate(trusted=False)]
        for item in invalid:
            with self.subTest(candidate=item):
                result = self.plan([package()], {"php8.2-cli": [item]})
                self.assertEqual([], result["updates"])
                self.assertTrue(result["blockers"])

    def test_no_safe_candidate_and_changelog_only_candidate_are_blocked(self):
        unsafe = candidate(version="8.2.34-1", upstream="8.2.34",
                           changelog="Fixed CVE-2026-109618 CVE-2026-109619")
        for choices in [{}, {"php8.2-cli": [unsafe]}]:
            with self.subTest(choices=choices):
                result = self.plan([package()], choices)
                self.assertEqual([], result["updates"])
                self.assertTrue(result["blockers"])

    def test_repair_of_mixed_package_versions_cannot_downgrade_a_newer_core_package(self):
        installed = [package(version="8.2.36-1", upstream="8.2.36"), package("php8.2-fpm")]
        choices = {name: [candidate(name)] for name in ("php8.2-cli", "php8.2-fpm")}
        result = self.plan(installed, choices)
        self.assertEqual([], result["updates"])
        self.assertTrue(result["blockers"])

    def test_native_comparator_failure_does_not_allow_an_update(self):
        with mock.patch.object(guard, "native_compare", side_effect=RuntimeError("comparator unavailable")):
            result = self.plan([package()], {"php8.2-cli": [candidate()]})
        self.assertEqual([], result["updates"])
        self.assertTrue(result["blockers"])


class CommandFailureTests(unittest.TestCase):
    def test_missing_program_is_a_failure_not_an_empty_success(self):
        with mock.patch.object(guard.subprocess, "Popen", side_effect=OSError("missing program")):
            result = guard.run_cmd(["/this-program-does-not-exist"])
        self.assertEqual(127, result["code"])
        self.assertIn("missing program", result["stderr"])

    def test_failed_dpkg_comparison_is_not_treated_as_equal(self):
        with mock.patch.object(guard, "run_cmd", return_value=dict(code=2, stdout="", stderr="invalid version")):
            with self.assertRaisesRegex(RuntimeError, "comparison failed"):
                guard.native_compare("8.2.35-1", "8.2.34-1", "apt")

    def test_package_backend_failure_is_raised_even_if_it_prints_success(self):
        commands = []

        def fake_command(argv, timeout=30, env=None):
            commands.append(argv)
            if "-c" in argv:
                return dict(code=0, stdout="", stderr="")
            return dict(code=5, stdout='{"ok": true}', stderr="transaction failed")

        with tempfile.TemporaryDirectory(dir=str(SCRIPT.parent)) as folder:
            worker_dir = pathlib.Path(folder) / "worker"
            worker_dir.mkdir()
            with mock.patch.object(guard.os.path, "exists", return_value=True), \
                 mock.patch.object(guard.tempfile, "mkdtemp", return_value=str(worker_dir)), \
                 mock.patch.object(guard, "run_cmd", side_effect=fake_command):
                with self.assertRaisesRegex(RuntimeError, "backend failed.*exit 5"):
                    guard.worker_call("raise RuntimeError('should never run')", {}, ["apt"])
            self.assertFalse(worker_dir.exists(), "temporary backend files must be removed")
        self.assertEqual(2, len(commands))


class BackendAndServiceTests(OfflineTestCase):
    def test_apt_failure_cannot_become_success(self):
        with mock.patch.object(guard, "worker_call", side_effect=RuntimeError("apt failed")):
            result = guard.apt_transaction([candidate()], execute=True)
        self.assertFalse(result["ok"])
        self.assertIn("apt failed", result["error"])

    def test_rpm_failure_cannot_become_success(self):
        with mock.patch.object(guard, "_rpm_worker_call", side_effect=RuntimeError("rpm failed")):
            result = guard.rpm_transaction([candidate()], execute=True)
        self.assertFalse(result["ok"])
        self.assertFalse(result["executed"])
        self.assertIn("rpm failed", result["error"])

    def test_restart_exit_code_and_active_state_are_both_required(self):
        for restart_code, active_code, active_text in [(1, 0, "active"), (0, 3, "failed"),
                                                       (0, 0, "inactive")]:
            with self.subTest(restart_code=restart_code, active_code=active_code,
                              active_text=active_text):
                def fake_command(argv, timeout=30):
                    if "restart" in argv:
                        return dict(code=restart_code, stdout="", stderr="")
                    if "is-active" in argv:
                        return dict(code=active_code, stdout=active_text, stderr="")
                    raise AssertionError("unexpected service command: " + repr(argv))

                with mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl"), \
                     mock.patch.object(guard, "_svc_show", return_value={"Id": "php8.2-fpm.service"}), \
                     mock.patch.object(guard, "run_cmd", side_effect=fake_command):
                    result = guard.restart_services(["php8.2-fpm.service"])
                self.assertFalse(result["ok"])
                self.assertTrue(result["errors"])

    def test_failed_fpm_configtest_blocks_restart_preflight(self):
        host = inventory(services=[dict(name="php8.2-fpm.service", active="active")])
        props = {"ExecStart": "{ path=/usr/sbin/php-fpm8.2 ; argv[]=/usr/sbin/php-fpm8.2 --nodaemonize --fpm-config /etc/php/8.2/fpm/php-fpm.conf ; }"}
        with mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl"), \
             mock.patch.object(guard, "_svc_show", return_value=props), \
             mock.patch.object(guard, "_inv_trusted_executable", return_value=(True, None)), \
             mock.patch.object(guard, "run_cmd", return_value=dict(code=78, stdout="", stderr="secret diagnostic")) as command:
            result = guard.service_preflight(host, [candidate()])
        self.assertTrue(result["blockers"])
        self.assertEqual([], result["services"])
        self.assertFalse(result["checks"][0]["ok"])
        self.assertNotIn("secret diagnostic", repr(result))
        self.assertIn("-t", command.call_args[0][0])

    def test_surviving_php_pid_after_restart_is_not_verified(self):
        process = dict(pid=100, comm="php-fpm8.2", exe="/usr/sbin/php-fpm8.2",
                       service="php8.2-fpm.service", version="8.2.35", deleted=False)
        result = guard.residual_process_check(inventory(processes=[process]),
                                              inventory(processes=[dict(process)]),
                                              services=["php8.2-fpm.service"])
        self.assertFalse(result["ok"])
        self.assertIn("survived", result["errors"][0]["reason"])

    def test_container_engine_cannot_be_restarted_as_a_php_service(self):
        with mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl"), \
             mock.patch.object(guard, "run_cmd") as command:
            result = guard.restart_services(["docker.service"])
        command.assert_not_called()
        self.assertFalse(result["ok"])


class RepairExecutionTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.host = inventory([package()])
        self.plan = dict(updates=[candidate()], blockers=[])
        self.preflight = dict(services=["php8.2-fpm.service"], blockers=[], checks=[])
        # These cases exercise transaction/health failures; fresh host scanning
        # has separate coverage in test_repair_revalidation.py.
        self.revalidation = mock.patch.object(
            guard, "repair_revalidate", return_value=dict(
                ok=True, inventory=self.host, preflight=self.preflight, errors=[]))
        self.revalidation.start()
        self.addCleanup(self.revalidation.stop)

    def test_unresolved_blocker_prevents_any_package_transaction(self):
        self.plan["blockers"] = [dict(reason="missing FPM candidate")]
        with mock.patch.object(guard, "package_transaction") as transaction:
            result = guard.execute_repair(self.host, self.plan, self.preflight, {}, "unused")
        transaction.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual("preflight", result["stage"])

    def test_apply_failure_stops_before_restart(self):
        with mock.patch.object(guard, "package_transaction", side_effect=[dict(ok=True), dict(ok=False, error="dpkg failed")]) as transaction, \
             mock.patch.object(guard, "backup_configuration", return_value="config.tar.gz"), \
             mock.patch.object(guard, "write_json"), \
             mock.patch.object(guard, "say"), \
             mock.patch.object(guard, "restart_services") as restart:
            result = guard.execute_repair(self.host, self.plan, self.preflight, {}, "unused")
        self.assertFalse(result["ok"])
        self.assertEqual("package_update", result["stage"])
        self.assertEqual([False, True], [call.kwargs["execute"] for call in transaction.call_args_list])
        restart.assert_not_called()

    def test_preview_failure_prevents_backup_and_apply(self):
        with mock.patch.object(guard, "package_transaction", return_value=dict(ok=False)) as transaction, \
             mock.patch.object(guard, "backup_configuration") as backup:
            result = guard.execute_repair(self.host, self.plan, self.preflight, {}, "unused")
        self.assertFalse(result["ok"])
        self.assertEqual("transaction_preview", result["stage"])
        self.assertEqual(1, transaction.call_count)
        self.assertFalse(transaction.call_args.kwargs["execute"])
        backup.assert_not_called()

    def test_failed_health_baseline_prevents_transaction(self):
        with mock.patch.object(guard, "health_checks", return_value=[dict(ok=False, status="503")]), \
             mock.patch.object(guard, "package_transaction") as transaction:
            result = guard.execute_repair(self.host, self.plan, self.preflight, {}, "unused", ["http://127.0.0.1/health"])
        self.assertFalse(result["ok"])
        self.assertEqual("health_before", result["stage"])
        transaction.assert_not_called()

    def test_requested_health_check_is_not_skipped_when_no_packages_need_updates(self):
        self.plan["updates"] = []
        with mock.patch.object(guard, "health_checks", return_value=[dict(ok=False, status="503")]) as health, \
             mock.patch.object(guard, "package_transaction") as transaction:
            result = guard.execute_repair(self.host, self.plan, self.preflight, {}, "unused", ["http://127.0.0.1/health"])
        health.assert_called_once()
        self.assertFalse(result["ok"])
        transaction.assert_not_called()


class MainFlowTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(dir=str(SCRIPT.parent))
        self.addCleanup(self.temp.cleanup)
        self.output = pathlib.Path(self.temp.name) / "report"
        self.before = inventory([package()])
        self.after = inventory([package(version="8.2.35-1", upstream="8.2.35")])
        self.candidates = {"php8.2-cli": [candidate()]}
        self.preflight = dict(services=["php8.2-fpm.service"], blockers=[], checks=[])
        patches = [mock.patch.object(guard.sys, "platform", "linux"),
                   mock.patch.object(guard.os, "geteuid", return_value=0),
                   mock.patch.object(guard.os, "umask"),
                   mock.patch.object(guard, "acquire_repair_lock", return_value=None, create=True),
                   mock.patch.object(guard, "POLICY", {"checked_on": "2026-10-22", "entries": []}, create=True),
                   mock.patch.object(guard, "say"),
                   mock.patch.object(guard, "show_summary"),
                   mock.patch.object(guard, "fetch_candidates", return_value=self.candidates),
                   mock.patch.object(guard, "check_package_integrity", return_value=[]),
                   mock.patch.object(guard, "service_preflight", return_value=self.preflight)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_main(self, args):
        code = guard.main(args + ["--output-dir", str(self.output)])
        with (self.output / "report.json").open() as handle:
            report = json.load(handle)
        return code, report

    def test_audit_with_container_returns_unresolved(self):
        self.after["containers"] = [dict(name="web", image="php:old")]
        with mock.patch.object(guard, "collect_inventory", return_value=self.after):
            code, report = self.run_main(["audit"])
        self.assertEqual(10, code)
        self.assertEqual("unresolved", report["result"])

    def test_fix_without_yes_only_previews(self):
        with mock.patch.object(guard, "collect_inventory", return_value=self.before), \
             mock.patch.object(guard, "package_transaction", return_value=dict(ok=True)) as transaction, \
             mock.patch.object(guard, "execute_repair") as repair:
            code, report = self.run_main(["fix"])
        self.assertEqual(0, code)
        self.assertEqual("plan_ready", report["result"])
        repair.assert_not_called()
        self.assertFalse(transaction.call_args.kwargs["execute"])

    def test_failed_repair_returns_nonzero_and_never_claims_fixed(self):
        with mock.patch.object(guard, "collect_inventory", return_value=self.before) as collect, \
             mock.patch.object(guard, "execute_repair", return_value=dict(ok=False, stage="package_update")):
            code, report = self.run_main(["fix", "--yes"])
        self.assertEqual(20, code)
        self.assertEqual("repair_failed", report["result"])
        self.assertEqual(1, collect.call_count)

    def test_lock_failure_stops_before_inventory_or_package_transaction(self):
        with mock.patch.object(guard, "acquire_repair_lock", side_effect=OSError("lock already held")), \
             mock.patch.object(guard, "collect_inventory") as collect, \
             mock.patch.object(guard, "package_transaction") as transaction, \
             mock.patch.object(guard, "execute_repair") as repair:
            code = guard.main(["fix", "--yes", "--output-dir", str(self.output)])
        self.assertEqual(20, code)
        collect.assert_not_called()
        transaction.assert_not_called()
        repair.assert_not_called()

    def test_remaining_affected_package_after_update_returns_unresolved(self):
        with mock.patch.object(guard, "collect_inventory", side_effect=[self.before, self.before]), \
             mock.patch.object(guard, "execute_repair", return_value=dict(ok=True, stage="verification")):
            code, report = self.run_main(["fix", "--yes"])
        self.assertEqual(10, code)
        self.assertNotEqual("fixed_within_scope", report["result"])

    def test_surviving_worker_pid_prevents_successful_final_verdict(self):
        process = dict(pid=100, comm="php-fpm8.2", exe="/usr/sbin/php-fpm8.2",
                       service="php8.2-fpm.service", version="8.2.34", deleted=False)
        self.before["processes"] = [process]
        self.after["processes"] = [dict(process, version="8.2.35")]
        with mock.patch.object(guard, "collect_inventory", side_effect=[self.before, self.after]), \
             mock.patch.object(guard, "execute_repair", return_value=dict(ok=True, stage="verification")):
            code, report = self.run_main(["fix", "--yes"])
        self.assertNotEqual(0, code)
        self.assertNotEqual("fixed_within_scope", report["result"])


class InventoryTests(unittest.TestCase):
    def test_package_query_failure_is_explicitly_incomplete(self):
        warnings = []
        with mock.patch.object(guard, "_inv_tool", side_effect=lambda name, unused: "/usr/bin/dpkg-query" if name == "dpkg-query" else None), \
             mock.patch.object(guard, "run_cmd", return_value=dict(code=2, stdout="", stderr="database unavailable")):
            manager, packages, _, _ = guard._inv_packages(warnings)
        self.assertEqual("apt", manager)
        self.assertEqual([], packages)
        self.assertTrue(any("incomplete" in warning for warning in warnings), warnings)

    def test_held_installed_package_is_included_but_removed_package_is_not(self):
        output = ("php8.2-cli\t8.2.34-1\tphp8.2\tamd64\thi \n"
                  "php8.2-fpm\t8.2.34-1\tphp8.2\tamd64\trc \n")
        with mock.patch.object(guard, "_inv_tool", side_effect=lambda name, unused: "/usr/bin/dpkg-query" if name == "dpkg-query" else None), \
             mock.patch.object(guard, "run_cmd", return_value=dict(code=0, stdout=output, stderr="")):
            _, packages, _, _ = guard._inv_packages([])
        self.assertEqual(["php8.2-cli"], [item["name"] for item in packages])

    def test_runtime_probe_disables_ini_and_does_not_copy_environment(self):
        path = "/usr/bin/php8.2"
        seen = []

        def fake_command(argv, timeout=30):
            seen.append(argv)
            if argv[-1] == "-v":
                return dict(code=0, stdout="PHP 8.2.34 (cli)\n", stderr="")
            return dict(code=0, stdout="Server API => Command Line Interface\n"
                        "Loaded Configuration File => (none)\n"
                        "AWS_SECRET_ACCESS_KEY => do-not-report-this-secret\n"
                        "HTTP_AUTHORIZATION => Bearer do-not-report-this-token\n", stderr="")

        with mock.patch.object(guard, "_inv_candidates", return_value=[path]), \
             mock.patch.object(guard, "_inv_owner", return_value="php8.2-cli"), \
             mock.patch.object(guard, "_inv_trusted_executable", return_value=(True, None)), \
             mock.patch.object(guard, "run_cmd", side_effect=fake_command):
            runtimes = guard._inv_runtimes([], [], None, None)
        self.assertEqual([[path, "-n", "-v"], [path, "-n", "-i"]], seen)
        self.assertEqual("8.2.34", runtimes[0]["version"])
        self.assertNotIn("do-not-report", repr(runtimes))
        self.assertIsNone(runtimes[0]["config_file"])

    def test_untrusted_php_executable_is_never_invoked(self):
        warnings = []
        with mock.patch.object(guard, "_inv_candidates", return_value=["/opt/custom/php"]), \
             mock.patch.object(guard, "_inv_owner", return_value=None), \
             mock.patch.object(guard, "_inv_trusted_executable", return_value=(False, "non-root owner")), \
             mock.patch.object(guard, "run_cmd") as command:
            runtimes = guard._inv_runtimes([], warnings, None, None)
        command.assert_not_called()
        self.assertIsNone(runtimes[0]["version"])
        self.assertTrue(any("Skipped PHP execution" in warning for warning in warnings))

    def test_replaced_executable_does_not_inherit_on_disk_fixed_version(self):
        runtime = dict(realpath="/usr/sbin/php-fpm8.2", version="8.2.35")
        warnings = []

        def read_proc(path, limit=65536):
            if path.endswith("/comm"):
                return "php-fpm8.2\n"
            return "0::/system.slice/php8.2-fpm.service\n"

        with mock.patch.object(guard.os, "listdir", return_value=["312", "self"]), \
             mock.patch.object(guard.os, "readlink", return_value="/usr/sbin/php-fpm8.2 (deleted)"), \
             mock.patch.object(guard, "_inv_read", side_effect=read_proc), \
             mock.patch.object(guard, "_inv_proc_stat", return_value=dict(pid=312, ppid=0, start_ticks=1, comm="php-fpm8.2", tty_nr=0)), \
             mock.patch.object(guard.os, "stat") as stat:
            processes = guard._inv_processes([runtime], warnings)
        stat.assert_not_called()
        self.assertTrue(processes[0]["deleted"])
        self.assertIsNone(processes[0]["version"])
        self.assertTrue(any("loaded version is unknown" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
