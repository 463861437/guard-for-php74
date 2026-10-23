"""Offline regressions for actionable blocker output and saved-report explanation."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "php_guard.py"
SPEC = importlib.util.spec_from_file_location("php_guard_diagnostics_under_test", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def al2_inventory():
    return {
        "os": {"id": "amzn", "version_id": "2", "pretty_name": "Amazon Linux 2"},
        "package_manager": "yum",
        "packages": [{"name": "php-cli", "source": "php", "version": "7.4.33-1.amzn2",
                      "upstream": "7.4.33", "arch": "x86_64"}],
        "runtimes": [], "services": [], "processes": [], "containers": [], "warnings": [],
    }


def blocked_report():
    return {
        "inventory_before": al2_inventory(),
        "plan": {"updates": [], "blockers": [
            {"source": "php", "branch": "7.4", "packages": ["php-cli", "php-fpm"],
             "reason": "no complete trusted fixed build in same branch"}]},
        "service_preflight": {"services": [], "checks": [], "blockers": [
            {"service": "php-fpm.service", "reason": "PHP-FPM configuration test failed (exit 78); inspect service logs locally"},
            {"service": "queue-worker.service", "reason": "new backend diagnostic: worker mapping unavailable"}]},
        "result": "blocked_no_update",
    }


class BlockerOutputTests(unittest.TestCase):
    def output(self, inv, plan, preflight):
        with mock.patch.object(guard, "say") as say:
            guard.print_blockers(inv, plan, preflight)
        return "\n".join(str(call.args[0]) for call in say.call_args_list)

    def test_all_package_and_service_blockers_are_visible(self):
        report = blocked_report()
        report["plan"]["blockers"].append({"source": "php82-php", "branch": "8.2",
                                              "packages": ["php82-php-cli"],
                                              "reason": "second source group has no candidate"})
        output = self.output(report["inventory_before"], report["plan"], report["service_preflight"])
        for detail in ("php-cli", "php-fpm", "7.4", "php82-php-cli", "8.2",
                       "php-fpm.service", "78", "queue-worker.service",
                       "new backend diagnostic: worker mapping unavailable",
                       "second source group has no candidate"):
            with self.subTest(detail=detail):
                self.assertIn(detail, output)

    def test_al2_php74_advice_preserves_branch_and_does_not_claim_a_fix(self):
        report = blocked_report()
        output = self.output(report["inventory_before"], report["plan"], report["service_preflight"])
        self.assertIn("7.4", output)
        self.assertIn("源码", output)
        self.assertIn("回补", output)
        self.assertIn("RPM", output)
        self.assertRegex(output, "保持|保留|不跨")
        self.assertNotIn("已修复", output)
        self.assertNotIn("修复成功", output)

    def test_missing_optional_fields_and_unknown_reason_still_show_diagnostics(self):
        output = self.output({}, {"blockers": [{}, {"reason": "unrecognized future reason"}]},
                             {"blockers": [{"service": "custom.service"}]})
        self.assertIn("unrecognized future reason", output)
        self.assertIn("custom.service", output)

    def test_missing_service_advice_identifies_absence_and_offers_read_only_check(self):
        output = self.output({}, {}, {"blockers": [{
            "service": "custom-worker.service",
            "reason": "Systemd service does not exist (LoadState=not-found)",
        }]})
        self.assertIn("不存在", output)
        self.assertIn("systemctl show", output)
        self.assertIn("custom-worker.service", output)
        self.assertNotIn("systemctl start", output)

    def test_incomplete_service_properties_are_not_treated_as_a_missing_service(self):
        output = self.output({}, {}, {"blockers": [{
            "service": "custom-worker.service",
            "reason": "Systemd property enumeration is incomplete; cannot verify service configuration",
        }]})
        self.assertIn("尚无法核实", output)
        self.assertIn("systemctl show", output)
        self.assertNotIn("该服务在当前机器上不存在", output)
        self.assertNotIn("删除多余参数", output)

    def test_invalid_report_service_name_is_not_used_in_a_pasteable_command(self):
        output = self.output({}, {}, {"blockers": [{
            "service": "worker.service; echo unexpected",
            "reason": "Systemd service does not exist (LoadState=not-found)",
        }]})
        self.assertNotIn("只读查看：systemctl show", output)


class CandidateDiagnosticTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(guard, "run_cmd", side_effect=AssertionError("unexpected host command"))
        patch.start()
        self.addCleanup(patch.stop)

    def test_al2_same_version_candidates_explain_missing_verified_backport(self):
        inv = al2_inventory()
        candidate = dict(inv["packages"][0], trusted=True, official_origin=True)
        result = guard.build_plan(inv, [], {"php-cli": [candidate]}, {})
        self.assertEqual([], result["updates"])
        detail = result["blockers"][0]["candidate_diagnostics"][0]
        self.assertEqual("php-cli", detail["package"])
        self.assertEqual(candidate["version"], detail["installed"])
        self.assertEqual(1, detail["total"])
        self.assertEqual(1, detail["same_branch"])
        self.assertEqual(1, detail["trusted_source_arch"])
        self.assertEqual(0, detail["verified_fixed"])
        self.assertEqual(0, detail["accepted"])

    def test_partial_build_reports_every_package_without_permitting_partial_update(self):
        inv = al2_inventory()
        installed = {"name": "php-cli", "source": "php", "version": "8.2.34-1",
                     "upstream": "8.2.34", "arch": "x86_64"}
        inv["packages"] = [installed, dict(installed, name="php-fpm")]
        candidate = dict(installed, version="8.2.35-1", upstream="8.2.35", trusted=True)
        with mock.patch.object(guard, "native_compare", return_value=1):
            result = guard.build_plan(inv, [], {"php-cli": [candidate]}, {})
        self.assertEqual([], result["updates"])
        details = {item["package"]: item for item in result["blockers"][0]["candidate_diagnostics"]}
        self.assertEqual({"php-cli", "php-fpm"}, set(details))
        self.assertEqual(1, details["php-cli"]["accepted"])
        self.assertEqual(0, details["php-fpm"]["total"])
        self.assertEqual(0, details["php-fpm"]["accepted"])

    def test_version_examples_prioritize_installed_branch_and_disclose_truncation(self):
        inv = al2_inventory()
        installed = inv["packages"][0]
        candidates = [dict(installed, version="%s-%d.amzn2" % (version, release),
                           upstream=version, trusted=True, official_origin=True)
                      for version, count in (("5.4.16", 12), ("7.4.33", 18))
                      for release in range(1, count + 1)]
        result = guard.build_plan(inv, [], {"php-cli": candidates}, {})
        detail = result["blockers"][0]["candidate_diagnostics"][0]
        self.assertEqual([], result["updates"])
        self.assertEqual((30, 18, 0), (detail["total"], detail["same_branch"], detail["accepted"]))
        self.assertEqual(12, len(detail["available_versions"]))
        self.assertTrue(all(version.startswith("7.4.33-") for version in detail["available_versions"]))
        self.assertEqual(18, detail["available_versions_omitted"])
        with mock.patch.object(guard, "say") as say:
            guard.print_blockers(inv, result, {})
        output = "\n".join(str(call.args[0]) for call in say.call_args_list)
        self.assertIn("候选版本样例", output)
        self.assertIn("已截断", output)
        self.assertIn("18 个不同版本未显示", output)
        self.assertNotIn("5.4.16-", output)

    def test_version_comparison_failure_is_visible_and_still_blocks(self):
        inv = al2_inventory()
        installed = dict(inv["packages"][0], version="8.2.34-1", upstream="8.2.34")
        inv["packages"] = [installed]
        candidate = dict(installed, version="8.2.35-1", upstream="8.2.35", trusted=True)
        with mock.patch.object(guard, "native_compare", side_effect=RuntimeError("comparison unavailable")):
            result = guard.build_plan(inv, [], {"php-cli": [candidate]}, {})
        self.assertEqual([], result["updates"])
        detail = result["blockers"][0]["candidate_diagnostics"][0]
        self.assertEqual(1, detail["verified_fixed"])
        self.assertEqual(1, detail["comparison_errors"])
        self.assertEqual(0, detail["accepted"])


class LegacySystemdTests(unittest.TestCase):
    def properties(self, **overrides):
        values = {"Id": "php-fpm.service", "LoadState": "loaded", "ActiveState": "active",
                  "ExecStart": "{ path=/usr/sbin/php-fpm ; argv[]=/usr/sbin/php-fpm --nodaemonize ; }",
                  "Environment": "", "EnvironmentFiles": "", "RootDirectory": "",
                  "WorkingDirectory": "", "User": "", "Group": ""}
        values.update(overrides)
        return values

    def response(self, properties, code=0):
        return {"code": code, "stdout": "\n".join(key + "=" + value for key, value in properties.items()),
                "stderr": "Unknown property 'RootImage'" if code else ""}

    def test_systemd219_without_rootimage_uses_complete_supported_properties(self):
        properties = self.properties(Description="unneeded service metadata")
        with mock.patch.object(guard, "run_cmd", side_effect=[self.response({}, 1), self.response(properties)]) as command:
            result = guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertEqual(2, command.call_count)
        self.assertEqual(["/usr/bin/systemctl", "show", "php-fpm.service", "--no-pager", "--all"],
                         command.call_args_list[1].args[0])
        self.assertEqual("php-fpm.service", result["Id"])
        self.assertEqual("active", result["ActiveState"])
        self.assertNotIn("RootImage", result)
        self.assertNotIn("Description", result)
        self.assertEqual(properties["ExecStart"], result["ExecStart"])

    def test_fallback_does_not_drop_root_or_environment_guards(self):
        for key, value, error in (("RootDirectory", "/srv/private-root", "separate root"),
                                  ("Environment", "SECRET_TOKEN=not-for-logs", "environment"),
                                  ("EnvironmentFiles", "/etc/private-php.env", "environment")):
            with self.subTest(property=key):
                properties = self.properties(**{key: value})
                with mock.patch.object(guard, "run_cmd", side_effect=[self.response({}, 1), self.response(properties)]) as command:
                    result = guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
                    self.assertEqual(value, result[key])
                    with self.assertRaisesRegex(ValueError, error) as raised:
                        guard._svc_fpm_test_argv(result)
                self.assertNotIn(value, str(raised.exception))
                self.assertEqual(2, command.call_count, "unsafe FPM command must not be run")

    def test_fallback_missing_any_required_property_fails_closed(self):
        for key in self.properties():
            with self.subTest(missing=key):
                properties = self.properties()
                del properties[key]
                responses = [self.response({}, 1), self.response(properties)]
                if key == "EnvironmentFiles":
                    responses.append(self.response({}, 1))
                with mock.patch.object(guard, "run_cmd", side_effect=responses):
                    with self.assertRaisesRegex(ValueError, "incomplete"):
                        guard._svc_show("/usr/bin/systemctl", "php-fpm.service")

    def test_omitted_environmentfiles_requires_successful_empty_dedicated_query(self):
        properties = self.properties()
        del properties["EnvironmentFiles"]
        responses = [self.response({}, 1), self.response(properties), self.response({})]
        with mock.patch.object(guard, "run_cmd", side_effect=responses) as command:
            result = guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertEqual("", result["EnvironmentFiles"])
        self.assertEqual(3, command.call_count)
        self.assertEqual(["/usr/bin/systemctl", "show", "php-fpm.service", "--no-pager", "--all",
                          "--property=EnvironmentFiles"], command.call_args_list[2].args[0])

    def test_environmentfiles_query_error_or_nonempty_result_never_bypasses_guard(self):
        properties = self.properties()
        del properties["EnvironmentFiles"]
        for code, stdout in ((1, ""), (1, "EnvironmentFiles="),
                             (0, "EnvironmentFiles=/etc/private-php.env")):
            with self.subTest(code=code, stdout=stdout):
                responses = [self.response({}, 1), self.response(properties),
                             {"code": code, "stdout": stdout, "stderr": ""}]
                with mock.patch.object(guard, "run_cmd", side_effect=responses) as command:
                    with self.assertRaisesRegex(ValueError, "incomplete"):
                        guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
                self.assertEqual(3, command.call_count)

    def test_two_failed_property_queries_do_not_validate_service(self):
        with mock.patch.object(guard, "run_cmd", side_effect=[self.response({}, 1), self.response(self.properties(), 1)]) as command:
            with self.assertRaisesRegex(ValueError, "Cannot read systemd service properties"):
                guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertEqual(2, command.call_count)

    def test_successful_property_query_does_not_trigger_fallback(self):
        with mock.patch.object(guard, "run_cmd", return_value=self.response(self.properties(RootImage=""))) as command:
            result = guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertEqual("", result["RootImage"])
        self.assertEqual(1, command.call_count)

    def test_sparse_missing_unit_reports_absence_on_legacy_and_current_systemd(self):
        properties = {"Id": "custom-worker.service", "LoadState": "not-found",
                      "ActiveState": "inactive"}
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                responses = ([self.response({}, 1)] if legacy else []) + [self.response(properties)]
                with mock.patch.object(guard, "run_cmd", side_effect=responses) as command:
                    with self.assertRaisesRegex(ValueError,
                                                r"Systemd service does not exist \(LoadState=not-found\)"):
                        guard._svc_show("/usr/bin/systemctl", "custom-worker.service")
                self.assertEqual(2 if legacy else 1, command.call_count,
                                 "a missing unit needs no service configuration probes")

    def test_sparse_legacy_unit_reports_explicit_load_or_activity_failure(self):
        for load_state, active_state, error in (
                ("masked", "inactive", r"not a loaded systemd unit \(LoadState=masked\)"),
                ("error", "inactive", r"not a loaded systemd unit \(LoadState=error\)"),
                ("loaded", "inactive", r"not active \(ActiveState=inactive\)"),
                ("loaded", "failed", r"not active \(ActiveState=failed\)")):
            with self.subTest(load_state=load_state, active_state=active_state):
                properties = {"Id": "custom-worker.service", "LoadState": load_state,
                              "ActiveState": active_state}
                with mock.patch.object(guard, "run_cmd", side_effect=[
                        self.response({}, 1), self.response(properties)]) as command:
                    with self.assertRaisesRegex(ValueError, error):
                        guard._svc_show("/usr/bin/systemctl", "custom-worker.service")
                self.assertEqual(2, command.call_count)

    def test_missing_load_state_does_not_infer_inactivity_from_partial_output(self):
        properties = self.properties(ActiveState="inactive")
        del properties["LoadState"]
        with mock.patch.object(guard, "run_cmd", side_effect=[
                self.response({}, 1), self.response(properties)]):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                guard._svc_show("/usr/bin/systemctl", "php-fpm.service")

    def test_unknown_state_values_are_not_echoed_in_diagnostics(self):
        for key in ("LoadState", "ActiveState"):
            with self.subTest(property=key):
                properties = self.properties(**{key: "UNEXPECTED_PRIVATE_VALUE"})
                with mock.patch.object(guard, "run_cmd", return_value=self.response(properties)):
                    with self.assertRaisesRegex(ValueError, key + "=unknown") as raised:
                        guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
                self.assertNotIn("UNEXPECTED_PRIVATE_VALUE", str(raised.exception))

    def test_explicit_missing_unit_still_blocks_preflight_and_restart(self):
        name = "custom-worker.service"
        properties = {"Id": name, "LoadState": "not-found", "ActiveState": "inactive"}
        for operation in ("preflight", "restart"):
            with self.subTest(operation=operation):
                with mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl"), \
                     mock.patch.object(guard, "run_cmd", side_effect=[
                         self.response({}, 1), self.response(properties)]) as command:
                    if operation == "preflight":
                        result = guard.service_preflight(al2_inventory(), [], [name])
                        self.assertEqual([], result["services"])
                        failures = result["blockers"]
                    else:
                        result = guard.restart_services([name])
                        self.assertFalse(result["ok"])
                        failures = result["errors"]
                self.assertEqual([name], [item["service"] for item in failures])
                self.assertIn("does not exist", failures[0]["reason"])
                self.assertTrue(all(call.args[0][1] == "show" for call in command.call_args_list),
                                "invalid explicit units must not be silently skipped or restarted")


class ExplainModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(SCRIPT.parent))
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.report_path = self.folder / "report.json"
        # A report explanation must work without Linux, root, probes, or writes.
        self.guarded = {}
        for name in ("collect_inventory", "fetch_candidates", "package_transaction",
                     "execute_repair", "service_preflight", "acquire_repair_lock",
                     "run_cmd", "write_json"):
            patch = mock.patch.object(guard, name, side_effect=AssertionError("unexpected host action: " + name))
            self.guarded[name] = patch.start()
            self.addCleanup(patch.stop)
        for name in ("geteuid", "umask", "makedirs"):
            patch = mock.patch.object(guard.os, name, side_effect=AssertionError("unexpected OS action: " + name))
            self.guarded[name] = patch.start()
            self.addCleanup(patch.stop)
        platform = mock.patch.object(guard.sys, "platform", "darwin")
        platform.start()
        self.addCleanup(platform.stop)

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = guard.main(args)
            except SystemExit as exc:
                code = exc.code
        for name, action in self.guarded.items():
            with self.subTest(action=name):
                action.assert_not_called()
        return code, stdout.getvalue() + stderr.getvalue()

    def save_and_explain(self, report):
        content = json.dumps(report, ensure_ascii=False).encode("utf-8")
        self.report_path.write_bytes(content)
        code, output = self.invoke(["explain", "--report", str(self.report_path)])
        self.assertEqual(content, self.report_path.read_bytes())
        self.assertEqual([self.report_path], list(self.folder.iterdir()))
        return code, output

    def test_saved_blocked_report_is_explained_without_root_or_host_actions(self):
        _, output = self.save_and_explain(blocked_report())
        for detail in ("blocked_no_update", "php-cli", "php-fpm.service", "78",
                       "queue-worker.service", "new backend diagnostic", "RPM"):
            with self.subTest(detail=detail):
                self.assertIn(detail, output)

    def test_failure_without_blockers_retains_failure_stage_and_result(self):
        report = {"plan": {"updates": [], "blockers": []},
                  "service_preflight": {"blockers": []}, "result": "repair_failed",
                  "repair": {"ok": False, "stage": "package_update", "error": "rpm transaction failed"}}
        _, output = self.save_and_explain(report)
        for detail in ("repair_failed", "package_update", "rpm transaction failed"):
            self.assertIn(detail, output)
        self.assertNotIn("修复成功", output)
        self.assertNotIn("已修复", output)

    def test_old_report_missing_optional_sections_is_readable(self):
        code, output = self.save_and_explain({"result": "unresolved"})
        self.assertNotEqual(2, code)
        self.assertIn("unresolved", output)
        self.assertNotIn("Traceback", output)

    def test_unknown_saved_reason_is_preserved(self):
        report = {"result": "blocked_no_update", "plan": {"blockers": [
            {"kind": "new_guard", "reason": "custom reason from a newer report"}]}}
        _, output = self.save_and_explain(report)
        self.assertIn("custom reason from a newer report", output)

    def test_missing_report_file_is_a_read_error(self):
        code, output = self.invoke(["explain", "--report", str(self.report_path)])
        self.assertEqual(2, code)
        self.assertTrue(output.strip())
        self.assertNotIn("Traceback", output)

    def test_invalid_json_or_non_object_json_returns_two(self):
        for content in (b"{invalid-json", b"[]", b"null"):
            with self.subTest(content=content):
                self.report_path.write_bytes(content)
                code, output = self.invoke(["explain", "--report", str(self.report_path)])
                self.assertEqual(2, code)
                self.assertNotIn("Traceback", output)
                self.assertEqual(content, self.report_path.read_bytes())

    def test_explain_without_report_argument_returns_two(self):
        code, output = self.invoke(["explain"])
        self.assertEqual(2, code)
        self.assertIn("report", output)


class BlockedMainFlowTests(unittest.TestCase):
    def test_plan_and_fix_print_actionable_blockers_without_attempting_transaction(self):
        for index, args in enumerate((["plan"], ["fix"], ["fix", "--yes"])):
            with self.subTest(mode=args), tempfile.TemporaryDirectory(dir=str(SCRIPT.parent)) as folder:
                output_dir = pathlib.Path(folder) / ("blocked-" + str(index))
                report = blocked_report()
                stdout = io.StringIO()
                with mock.patch.object(guard.sys, "platform", "linux"), \
                     mock.patch.object(guard.os, "geteuid", return_value=0), \
                     mock.patch.object(guard.os, "umask"), \
                     mock.patch.object(guard, "POLICY", {"checked_on": "2026-10-22", "entries": []}), \
                     mock.patch.object(guard, "collect_inventory", return_value=report["inventory_before"]), \
                     mock.patch.object(guard, "fetch_candidates", return_value={}), \
                     mock.patch.object(guard, "check_package_integrity", return_value=[]), \
                     mock.patch.object(guard, "service_preflight", return_value=report["service_preflight"]), \
                     mock.patch.object(guard, "acquire_repair_lock", return_value=None), \
                     mock.patch.object(guard, "run_cmd", side_effect=AssertionError("unexpected host command")), \
                     mock.patch.object(guard, "package_transaction") as transaction, \
                     mock.patch.object(guard, "execute_repair") as repair, \
                     contextlib.redirect_stdout(stdout):
                    code = guard.main(args + ["--output-dir", str(output_dir)])
                self.assertEqual(10, code)
                self.assertEqual("blocked_no_update", json.loads((output_dir / "report.json").read_text())["result"])
                transaction.assert_not_called()
                repair.assert_not_called()
                for detail in ("php-cli", "php-fpm.service", "78", "queue-worker.service",
                               "new backend diagnostic", "RPM"):
                    self.assertIn(detail, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
