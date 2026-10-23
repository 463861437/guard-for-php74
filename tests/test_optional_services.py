"""Optional service absence must never weaken PHP process/restart coverage."""
import copy
import importlib.util
import pathlib
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("optional_service_guard", ROOT / "php_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
for module in ("service_ops", "cli", "oneclick"):
    exec(compile((ROOT / ("src/" + module + ".py")).read_text(), module, "exec"), guard.__dict__)


def inventory():
    return dict(os=dict(id="amzn", version_id="2"), package_manager="yum",
                packages=[], services=[], processes=[], runtimes=[], containers=[], warnings=[])


def properties(name="supervisord.service", **overrides):
    result = dict(Id=name, LoadState="loaded", ActiveState="active", ExecStart="",
                  Environment="", EnvironmentFiles="", RootDirectory="", RootImage="",
                  WorkingDirectory="", User="", Group="")
    result.update(overrides)
    return result


def response(values=None, code=0, stderr=""):
    return dict(code=code, stdout="\n".join(key + "=" + value for key, value in (values or {}).items()),
                stderr=stderr)


def missing(name="supervisord.service"):
    return response(dict(Id=name, LoadState="not-found", ActiveState="inactive"))


class OptionalServiceTests(unittest.TestCase):
    def setUp(self):
        self.inv = inventory()
        self.tool = mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl").start()
        self.command = mock.patch.object(guard, "run_cmd", side_effect=AssertionError("unexpected host command")).start()
        self.addCleanup(mock.patch.stopall)

    def resolve(self, required=(), optional=("supervisord",)):
        return guard.resolve_optional_services(self.inv, list(required), list(optional))

    def assert_blocked(self, result):
        self.assertTrue(result["blockers"], result)
        self.assertEqual([], result["skipped"], result)

    def test_observed_absence_is_skipped_on_current_and_legacy_systemd(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                self.command.side_effect = ([response(code=1, stderr="Unknown property 'RootImage'")]
                                            if legacy else []) + [missing()]
                result = self.resolve()
                self.assertEqual([], result["services"])
                self.assertEqual([], result["blockers"])
                self.assertEqual(["supervisord.service"], [row["service"] for row in result["skipped"]])
                self.assertTrue(result["skipped"][0]["reason"])
        self.assertTrue(all(call.args[0][1] == "show" for call in self.command.call_args_list))

    def test_only_successful_explicit_absence_has_the_distinct_exception_type(self):
        self.command.side_effect = [missing()]
        with self.assertRaises(guard.ServiceNotFoundError):
            guard._svc_show("/usr/bin/systemctl", "supervisord.service")
        self.assertTrue(issubclass(guard.ServiceNotFoundError, ValueError))

    def test_failure_output_containing_not_found_is_not_trusted(self):
        for message in ("Failed to connect to bus", "Permission denied", "Access denied"):
            with self.subTest(error=message):
                invalid = missing()
                invalid.update(code=1, stderr=message)
                self.command.side_effect = [invalid, invalid]
                self.assert_blocked(self.resolve())

    def test_missing_or_incomplete_properties_do_not_become_absence(self):
        cases = [
            [response()],
            [response(dict(ActiveState="inactive"))],
            [response(dict(LoadState="loaded"))],
            [response(code=1), response(dict(LoadState="loaded", ActiveState="active")), response()],
        ]
        for replies in cases:
            with self.subTest(replies=replies):
                self.command.side_effect = replies
                self.assert_blocked(self.resolve())

    def test_missing_identity_or_wrong_unit_cannot_prove_requested_service_absence(self):
        for fields in (dict(LoadState="not-found", ActiveState="inactive"),
                       dict(Id="different.service", LoadState="not-found", ActiveState="inactive")):
            with self.subTest(fields=fields):
                self.command.side_effect = [response(fields)]
                self.assert_blocked(self.resolve())

    def test_timeout_and_os_error_remain_blockers_without_echoing_output(self):
        for failure in (OSError("systemctl unavailable"),):
            with self.subTest(failure=type(failure).__name__):
                self.command.side_effect = failure
                self.assert_blocked(self.resolve())
        self.command.side_effect = [response(code=124, stderr="PRIVATE_ENV_SECRET"),
                                    response(code=124, stderr="PRIVATE_ENV_SECRET")]
        result = self.resolve()
        self.assert_blocked(result)
        self.assertNotIn("PRIVATE_ENV_SECRET", repr(result))

    def test_untrusted_systemctl_does_not_allow_skip(self):
        self.tool.return_value = None
        self.assert_blocked(self.resolve())
        self.command.assert_not_called()

    def test_plain_value_error_with_missing_message_is_not_an_absence_proof(self):
        with mock.patch.object(guard, "_svc_show", side_effect=ValueError(
                "Systemd service does not exist (LoadState=not-found)")):
            self.assert_blocked(self.resolve())

    def test_existing_inactive_failed_or_masked_services_are_not_skipped(self):
        for fields in (dict(ActiveState="inactive"), dict(ActiveState="failed"),
                       dict(ActiveState="activating"), dict(LoadState="masked"),
                       dict(LoadState="error")):
            with self.subTest(fields=fields):
                self.command.side_effect = [response(properties(**fields))]
                self.assert_blocked(self.resolve())

    def test_existing_service_is_promoted_to_normalized_strict_restart_scope(self):
        self.command.side_effect = [response(properties())]
        result = self.resolve(optional=("supervisord", "supervisord.service"))
        self.assertEqual(["supervisord.service"], result["services"])
        self.assertEqual([], result["skipped"])
        self.assertEqual([], result["blockers"])
        self.assertEqual(1, self.command.call_count)

    def test_required_service_wins_over_optional_duplicates_and_stays_strict(self):
        result = self.resolve(required=("supervisord", "supervisord.service"))
        self.assertEqual(["supervisord.service"], result["services"])
        self.assertEqual([], result["skipped"])
        self.command.assert_not_called()
        self.command.side_effect = [missing()]
        preflight = guard.service_preflight(self.inv, [], result["services"])
        self.assertTrue(preflight["blockers"])
        self.assertEqual([], preflight["services"])

    def test_invalid_names_and_container_managers_never_reach_a_command(self):
        for service in ("../supervisord", "supervisord;reboot", "--help", "docker",
                        "podman", "containerd", "kubelet"):
            with self.subTest(service=service):
                self.assert_blocked(self.resolve(optional=(service,)))
        self.command.assert_not_called()

    def test_loaded_alias_to_container_manager_is_rejected(self):
        self.command.side_effect = [response(properties(Id="docker.service"))]
        self.assert_blocked(self.resolve(optional=("worker-alias",)))

    def test_absence_conflicting_with_live_inventory_is_never_skipped(self):
        cases = [
            dict(services=[dict(name="supervisord.service", active="active")]),
            dict(processes=[dict(pid=91, comm="php", exe="/usr/bin/php",
                                 service="supervisord.service")]),
            dict(processes=[dict(pid=92, comm="php-fpm", exe="/usr/sbin/php-fpm",
                                 service="supervisord.service")]),
        ]
        for fields in cases:
            with self.subTest(fields=fields):
                self.inv = inventory()
                self.inv.update(fields)
                self.command.side_effect = [missing()]
                self.assert_blocked(self.resolve())

    def test_skipping_absent_optional_does_not_cover_unmapped_php_or_other_service(self):
        for service in (None, "actual-worker.service"):
            with self.subTest(service=service):
                self.inv["processes"] = [dict(pid=95, comm="php", exe="/usr/bin/php", service=service)]
                self.command.side_effect = [missing()]
                result = self.resolve()
                self.assertEqual([], result["services"])
                preflight = guard.service_preflight(self.inv, [], result["services"])
                self.assertTrue(preflight["blockers"])
                self.assertEqual(95, preflight["blockers"][0]["pid"])

    def test_child_install_receives_only_resolved_strict_services(self):
        self.command.side_effect = [response(properties()), missing("unused.service")]
        result = self.resolve(optional=("supervisord", "unused"))
        args = types.SimpleNamespace(service=result["services"], service_if_present=["supervisord", "unused"],
                                     lock_wait=300, health_url=[], health_host=None)
        command = guard.oc_install_args(args, "/build")
        self.assertEqual(["fix", "--yes", "--work-dir", "/build", "--lock-wait", "300",
                          "--service", "supervisord.service"], command)

    def test_previously_resolved_service_disappearing_before_install_blocks_revalidation(self):
        self.command.side_effect = [response(properties()), missing()]
        result = self.resolve()
        with mock.patch.object(guard, "collect_inventory", return_value=copy.deepcopy(self.inv)), \
             mock.patch.object(guard, "assess_inventory", return_value=[]), \
             mock.patch.object(guard, "check_package_integrity", return_value=[]):
            fresh = guard.repair_revalidate(self.inv, [], result["services"], {})
        self.assertFalse(fresh["ok"])
        self.assertEqual("supervisord.service", fresh["preflight"]["blockers"][0]["service"])
        self.assertTrue(all(call.args[0][1] == "show" for call in self.command.call_args_list))


FIXTURE_SPEC = importlib.util.spec_from_file_location("optional_oneclick_fixture", ROOT / "tests/test_oneclick.py")
oneclick_fixture = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(oneclick_fixture)
for module in ("service_ops", "cli"):
    exec(compile((ROOT / ("src/" + module + ".py")).read_text(), module, "exec"), oneclick_fixture.guard.__dict__)


class OptionalOneclickIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the offline orchestration fixture, not its tests or host probes.
        oneclick_fixture.OneclickTests.setUp(self)
        self.guard = oneclick_fixture.guard
        patch = mock.patch.object(self.guard, "_inv_tool", return_value="/usr/bin/systemctl")
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(self.guard, "run_cmd", side_effect=AssertionError("unexpected host command"))
        self.command = patch.start()
        self.addCleanup(patch.stop)

    def run_main(self, args):
        return oneclick_fixture.OneclickTests.run_main(self, args)

    def test_plan_skips_absent_optional_and_checks_remaining_restart_scope(self):
        self.command.side_effect = [missing()]
        code, report = self.run_main(["plan", "--service-if-present", "supervisord"])
        self.assertEqual(0, code, report)
        self.assertEqual("route_plan_ready", report["result"])
        self.assertEqual("supervisord.service", report["optional_service_selection"]["skipped"][0]["service"])
        self.assertEqual([], self.mocks["service_preflight"].call_args.args[2])
        self.mocks["oc_source_apply"].assert_not_called()
        self.mocks["execute_repair"].assert_not_called()

    def test_unknown_optional_status_blocks_fix_before_any_build_or_deployment(self):
        self.command.side_effect = [response(code=1, stderr="Access denied"),
                                    response(code=1, stderr="Access denied")]
        code, report = self.run_main(["fix", "--yes", "--service-if-present", "supervisord"])
        self.assertEqual(10, code, report)
        self.assertEqual("blocked_services", report["result"])
        self.assertTrue(report["service_preflight"]["blockers"])
        self.mocks["oc_source_apply"].assert_not_called()
        self.mocks["execute_repair"].assert_not_called()
        self.mocks["package_transaction"].assert_not_called()

    def test_existing_optional_is_strict_in_source_builder_and_child_install(self):
        self.command.side_effect = [response(properties())]
        code, report = self.run_main(["fix", "--yes", "--service-if-present", "supervisord"])
        self.assertEqual(0, code, report)
        self.mocks["oc_source_apply"].assert_called_once()
        args = self.mocks["oc_source_apply"].call_args.args[1]
        self.assertEqual(["supervisord.service"], args.service)
        command = self.guard.oc_install_args(args, "/build")
        self.assertIn("--service", command)
        self.assertEqual("supervisord.service", command[command.index("--service") + 1])
        self.assertNotIn("--service-if-present", command)


if __name__ == "__main__":
    unittest.main()
