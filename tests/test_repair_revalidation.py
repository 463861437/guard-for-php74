"""Fresh-state checks must guard both package application and service restart."""
import copy
import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "php_guard.py"
SPEC = importlib.util.spec_from_file_location("guard_revalidation_under_test", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def host():
    return dict(
        os=dict(id="debian", version_id="12"), package_manager="apt",
        packages=[dict(name="php8.2-cli", source="php8.2", arch="amd64",
                       version="8.2.34-1", upstream="8.2.34")],
        runtimes=[], processes=[], containers=[], warnings=[],
        services=[dict(name="php8.2-fpm.service", active="active")])


def update():
    return dict(name="php8.2-cli", source="php8.2", arch="amd64",
                old_version="8.2.34-1", version="8.2.35-1", upstream="8.2.35")


class RevalidateTests(unittest.TestCase):
    def setUp(self):
        self.before = host()
        self.current = copy.deepcopy(self.before)
        self.services = ["php8.2-fpm.service"]
        self.updates = [update()]
        properties = {"ExecStart": "{ path=/usr/sbin/php-fpm8.2 ; argv[]=/usr/sbin/php-fpm8.2 --nodaemonize ; }"}
        self.collect = mock.patch.object(guard, "collect_inventory", return_value=self.current).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(guard, "check_package_integrity", return_value=[]).start()
        mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl").start()
        mock.patch.object(guard, "_svc_show", return_value=properties).start()
        mock.patch.object(guard, "_inv_trusted_executable", return_value=(True, None)).start()

        def config_test(argv, timeout=30):
            if argv == ["/usr/sbin/php-fpm8.2", "-t"]:
                return dict(code=0, stdout="", stderr="")
            raise AssertionError("unexpected host command: " + repr(argv))
        mock.patch.object(guard, "run_cmd", side_effect=config_test).start()

    def check(self, **kwargs):
        return guard.repair_revalidate(self.before, self.updates, self.services, {}, **kwargs)

    def test_scan_roots_are_preserved_when_collecting_fresh_inventory(self):
        roots = ["/srv/custom/php", "/opt/second-php"]
        result = self.check(scan_roots=roots)
        self.assertTrue(result["ok"], result)
        self.collect.assert_called_once_with(roots)

    def test_new_unmapped_php_process_blocks_even_if_executable_version_is_known(self):
        self.current["processes"].append(dict(
            pid=991, comm="php", exe="/usr/bin/php8.2", version="8.2.34",
            service=None, container=False, deleted=False))
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("991" in item["reason"]
                            for item in result["preflight"]["blockers"]), result)

    def test_new_fpm_service_cannot_silently_expand_restart_scope(self):
        self.current["services"].append(dict(name="php8.3-fpm.service", active="active"))
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])
        self.assertIn("php8.3-fpm.service", result["preflight"]["services"])

    def test_installed_version_changed_since_plan_blocks_before_apply(self):
        self.current["packages"][0].update(version="8.2.34-2")
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_new_core_extension_not_in_original_plan_blocks(self):
        self.current["packages"].append(dict(
            name="php8.2-mbstring", source="php8.2", arch="amd64",
            version="8.2.34-1", upstream="8.2.34"))
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_exact_expected_updated_inventory_passes_after_apply(self):
        self.current["packages"][0].update(version="8.2.35-1", upstream="8.2.35")
        result = self.check(after_update=True)
        self.assertTrue(result["ok"], result)

    def test_old_version_after_apply_cannot_be_marked_complete(self):
        result = self.check(after_update=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_deleted_executable_of_approved_service_can_reach_restart(self):
        self.current["packages"][0].update(version="8.2.35-1", upstream="8.2.35")
        self.current["processes"].append(dict(
            pid=992, comm="php-fpm8.2", exe="/usr/sbin/php-fpm8.2 (deleted)",
            version=None, service="php8.2-fpm.service", container=False, deleted=True))
        result = self.check(after_update=True)
        self.assertTrue(result["ok"], result)

    def test_deleted_executable_outside_approved_service_still_blocks(self):
        self.current["packages"][0].update(version="8.2.35-1", upstream="8.2.35")
        self.current["processes"].append(dict(
            pid=993, comm="php", exe="/usr/bin/php8.2 (deleted)",
            version=None, service=None, container=False, deleted=True))
        result = self.check(after_update=True)
        self.assertFalse(result["ok"])
        self.assertTrue(any(item.get("kind") == "stale_process" for item in result["errors"]))

    def test_container_process_cannot_use_approved_service_restart_exception(self):
        self.current["packages"][0].update(version="8.2.35-1", upstream="8.2.35")
        self.current["processes"].append(dict(
            pid=994, comm="php-fpm8.2", exe="/usr/sbin/php-fpm8.2 (deleted)",
            version=None, service="php8.2-fpm.service", container=True, deleted=True))
        result = self.check(after_update=True)
        self.assertFalse(result["ok"])
        self.assertTrue(any(item.get("kind") == "stale_process" for item in result["errors"]))

    def test_new_coverage_warning_blocks_before_apply(self):
        self.current["warnings"].append("Process inventory incomplete")
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_new_unmanaged_runtime_blocks_before_apply(self):
        self.current["runtimes"].append(dict(
            path="/opt/custom/php", realpath="/opt/custom/php", package=None,
            version="8.2.35"))
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])


class ExecutionRevalidationTests(unittest.TestCase):
    def setUp(self):
        self.before = host()
        self.preflight = dict(services=["php8.2-fpm.service"], blockers=[], checks=[])
        self.plan = dict(updates=[update()], blockers=[])
        self.good = dict(ok=True, inventory=self.before, preflight=self.preflight, errors=[])
        self.bad = dict(ok=False, inventory=self.before, preflight=self.preflight,
                        errors=["Fresh runtime scope changed"])
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(guard, "run_cmd", side_effect=AssertionError("unexpected host command")).start()
        mock.patch.object(guard, "health_checks", return_value=[]).start()
        mock.patch.object(guard, "write_json").start()
        mock.patch.object(guard, "say").start()
        self.backup = mock.patch.object(guard, "backup_configuration", return_value="backup.tar.gz").start()
        self.restart = mock.patch.object(guard, "restart_services", return_value=dict(ok=True)).start()
        self.transaction = mock.patch.object(guard, "package_transaction", return_value=dict(ok=True)).start()

    def test_failed_revalidation_before_apply_prevents_backup_and_mutation(self):
        with mock.patch.object(guard, "repair_revalidate", return_value=self.bad):
            result = guard.execute_repair(self.before, self.plan, self.preflight, {}, "unused")
        self.assertFalse(result["ok"])
        self.assertFalse(any(call.kwargs.get("execute") for call in self.transaction.call_args_list))
        self.backup.assert_not_called()
        self.restart.assert_not_called()

    def test_failed_revalidation_after_apply_prevents_service_restart(self):
        with mock.patch.object(guard, "repair_revalidate", side_effect=[self.good, self.bad]):
            result = guard.execute_repair(self.before, self.plan, self.preflight, {}, "unused")
        self.assertFalse(result["ok"])
        self.assertEqual([False, True], [call.kwargs["execute"] for call in self.transaction.call_args_list])
        self.restart.assert_not_called()

    def test_scan_roots_are_passed_to_each_revalidation(self):
        roots = ["/srv/php-custom"]
        with mock.patch.object(guard, "repair_revalidate", return_value=self.good) as revalidate:
            result = guard.execute_repair(self.before, self.plan, self.preflight, {}, "unused", scan_roots=roots)
        self.assertTrue(result["ok"], result)
        self.assertEqual(2, revalidate.call_count)
        for call in revalidate.call_args_list:
            observed = call.kwargs.get("scan_roots", call.args[4] if len(call.args) > 4 else None)
            self.assertEqual(roots, observed)
        self.restart.assert_called_once_with(self.preflight["services"])


if __name__ == "__main__":
    unittest.main()
