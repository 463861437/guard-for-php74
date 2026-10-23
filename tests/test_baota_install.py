"""Local Baota-source RPM deployment must fail closed before mutation."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "php_guard.py"
SPEC = importlib.util.spec_from_file_location("guard_baota_install_test", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def manifest():
    rows = []
    for name in sorted(guard.BP_CORE_NAMES):
        rows.append(dict(name=name, version=guard.BAOTA_AL2_VERSION,
                         release=guard.BAOTA_AL2_RELEASE, arch="x86_64",
                         file="%s-%s-%s.x86_64.rpm" % (name, guard.BAOTA_AL2_VERSION, guard.BAOTA_AL2_RELEASE),
                         sha256=hashlib.sha256(b"rpm bytes").hexdigest()))
    return dict(recipe="baota-al2-php74", state="built_not_deployed", stage="complete",
                target_version=guard.BAOTA_AL2_VERSION, target_release=guard.BAOTA_AL2_RELEASE,
                upstream_commit=guard.BP_COMMIT, rpm_signature_verified=True, php_selftests_passed=True,
                inputs={guard.BP_SRPM: guard.BP_SRPM_SHA, guard.BP_KEY: guard.BP_KEY_SHA,
                        guard.BP_PATCH: guard.BP_PATCH_SHA, "php-7.4.34.tar.gz": guard.BAOTA_AL2_SOURCE_SHA},
                php_selftest_summary=dict(total=10, passed=10, failed=0, borked=0, leaked=0),
                mitigation_smoke_tests=[dict(sapi=sapi, version=guard.BAOTA_AL2_VERSION,
                    oom_exit=1, shutdown_callback_ran=False) for sapi in ("build-apache", "build-ztscli")],
                artifacts=rows)


def host():
    return dict(os=dict(id="amzn", version_id="2"), package_manager="yum",
                packages=[dict(name="php-cli", source="php", arch="x86_64",
                               version="7.4.33-1.amzn2", upstream="7.4.33")],
                runtimes=[], processes=[], containers=[], services=[], warnings=[])


class BuildBundleTests(unittest.TestCase):
    def test_complete_expected_manifest_is_accepted(self):
        report = manifest()
        self.assertEqual(report["artifacts"], guard.bi_validate_build(report))

    def test_incomplete_recipe_failed_tests_and_unexpected_rpms_are_rejected(self):
        cases = []
        report = manifest(); report["recipe"] = "al2-php74"; cases.append(report)
        report = manifest(); report["inputs"]["php-7.4.34.tar.gz"] = "0" * 64; cases.append(report)
        report = manifest(); report["php_selftest_summary"]["failed"] = 1; cases.append(report)
        report = manifest(); report["artifacts"].pop(); cases.append(report)
        report = manifest(); report["artifacts"][0]["file"] = "../../outside.rpm"; cases.append(report)
        report = manifest(); report["artifacts"].append(copy.deepcopy(report["artifacts"][0])); cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(RuntimeError):
                guard.bi_validate_build(report)

    def test_artifact_hash_failure_occurs_before_rpm_metadata_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            report = manifest()
            (root / "build.json").write_text(json.dumps(report))
            (root / "build.log").write_text("test log")
            src = root / "rpmbuild" / "RPMS" / "x86_64"
            src.mkdir(parents=True)
            (src / report["artifacts"][0]["file"]).write_bytes(b"tampered RPM")
            folder = root / "report"; folder.mkdir()
            with mock.patch.object(guard, "bp_selftest_summary", return_value=report["php_selftest_summary"]), \
                 mock.patch.object(guard, "bi_metadata") as metadata:
                with self.assertRaises(RuntimeError):
                    guard.bi_stage(str(root / "build.json"), str(folder))
                metadata.assert_not_called()

    def test_log_summary_mismatch_rejects_before_copying_rpms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); report = manifest()
            (root / "build.json").write_text(json.dumps(report))
            (root / "build.log").write_text("test log")
            with mock.patch.object(guard, "bp_selftest_summary", return_value={"total": 1}), \
                 mock.patch.object(guard, "bi_metadata") as metadata:
                with self.assertRaises(RuntimeError):
                    guard.bi_stage(str(root / "build.json"), str(root))
                metadata.assert_not_called()
                self.assertFalse((root / "rpms").exists())

    def test_latest_report_does_not_fall_back_from_a_failed_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            old = root / "build-old" / "build.json"
            new = root / "build-new" / "build.json"
            old.parent.mkdir(); new.parent.mkdir()
            old.write_text(json.dumps(manifest()))
            new.write_text(json.dumps({"state": "build_failed"}))
            guard.os.utime(str(old), (100, 100))
            guard.os.utime(str(new), (200, 200))
            self.assertEqual(str(new), guard.bi_latest_report(tmp))
            with self.assertRaises(RuntimeError):
                guard.bi_validate_build(guard.bi_read_json(str(new)))

    def test_manifest_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); (root / "real.json").write_text("{}")
            (root / "link.json").symlink_to(root / "real.json")
            with self.assertRaises(RuntimeError):
                guard.bi_read_json(str(root / "link.json"))


class LocalPlanTests(unittest.TestCase):
    def test_non_al2_host_and_unmanaged_runtime_are_blocked(self):
        inv = host(); inv["os"]["id"] = "ubuntu"
        self.assertTrue(guard.bi_plan(inv, [])["blockers"])
        inv = host(); inv["runtimes"] = [dict(path="/www/server/php/74/bin/php", package=None)]
        item = dict(manifest()["artifacts"][0], name="php-cli", header_sha1="a" * 40)
        with mock.patch.object(guard, "native_compare", return_value=1), \
             mock.patch.object(guard, "check_package_integrity", return_value=[]):
            result = guard.bi_plan(inv, [item])
        self.assertTrue(any(x.get("kind") == "unmanaged_runtime" for x in result["blockers"]))

    def test_same_evr_different_header_does_not_become_noop_success(self):
        inv = host(); inv["packages"][0]["version"] = guard.BAOTA_AL2_VERSION + "-" + guard.BAOTA_AL2_RELEASE
        item = dict(manifest()["artifacts"][0], name="php-cli", header_sha1="a" * 40)
        with mock.patch.object(guard, "native_compare", return_value=0), \
             mock.patch.object(guard, "bi_metadata", return_value={"header_sha1": "b" * 40}), \
             mock.patch.object(guard, "check_package_integrity", return_value=[]):
            result = guard.bi_plan(inv, [item])
        self.assertTrue(result["blockers"])
        self.assertFalse(result["updates"])

    def test_version_string_without_matching_receipt_does_not_prove_fix(self):
        inv = host(); inv["packages"][0].update(version=guard.BAOTA_AL2_VERSION + "-" + guard.BAOTA_AL2_RELEASE,
                                            upstream=guard.BAOTA_AL2_VERSION)
        with mock.patch.object(guard, "check_package_integrity", return_value=[]):
            result = guard.bi_assess(inv, {})
        self.assertEqual("affected", result[0]["status"])


class ReceiptPayloadTests(unittest.TestCase):
    def test_config_edits_are_allowed_but_changed_shared_module_is_not(self):
        cases = [
            (dict(code=0, stdout="", stderr=""), True),
            (dict(code=1, stdout="S.5....T.  c /etc/php.ini\n", stderr=""), True),
            (dict(code=1, stdout="S.5....T.    /usr/lib64/php/modules/xml.so\n", stderr=""), False),
            (dict(code=1, stdout="missing     /usr/lib64/httpd/modules/libphp7.so\n", stderr=""), False),
            (dict(code=1, stdout="", stderr="error: rpmdb unavailable"), False),
        ]
        for result, expected in cases:
            with self.subTest(result=result), mock.patch.object(guard, "run_cmd", return_value=result):
                self.assertEqual(expected, guard.bi_payload_ok("php.x86_64"))

    def test_matching_header_cannot_hide_changed_installed_payload(self):
        inv = host(); inv["packages"][0].update(version=guard.BAOTA_AL2_VERSION + "-" + guard.BAOTA_AL2_RELEASE,
                                            upstream=guard.BAOTA_AL2_VERSION)
        receipt = dict(packages=[dict(name="php-cli", arch="x86_64", header_sha1="a" * 40)])
        meta = dict(version=guard.BAOTA_AL2_VERSION, release=guard.BAOTA_AL2_RELEASE, header_sha1="a" * 40)
        with mock.patch.object(guard, "check_package_integrity", return_value=[]), \
             mock.patch.object(guard, "bi_metadata", return_value=meta), \
             mock.patch.object(guard, "bi_payload_ok", return_value=False):
            findings = guard.bi_assess(inv, receipt)
        self.assertTrue(any(x["status"] != "fixed" for x in findings))
        self.assertTrue(any(x.get("kind") == "binary_integrity" for x in findings))


class NativeTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / "php-cli.rpm"; self.path.write_bytes(b"original")
        update = dict(name="php-cli", arch="x86_64", source="php", old_version="7.4.33-1.amzn2",
                      version=guard.BAOTA_AL2_VERSION + "-" + guard.BAOTA_AL2_RELEASE,
                      path=str(self.path), sha256=hashlib.sha256(b"original").hexdigest())
        self.request = dict(updates=[update], lock_wait=0, execute=True,
                            log=str(pathlib.Path(self.tmp.name) / "transaction.log"))
        base = mock.Mock()
        base.conf.installroot = "/"; base.conf.persistdir = "/var/lib/yum"
        base._lockfile = "/run/yum.pid"
        base.buildTransaction.return_value = (2, [])
        self.base = base
        yum = types.ModuleType("yum"); yum.YumBase = mock.Mock(return_value=base)
        yum.misc = types.ModuleType("yum.misc"); yum.misc.find_unfinished_transactions = mock.Mock(return_value=[])
        yum.constants = types.ModuleType("yum.constants")
        yum.constants.TS_UPDATE = 10; yum.constants.TS_UPDATED = 90
        yum.constants.TS_OBSOLETED = 50; yum.constants.TS_INSTALL = 20
        self.constants = yum.constants
        self.new = types.SimpleNamespace(name="php-cli", arch="x86_64", epoch="0",
                     version=guard.BAOTA_AL2_VERSION, release=guard.BAOTA_AL2_RELEASE,
                     sourcerpm="php-%s-%s.src.rpm" % (guard.BAOTA_AL2_VERSION, guard.BAOTA_AL2_RELEASE),
                     repoid="@local")
        self.old = types.SimpleNamespace(name="php-cli", arch="x86_64", epoch="0", version="7.4.33",
                                        release="1.amzn2", sourcerpm="php-7.4.33-1.amzn2.src.rpm", repoid="installed")
        base.tsInfo.getMembers.return_value = [
            types.SimpleNamespace(output_state=yum.constants.TS_UPDATE, po=self.new),
            types.SimpleNamespace(output_state=yum.constants.TS_UPDATED, po=self.old)]
        rpm = types.ModuleType("rpm"); rpm.labelCompare = lambda a, b: (a > b) - (a < b)
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict("sys.modules", {"yum": yum, "yum.misc": yum.misc,
                                       "yum.constants": yum.constants, "rpm": rpm}).start()
        self.ns = {}
        exec(guard._RPM_WORKER.rsplit("if __name__ == '__main__': main()", 1)[0], self.ns)
        self.ns.update(yum_acquire_lock=mock.Mock(), verify_existing=mock.Mock(), verify_after=mock.Mock())
        exec(guard._BI_WORKER.split("request_path, response_path =", 1)[0], self.ns)
        self.call = mock.patch("subprocess.call", return_value=0).start()

    def test_obsoletes_removal_is_rejected_before_rpm_test_or_install(self):
        self.base.tsInfo.getMembers.return_value[1].output_state = self.constants.TS_OBSOLETED
        result = self.ns["bi_native"](self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["executed"])
        self.assertIn("obsoletes action blocked", result["error"])
        self.call.assert_not_called(); self.ns["verify_after"].assert_not_called()
        self.base.doUnlock.assert_called_once()

    def test_unplanned_dependency_install_is_rejected_before_rpm_execution(self):
        extra = types.SimpleNamespace(name="unexpected-lib", arch="x86_64")
        self.base.tsInfo.getMembers.return_value.append(
            types.SimpleNamespace(output_state=self.constants.TS_INSTALL, po=extra))
        result = self.ns["bi_native"](self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["executed"])
        self.assertIn("Unplanned dependency change", result["error"])
        self.call.assert_not_called(); self.ns["verify_after"].assert_not_called()

    def test_unresolved_local_dependency_plan_never_reaches_rpm(self):
        self.base.buildTransaction.return_value = (1, ["unresolved dependency"])
        result = self.ns["bi_native"](self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["executed"])
        self.call.assert_not_called()

    def test_rpm_dependency_failure_never_runs_install(self):
        self.call.return_value = 1
        result = self.ns["bi_native"](self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["executed"])
        self.assertEqual(1, self.call.call_count)
        self.assertIn("--test", self.call.call_args.args[0])
        self.ns["verify_after"].assert_not_called()
        self.base.doUnlock.assert_called_once()

    def test_hash_change_after_preview_blocks_install(self):
        def preview(*args, **kwargs):
            self.path.write_bytes(b"changed")
            return 0
        self.call.side_effect = preview
        result = self.ns["bi_native"](self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["executed"])
        self.assertEqual(1, self.call.call_count)
        self.assertIn("checksum", result["error"])

    def test_preview_is_read_only_and_apply_checks_installed_state(self):
        self.request["execute"] = False
        result = self.ns["bi_native"](self.request)
        self.assertTrue(result["ok"]); self.assertFalse(result["executed"])
        self.assertEqual(1, self.call.call_count)
        self.ns["verify_after"].assert_not_called()
        self.call.reset_mock(); self.request["execute"] = True
        result = self.ns["bi_native"](self.request)
        self.assertTrue(result["ok"]); self.assertTrue(result["executed"])
        self.assertEqual(2, self.call.call_count)
        self.assertIn("--test", self.call.call_args_list[0].args[0])
        self.assertNotIn("--test", self.call.call_args_list[1].args[0])
        self.ns["verify_after"].assert_called_once()


class InstallControlFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)
        self.inv = host()
        self.update = dict(name="php-cli", arch="x86_64", source="php", old_version="7.4.33-1.amzn2",
                           version=guard.BAOTA_AL2_VERSION + "-" + guard.BAOTA_AL2_RELEASE)
        self.plan = dict(updates=[self.update], blockers=[])
        self.preflight = dict(services=["php-fpm.service"], blockers=[])
        self.good = dict(ok=True, inventory=self.inv)
        for name, value in [("bi_private_dir", None), ("say", None), ("write_json", None),
                            ("collect_inventory", self.inv), ("bi_stage", []), ("bi_plan", self.plan),
                            ("service_preflight", self.preflight), ("acquire_repair_lock", None),
                            ("bi_save_receipt", {}), ("bi_assess", [{"status": "fixed"}]),
                            ("residual_process_check", {"ok": True})]:
            mock.patch.object(guard, name, return_value=value).start()
        mock.patch.object(guard.sys, "platform", "linux").start()
        mock.patch.object(guard.os, "geteuid", return_value=0).start()
        mock.patch.object(guard.os, "uname", return_value=("Linux", "host", "4", "4", "x86_64")).start()
        mock.patch.object(guard.os, "umask").start()
        mock.patch.object(guard.tempfile, "mkdtemp", return_value=self.tmp.name).start()
        self.transaction = mock.patch.object(guard, "bi_transaction", return_value=dict(ok=True, executed=True)).start()
        self.revalidate = mock.patch.object(guard, "repair_revalidate", return_value=self.good).start()
        self.backup = mock.patch.object(guard, "backup_configuration", return_value="backup").start()
        self.restart = mock.patch.object(guard, "restart_services", return_value=dict(ok=True)).start()
        self.health = mock.patch.object(guard, "health_checks", return_value=[]).start()

    def invoke(self, *flags):
        return guard.baota_install_main(["fix", "--build-report", "/build/build.json"] + list(flags))

    def test_fix_without_yes_only_previews_and_never_restarts(self):
        self.assertEqual(0, self.invoke())
        self.assertEqual(1, self.transaction.call_count)
        self.assertFalse(self.transaction.call_args.kwargs.get("execute", False))
        self.backup.assert_not_called(); self.restart.assert_not_called()

    def test_uncovered_php_service_prevents_even_transaction_preview(self):
        self.preflight["blockers"].append(dict(reason="unmapped PHP process", service=None))
        self.assertEqual(10, self.invoke("--yes"))
        self.transaction.assert_not_called(); self.backup.assert_not_called(); self.restart.assert_not_called()

    def test_changed_host_blocks_real_install(self):
        self.revalidate.return_value = dict(ok=False)
        self.assertEqual(10, self.invoke("--yes"))
        self.assertEqual(1, self.transaction.call_count)
        self.backup.assert_not_called(); self.restart.assert_not_called()

    def test_failed_after_check_never_explicitly_restarts(self):
        self.revalidate.side_effect = [self.good, dict(ok=False)]
        self.assertEqual(20, self.invoke("--yes"))
        self.assertEqual([False, True], [x.kwargs.get("execute", False) for x in self.transaction.call_args_list])
        self.restart.assert_not_called()

    def test_partial_transaction_never_restarts_or_issues_receipt(self):
        self.transaction.side_effect = [dict(ok=True, executed=False), dict(ok=False, executed=True)]
        self.assertEqual(20, self.invoke("--yes"))
        self.restart.assert_not_called(); guard.bi_save_receipt.assert_not_called()

    def test_already_installed_build_is_not_reinstalled_or_restarted(self):
        self.plan["updates"] = []
        self.assertEqual(0, self.invoke("--yes"))
        self.transaction.assert_not_called(); self.backup.assert_not_called(); self.restart.assert_not_called()
        guard.bi_save_receipt.assert_called_once()

    def test_already_installed_plan_does_not_write_acceptance_receipt(self):
        self.plan["updates"] = []
        self.assertEqual(0, self.invoke())
        self.transaction.assert_not_called(); guard.bi_save_receipt.assert_not_called()

    def test_success_runs_before_after_checks_then_restart_and_receipt(self):
        self.assertEqual(0, self.invoke("--yes"))
        self.assertEqual(2, self.revalidate.call_count)
        self.assertTrue(self.revalidate.call_args_list[-1].kwargs["after_update"])
        self.restart.assert_called_once_with(["php-fpm.service"])
        guard.bi_save_receipt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
