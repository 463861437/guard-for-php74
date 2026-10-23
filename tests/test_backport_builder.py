"""Offline safety regressions; no package installation, network, or host mutation."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "php_guard.py"
SPEC_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "php74-amzn2.spec"
SPEC = importlib.util.spec_from_file_location("php_guard_backport_under_test", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
# Exercise editable source without requiring a release-bundle regeneration.
BUILDER_SOURCE = SCRIPT.parent / 'src' / 'backport_builder.py'
exec(compile(BUILDER_SOURCE.read_text(), str(BUILDER_SOURCE), 'exec'), guard.__dict__)


def passing_selftest_log():
    names = ('rfc1867', 'rfc1867_inter', 'rfc1867_sid_cookie', 'rfc1867_sid_get',
             'rfc1867_sid_get_2', 'rfc1867_sid_invalid', 'rfc1867_sid_only_cookie',
             'rfc1867_sid_post')
    lines = ['XFAIL session upload progress [ext/session/tests/' + name + '.phpt]' for name in names]
    lines += ['TEST 10/100 [ext/session/tests/phpguard_upload_progress_disabled.phpt]\r'
              'PASS PHP Guard upload progress [ext/session/tests/phpguard_upload_progress_disabled.phpt]',
              'PASS OOM regression [tests/lang/bug45392.phpt]',
              'PASS date regression [ext/date/tests/bug33415-2.phpt]',
              'PASS SNI server regression [ext/openssl/tests/sni_server.phpt]',
              'PASS SNI key/cert regression [ext/openssl/tests/sni_server_key_cert.phpt]',
              'TEST RESULT SUMMARY', 'Number of tests : 100 80',
              'Tests skipped : 20 (20.0%) --------', 'Tests warned : 0 (0.0%) (0.0%)',
              'Tests failed : 0 (0.0%) (0.0%)', 'Expected fail : 8 (8.0%) (10.0%)',
              'Tests passed : 72 (72.0%) (90.0%)', 'Time taken : 10 seconds']
    return '\n'.join(lines) + '\n'


class OfflineBackportCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phpguard-backport-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        for name in ("run_cmd",):
            patch = mock.patch.object(guard, name, side_effect=AssertionError("unexpected host command"))
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(guard.subprocess, "Popen", side_effect=AssertionError("unexpected subprocess"))
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(guard, "say")
        self.say = patch.start()
        self.addCleanup(patch.stop)

    def prepare_args(self, target=None, **overrides):
        values = dict(output_dir=str(target or self.folder / "prepared"), srpm=None,
                      patch_file=None, key_file=None)
        values.update(overrides)
        return argparse.Namespace(**values)


class PinnedBackportInputTests(OfflineBackportCase):
    def test_pinned_srpm_patch_and_key_reject_bad_local_bytes_before_copy(self):
        bad = self.folder / "untrusted-input"
        bad.write_bytes(b"not the pinned upstream input")
        for name, digest in guard.bp_inputs(str(self.folder)):
            with self.subTest(input=name):
                destination = self.folder / name
                with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                    guard.bp_fetch(str(bad), "https://invalid.example/never-requested", digest,
                                   str(destination))
                self.assertFalse(destination.exists())

    def test_symlink_input_is_rejected_even_when_content_hash_matches(self):
        regular = self.folder / "content"
        regular.write_bytes(b"fixture")
        symlink = self.folder / "input-link"
        symlink.symlink_to(regular)
        with self.assertRaisesRegex(RuntimeError, "non-regular input"):
            guard.bp_verify(str(symlink), hashlib.sha256(b"fixture").hexdigest())

    def test_srpm_hash_failure_prevents_archive_tool_and_directory_creation(self):
        bad = self.folder / "bad.src.rpm"
        bad.write_bytes(b"bad RPM")
        target = self.folder / "extracted"
        with mock.patch.object(guard, "bp_tool", side_effect=AssertionError("archive tool must not run")):
            with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                guard.bp_extract_srpm(str(bad), str(target))
        self.assertFalse(target.exists())

    def test_real_pinned_spec_requires_selftests_and_applies_security_patch(self):
        original = SPEC_FIXTURE.read_bytes()
        self.assertEqual(guard.BP_SPEC_SHA, hashlib.sha256(original).hexdigest())
        rendered = guard.bp_render_spec(original).decode("utf-8")
        self.assertIn("Release: " + guard.BP_RELEASE, rendered)
        self.assertEqual(1, rendered.count("Patch200: " + guard.BP_PATCH))
        self.assertEqual(1, rendered.count("%patch200 -p1 -F0 -b .cve2026"))
        self.assertNotIn("  #exit 1\n", rendered)
        self.assertIn("  exit 1\n", rendered)
        self.assertIn(guard.BP_COMMIT, rendered)

    def test_changed_real_spec_is_rejected_before_best_effort_rewrite(self):
        original = SPEC_FIXTURE.read_bytes()
        for changed in (original + b"\n# local edit\n", original.replace(b"  #exit 1\n", b"  true\n", 1)):
            with self.subTest(hash=hashlib.sha256(changed).hexdigest()):
                with self.assertRaisesRegex(RuntimeError, "Unexpected SPEC"):
                    guard.bp_render_spec(changed)


class BackportTestGateTests(OfflineBackportCase):
    def test_build_commands_cannot_inherit_skip_selection_or_ignored_failures(self):
        inherited = dict((name, 'untrusted-test-setting') for name in (
            'MAKEFLAGS', 'MFLAGS', 'GNUMAKEFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES', 'MAKEFILES',
            'TESTS', 'TEST_PHP_ARGS', 'TEST_PHP_EXECUTABLE', 'TEST_PHP_CGI_EXECUTABLE',
            'TEST_PHPDBG_EXECUTABLE', 'TEST_PHP_WORKER', 'TEST_PHP_JUNIT',
            'PHP_TEST_SETTINGS', 'PHP_EXECUTABLE', 'PHPRC', 'PHP_INI_SCAN_DIR',
            'SHOW_ONLY_GROUPS', 'NO_PHPTEST_SUMMARY', 'REPORT_EXIT_STATUS',
            'NO_INTERACTION', 'SKIP_SLOW_TESTS', 'SKIP_ONLINE_TESTS'))
        inherited.update({'USE_ZEND_ALLOC': '0', 'SAFE_BUILD_SETTING': 'preserved'})
        proc = mock.Mock(returncode=0)
        proc.communicate.return_value = (b'', b'')
        for log in (None, str(self.folder / 'command.log')):
            with self.subTest(log=log), mock.patch.dict(guard.os.environ, inherited):
                with mock.patch.object(guard.subprocess, 'Popen', return_value=proc) as command, \
                     mock.patch.object(guard, 'bm_run', return_value='') as monitored:
                    guard.bp_call(['/usr/bin/rpmbuild', '-ba', 'fixture.spec'], log=log)
                env = (monitored if log else command).call_args.kwargs['env']
                self.assertFalse((set(inherited) - {'USE_ZEND_ALLOC', 'SAFE_BUILD_SETTING'}) & set(env))
                self.assertEqual('1', env['USE_ZEND_ALLOC'])
                self.assertEqual('preserved', env['SAFE_BUILD_SETTING'])
                self.assertEqual('untrusted-test-setting', guard.os.environ['MAKEFLAGS'])

    def check_summary(self, value):
        path = self.folder / 'build.log'
        path.write_text(value)
        return guard.bp_selftest_summary(str(path))

    def test_complete_summary_and_all_critical_regressions_are_recorded(self):
        result = self.check_summary(passing_selftest_log())
        self.assertEqual(100, result['total'])
        self.assertEqual(72, result['passed'])
        self.assertEqual(8, result['xfailed'])
        self.assertEqual(13, len(result['critical_regressions']))

    def test_existing_upstream_xfails_and_skips_remain_allowed(self):
        value = passing_selftest_log().replace('Expected fail : 8 ', 'Expected fail : 41 ')
        value = value.replace('Tests passed : 72 ', 'Tests passed : 39 ')
        result = self.check_summary(value)
        self.assertEqual(41, result['xfailed'])
        self.assertEqual(20, result['skipped'])

    def test_zero_command_exit_cannot_hide_failed_borked_or_leaked_tests(self):
        valid = passing_selftest_log()
        for value in (valid.replace('Tests failed : 0', 'Tests failed : 1'),
                      valid.replace('Tests failed : 0', 'Tests borked : 1\nTests failed : 0'),
                      valid.replace('Tests failed : 0', 'Tests leaked : 1\nTests failed : 0')):
            with self.subTest(log=value):
                with self.assertRaisesRegex(RuntimeError, 'failing or inconsistent summary'):
                    self.check_summary(value)

    def test_missing_partial_selected_empty_or_inconsistent_summaries_fail(self):
        valid = passing_selftest_log()
        cases = ('', 'No tests were run.\n', valid.replace('TEST RESULT SUMMARY\n', ''),
                 valid.replace('Time taken : 10 seconds\n', ''),
                 valid.replace('Tests passed : 72 (72.0%) (90.0%)\n', ''),
                 valid.replace('Number of tests : 100 80', 'Number of tests : 101 81'),
                 valid.replace('Number of tests : 100 80', 'Number of tests : 0 0'),
                 valid + valid)
        for value in cases:
            with self.subTest(log=value):
                with self.assertRaisesRegex(RuntimeError, 'PHP regression tests failed'):
                    self.check_summary(value)

    def test_skipped_missing_or_changed_critical_results_fail(self):
        valid = passing_selftest_log()
        for before, after in (('PASS PHP Guard', 'SKIP PHP Guard'),
                              ('PASS OOM regression', 'FAIL OOM regression'),
                              ('XFAIL session upload progress', 'PASS session upload progress'),
                              ('[tests/lang/bug45392.phpt]', '[tests/lang/unrelated.phpt]')):
            with self.subTest(change=before):
                with self.assertRaisesRegex(RuntimeError, 'required PASS/XFAIL'):
                    self.check_summary(valid.replace(before, after, 1))

    def test_corrected_date_and_openssl_regressions_each_require_pass(self):
        valid = passing_selftest_log()
        for name in ('ext/date/tests/bug33415-2.phpt',
                     'ext/openssl/tests/sni_server.phpt',
                     'ext/openssl/tests/sni_server_key_cert.phpt'):
            line = next(value for value in valid.splitlines() if '[' + name + ']' in value)
            for status in ('SKIP', 'FAIL', 'XFAIL', None):
                with self.subTest(test=name, status=status):
                    replacement = '' if status is None else line.replace('PASS ', status + ' ', 1)
                    with self.assertRaisesRegex(RuntimeError, 'required PASS/XFAIL'):
                        self.check_summary(valid.replace(line, replacement, 1))


class BackportPrepareTests(OfflineBackportCase):
    def test_prepare_refuses_existing_directory_and_symlink_without_overwrite(self):
        existing = self.folder / "existing"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("original")
        symlink = self.folder / "link"
        symlink.symlink_to(existing, target_is_directory=True)
        with mock.patch.object(guard, "bp_fetch", side_effect=AssertionError("must not fetch")):
            for target in (existing, symlink):
                with self.subTest(target=str(target)):
                    with self.assertRaisesRegex(RuntimeError, "already exists"):
                        guard.bp_prepare(self.prepare_args(target))
        self.assertEqual("original", marker.read_text())
        self.assertEqual([marker], list(existing.iterdir()))

    def test_prepare_bad_input_records_failure_and_never_claims_built_or_deployed(self):
        source = self.folder / "bad.src.rpm"
        source.write_bytes(b"corrupt SRPM")
        args = self.prepare_args(srpm=str(source))
        with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
            guard.bp_prepare(args)
        report = json.loads((pathlib.Path(args.output_dir) / "prepare.json").read_text())
        self.assertEqual("prepare_failed", report["state"])
        self.assertFalse(report["deployed"])
        self.assertIn("SHA256 mismatch", report["error"])
        self.assertNotIn("artifacts", report)
        self.assertFalse((pathlib.Path(args.output_dir) / "preview").exists())


class BackportHostAndCliTests(OfflineBackportCase):
    def test_build_rejects_root_other_systems_and_architectures_before_build_actions(self):
        cases = (("darwin", 1000, "ID=amzn\nVERSION_ID=2\n", "x86_64", "Amazon Linux 2"),
                 ("linux", 0, "ID=amzn\nVERSION_ID=2\n", "x86_64", "not as root"),
                 ("linux", 1000, "ID=ubuntu\nVERSION_ID=22.04\n", "x86_64", "only supports"),
                 ("linux", 1000, "ID=amzn\nVERSION_ID=2023\n", "x86_64", "only supports"),
                 ("linux", 1000, "ID=amzn\nVERSION_ID=2\n", "aarch64", "only supports"))
        for platform, uid, release, arch, message in cases:
            with self.subTest(platform=platform, uid=uid, release=release, arch=arch):
                with mock.patch.object(guard.sys, "platform", platform), \
                        mock.patch.object(guard.os, "geteuid", return_value=uid), \
                        mock.patch.object(guard.os, "uname", return_value=("Linux", "fixture", "", "", arch)), \
                        mock.patch("builtins.open", mock.mock_open(read_data=release)), \
                        mock.patch.object(guard, "bp_verify", side_effect=AssertionError("must not inspect inputs")), \
                        mock.patch.object(guard, "bp_tool", side_effect=AssertionError("must not find build tools")):
                    with self.assertRaisesRegex(RuntimeError, message):
                        guard.bp_build(argparse.Namespace(work_dir=str(self.folder), jobs=2))
        self.assertEqual([], list(self.folder.iterdir()))

    def test_cli_rejects_conflicting_missing_and_out_of_range_arguments(self):
        invalid = (["prepare"], ["build"],
                   ["prepare", "--output-dir", "a", "--work-dir", "b"],
                   ["build", "--work-dir", "a", "--output-dir", "b"],
                   ["build", "--work-dir", "a", "--srpm", "input"],
                   ["build", "--work-dir", "a", "--patch-file", "input"],
                   ["build", "--work-dir", "a", "--key-file", "input"],
                   ["build", "--work-dir", "a", "--jobs", "0"],
                   ["build", "--work-dir", "a", "--jobs", "65"],
                   ["build", "--work-dir", "a", "--jobs", "two"])
        with mock.patch.object(guard, "bp_prepare", side_effect=AssertionError("must not prepare")), \
                mock.patch.object(guard, "bp_build", side_effect=AssertionError("must not build")):
            for argv in invalid:
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        guard.backport_main(argv)
                    self.assertEqual(2, error.exception.code)

    def test_cli_failure_returns_nonzero_without_success_message(self):
        with mock.patch.object(guard, "bp_prepare", side_effect=RuntimeError("pinned input rejected")):
            result = guard.backport_main(["prepare", "--output-dir", str(self.folder / "new")])
        self.assertEqual(20, result)
        self.assertIn("pinned input rejected", self.say.call_args.args[0])


class BackportSmokeTests(OfflineBackportCase):
    def setUp(self):
        super().setUp()
        self.sapis = ("build-apache", "build-ztscli")
        for sapi in self.sapis:
            php = self.folder / "BUILD" / "php-7.4.33" / sapi / "sapi" / "cli" / "php"
            php.parent.mkdir(parents=True)
            php.write_bytes(b"unexecuted CLI fixture")
        self.version_ok = {"code": 0, "stdout": "7.4.33", "stderr": ""}
        self.oom_ok = {"code": 1, "stdout": "", "stderr": "PHP Fatal error: Allowed memory size of 16777216 bytes exhausted"}

    def test_both_sapis_require_version_and_controlled_oom_without_shutdown(self):
        with mock.patch.object(guard, "run_cmd", side_effect=[self.version_ok, self.oom_ok] * 2) as command:
            results = guard.bp_smoke_tests(str(self.folder))
        self.assertEqual(list(self.sapis), [result["sapi"] for result in results])
        self.assertTrue(all(result["oom_exit"] == 1 and result["shutdown_callback_ran"] is False
                            for result in results))
        self.assertEqual(4, command.call_count)
        for call in command.call_args_list[1::2]:
            self.assertIn("memory_limit=16M", call.args[0])
            self.assertIn("-n", call.args[0])
            self.assertEqual(15, call.kwargs["timeout"])
            self.assertEqual({"USE_ZEND_ALLOC": "1"}, call.kwargs["env"])

    def test_unpatched_shutdown_behavior_fails_for_either_sapi_and_output_stream(self):
        for branch in range(2):
            for stream in ("stdout", "stderr"):
                with self.subTest(sapi=self.sapis[branch], stream=stream):
                    unpatched = dict(self.oom_ok)
                    unpatched[stream] += "PHP_GUARD_SHUTDOWN_RAN"
                    responses = [self.version_ok, self.oom_ok] * branch + [self.version_ok, unpatched]
                    with mock.patch.object(guard, "run_cmd", side_effect=responses):
                        with self.assertRaisesRegex(RuntimeError, "OOM immediate-exit.*" + self.sapis[branch]):
                            guard.bp_smoke_tests(str(self.folder))

    def test_wrong_exit_timeout_or_fatal_in_wrong_stream_cannot_pass(self):
        failures = [dict(self.oom_ok, code=code) for code in (0, 255, 124)]
        failures += [dict(self.oom_ok, stderr=""),
                     dict(self.oom_ok, stdout=self.oom_ok["stderr"], stderr="")]
        for branch in range(2):
            for failed in failures:
                with self.subTest(sapi=self.sapis[branch], result=failed):
                    responses = [self.version_ok, self.oom_ok] * branch + [self.version_ok, failed]
                    with mock.patch.object(guard, "run_cmd", side_effect=responses):
                        with self.assertRaisesRegex(RuntimeError, "OOM immediate-exit.*" + self.sapis[branch]):
                            guard.bp_smoke_tests(str(self.folder))

    def test_wrong_version_or_version_timeout_stops_before_oom(self):
        for failed in (dict(self.version_ok, stdout="7.4.32"), dict(self.version_ok, code=124)):
            with self.subTest(result=failed):
                with mock.patch.object(guard, "run_cmd", return_value=failed) as command:
                    with self.assertRaisesRegex(RuntimeError, "version smoke test failed"):
                        guard.bp_smoke_tests(str(self.folder))
                self.assertEqual(1, command.call_count)


class BackportBuildFailureTests(OfflineBackportCase):
    def setUp(self):
        super().setUp()
        self.inputs = self.folder / "inputs"
        self.inputs.mkdir()
        # These are command-boundary stubs, not trusted test inputs. Pinning is
        # exercised separately above without mocking hashes or digest constants.
        for name, _ in guard.bp_inputs(str(self.folder)):
            (self.inputs / name).write_bytes(b"external-command stub")
        self.args = argparse.Namespace(work_dir=str(self.folder), jobs=2)

    def extract_fixture(self, source, destination):
        target = pathlib.Path(destination)
        target.mkdir()
        shutil.copyfile(str(SPEC_FIXTURE), str(target / "php.spec"))

    def run_mock_build(self, compile_error=None, signature_ok=True, omit_package=None,
                       smoke_error=None, selftest_log=None):
        def command(argv, log=None, cwd=None, data=None):
            if "--checksig" in argv:
                return "Header V4 RSA/SHA256 Signature, key ID c87f5b1a: OK" if signature_ok else "NOT OK"
            if "-ba" in argv:
                if compile_error:
                    raise RuntimeError(compile_error)
                pathlib.Path(log).write_text(passing_selftest_log() if selftest_log is None else selftest_log)
                top = pathlib.Path(argv[-1]).parent.parent
                rpms = top / "RPMS" / "x86_64"
                rpms.mkdir()
                for name in guard.BP_CORE_NAMES - {omit_package}:
                    (rpms / (name + ".rpm")).write_bytes(b"built RPM command stub")
                (top / "SRPMS" / ("php-7.4.33-" + guard.BP_RELEASE + ".src.rpm")).write_bytes(b"source RPM stub")
            if "-qp" in argv:
                name = pathlib.Path(argv[-1]).stem
                return "\t".join((name, "7.4.33", guard.BP_RELEASE, "x86_64",
                                  "php-7.4.33-" + guard.BP_RELEASE + ".src.rpm"))
            return ""

        def smoke(top):
            if smoke_error:
                raise RuntimeError(smoke_error)
            return [{"sapi": "build-apache", "version": "7.4.33", "oom_exit": 1,
                     "shutdown_callback_ran": False},
                    {"sapi": "build-ztscli", "version": "7.4.33", "oom_exit": 1,
                     "shutdown_callback_ran": False}]

        with mock.patch.object(guard, "bp_host_check"), \
                mock.patch.object(guard, "bp_verify"), \
                mock.patch.object(guard, "bp_tool", side_effect=lambda name: "/usr/bin/" + name), \
                mock.patch.object(guard, "bp_extract_srpm", side_effect=self.extract_fixture), \
                mock.patch.object(guard, "bp_smoke_tests", side_effect=smoke), \
                mock.patch.object(guard, "bp_call", side_effect=command) as commands:
            with self.assertRaises(RuntimeError) as error:
                guard.bp_build(self.args)
        reports = list(self.folder.glob("build-*/build.json"))
        self.assertEqual(1, len(reports))
        return json.loads(reports[0].read_text()), commands, str(error.exception)

    def assert_failed_not_deployed(self, report):
        self.assertEqual("build_failed", report["state"])
        self.assertFalse(report["deployed"])
        self.assertFalse(report["signed"])
        self.assertTrue(report["tests_required"])
        self.assertNotEqual("complete", report.get("stage"))
        self.assertNotEqual(True, report.get("php_selftests_passed"))
        self.assertNotIn("artifacts", report)

    def test_php_selftest_failure_cannot_mark_build_complete(self):
        report, commands, error = self.run_mock_build(compile_error="PHP regression tests failed (exit 1)")
        self.assert_failed_not_deployed(report)
        self.assertEqual("compile_test_package", report["stage"])
        self.assertIn("regression tests failed", report["error"])
        self.assertEqual(error, report["error"])
        self.assertFalse(any("-qp" in call.args[0] for call in commands.call_args_list))
        build_command = next(call.args[0] for call in commands.call_args_list if "-ba" in call.args[0])
        self.assertIn("runselftest 1", build_command)

    def test_missing_core_package_blocks_completion_and_records_failure(self):
        report, _, error = self.run_mock_build(omit_package="php-fpm")
        self.assert_failed_not_deployed(report)
        self.assertIn("Incomplete core package set: php-fpm", error)
        self.assertEqual(error, report["error"])

    def test_successful_rpmbuild_cannot_accept_failing_or_missing_test_summary(self):
        log = passing_selftest_log().replace('Tests failed : 0', 'Tests failed : 1')
        report, commands, error = self.run_mock_build(selftest_log=log)
        self.assert_failed_not_deployed(report)
        self.assertEqual('verify_selftest_results', report['stage'])
        self.assertIn('failing or inconsistent summary', error)
        self.assertFalse(any('-qp' in call.args[0] for call in commands.call_args_list))

    def test_successful_rpmbuild_with_no_tests_never_marks_selftests_passed(self):
        report, commands, error = self.run_mock_build(selftest_log='No tests were run.\n')
        self.assert_failed_not_deployed(report)
        self.assertEqual('verify_selftest_results', report['stage'])
        self.assertIn('full-suite summary missing', error)
        self.assertFalse(any('-qp' in call.args[0] for call in commands.call_args_list))

    def test_failed_mitigation_smoke_test_prevents_artifact_acceptance(self):
        report, commands, error = self.run_mock_build(smoke_error="OOM immediate-exit smoke test failed: build-ztscli")
        self.assert_failed_not_deployed(report)
        self.assertEqual("mitigation_smoke_tests", report["stage"])
        self.assertEqual(error, report["error"])
        self.assertFalse(any("-qp" in call.args[0] for call in commands.call_args_list))

    def test_unconfirmed_aws_signature_stops_before_extracting_or_compiling(self):
        report, commands, error = self.run_mock_build(signature_ok=False)
        self.assert_failed_not_deployed(report)
        self.assertIn("Expected AWS RPM signature not confirmed", error)
        self.assertNotEqual(True, report.get("rpm_signature_verified"))
        self.assertFalse(any("-bp" in call.args[0] or "-ba" in call.args[0]
                             for call in commands.call_args_list))
        self.assertFalse(list(self.folder.glob("build-*/rpmbuild")))

    def test_build_rechecks_prepared_inputs_before_any_external_tool(self):
        with mock.patch.object(guard, "bp_host_check"), \
                mock.patch.object(guard, "bp_tool", side_effect=AssertionError("must not find tools")):
            with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                guard.bp_build(self.args)
        self.assertFalse(list(self.folder.glob("build-*")))


if __name__ == "__main__":
    unittest.main()
