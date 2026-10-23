"""Legacy systemd EnvironmentFile fields and conservative empty-file checks."""
import copy
import errno
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("legacy_environment_guard", ROOT / "php_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
for module in ("service_ops", "cli"):
    exec(compile((ROOT / ("src/" + module + ".py")).read_text(), module, "exec"), guard.__dict__)


def properties(**overrides):
    values = dict(Id="php-fpm.service", LoadState="loaded", ActiveState="active",
                  ExecStart="{ path=/usr/sbin/php-fpm ; argv[]=/usr/sbin/php-fpm --nodaemonize ; }",
                  Environment="", RootDirectory="", WorkingDirectory="", User="", Group="")
    values.update(overrides)
    return values


def response(values=None, suffix="", code=0):
    text = "\n".join(key + "=" + value for key, value in (values or {}).items())
    return dict(code=code, stdout=text + ("\n" + suffix if suffix else ""), stderr="")


class LegacyEnvironmentPropertyTests(unittest.TestCase):
    def show(self, values, suffix="", first_failure=True):
        replies = ([response(code=1)] if first_failure else []) + [response(values, suffix)]
        with mock.patch.object(guard, "run_cmd", side_effect=replies) as command:
            result = guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertTrue(all(call.args[0][1] == "show" for call in command.call_args_list))
        return result

    def test_real_219_singular_environmentfile_is_preserved(self):
        entry = "/etc/sysconfig/php-fpm (ignore_errors=yes)"
        result = self.show(properties(), "EnvironmentFile=" + entry)
        self.assertEqual(entry, result["EnvironmentFiles"])
        self.assertNotIn("EnvironmentFile", result)

    def test_repeated_singular_plural_and_empty_values_never_discard_a_reference(self):
        first = "/etc/sysconfig/php-fpm (ignore_errors=yes)"
        second = "/etc/php-fpm-private (ignore_errors=no)"
        cases = [
            "EnvironmentFile=" + first + "\nEnvironmentFile=" + second,
            "EnvironmentFiles=" + first + "\nEnvironmentFile=" + second,
            "EnvironmentFile=" + first + "\nEnvironmentFiles=\nEnvironmentFile=" + second,
            "EnvironmentFiles=" + first + "\nEnvironmentFiles=" + second + "\nEnvironmentFiles=",
        ]
        for suffix in cases:
            with self.subTest(suffix=suffix):
                result = self.show(properties(), suffix)
                self.assertEqual([first, second], result["EnvironmentFiles"].splitlines())

    def test_plural_references_are_preserved_in_successful_initial_query(self):
        value = "/etc/default/php-fpm (ignore_errors=no)"
        result = self.show(properties(RootImage="", EnvironmentFiles=value), first_failure=False)
        self.assertEqual(value, result["EnvironmentFiles"])

    def test_missing_whitelisted_fields_are_named_without_echoing_other_properties(self):
        values = properties(EnvironmentFile="/etc/sysconfig/php-fpm (ignore_errors=yes)")
        del values["User"]
        del values["Group"]
        values["Description"] = "PRIVATE_DESCRIPTION"
        with mock.patch.object(guard, "run_cmd", side_effect=[response(code=1), response(values)]):
            with self.assertRaises(ValueError) as failure:
                guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        message = str(failure.exception)
        self.assertIn("User", message)
        self.assertIn("Group", message)
        self.assertNotIn("PRIVATE_DESCRIPTION", message)
        self.assertNotIn("/etc/sysconfig/php-fpm", message)

    def test_similarly_named_unknown_property_is_not_accepted_as_environmentfiles(self):
        values = properties(EnvironmentFileUnknown="PRIVATE_VALUE")
        with mock.patch.object(guard, "run_cmd", side_effect=[response(code=1), response(values), response(code=1)]):
            with self.assertRaises(ValueError) as failure:
                guard._svc_show("/usr/bin/systemctl", "php-fpm.service")
        self.assertIn("EnvironmentFiles", str(failure.exception))
        self.assertNotIn("PRIVATE_VALUE", str(failure.exception))


class EmptyEnvironmentFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=str(ROOT))
        self.addCleanup(self.temporary.cleanup)
        self.folder = pathlib.Path(self.temporary.name)
        self.original_lstat = os.lstat
        self.original_fstat = os.fstat
        self.foreign_inodes = set()

        def metadata(value, parent=False):
            fields = list(value)
            fields[4] = 12345 if value.st_ino in self.foreign_inodes else 0
            fields[5] = 0
            if parent:
                fields[0] &= ~0o022
            return os.stat_result(fields)

        def lstat(path, *args, **kwargs):
            value = self.original_lstat(path, *args, **kwargs)
            inside = str(path) == str(self.folder) or str(path).startswith(str(self.folder) + os.sep)
            return metadata(value, parent=not inside)

        patches = [mock.patch.object(guard.os, "lstat", side_effect=lstat),
                   mock.patch.object(guard.os, "fstat", side_effect=lambda fd: metadata(self.original_fstat(fd))),
                   mock.patch.object(guard, "run_cmd", side_effect=AssertionError("unexpected host command"))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def file(self, name="php-fpm", content="# Default Remi PHP-FPM environment\n\n", mode=0o644):
        path = self.folder / name
        path.write_text(content)
        path.chmod(mode)
        return path

    def env(self, path, optional=False):
        return str(path) + " (ignore_errors=" + ("yes" if optional else "no") + ")"

    def check(self, entries, environment=""):
        return guard._svc_require_empty_environment(dict(Environment=environment, EnvironmentFiles=entries))

    def assert_rejected(self, entries, secret=None, environment=""):
        with self.assertRaises((ValueError, OSError)) as failure:
            self.check(entries, environment=environment)
        if secret:
            self.assertNotIn(secret, str(failure.exception))

    def test_comment_only_default_and_empty_files_are_accepted(self):
        first = self.file(content="# REMI default\n  # Another comment\n; Comment\n\n")
        second = self.file("empty", content=" \t\n")
        self.check(self.env(first))
        self.check(self.env(first) + "\n" + self.env(second))

    def test_active_environment_property_still_blocks_even_with_empty_file(self):
        path = self.file()
        self.assert_rejected(self.env(path), environment="PRIVATE_NAME=PRIVATE_VALUE", secret="PRIVATE_VALUE")

    def test_assignments_continuations_or_unknown_content_are_not_evaluated_or_reported(self):
        for content in ("PHPRC=/etc/private-php\n", "SECRET=DO_NOT_DISCLOSE\n",
                        "SECRET=$(touch /UNAUTHORIZED_SIDE_EFFECT)\n", "export SECRET=DO_NOT_DISCLOSE\n",
                        "\\\nSECRET=DO_NOT_DISCLOSE\n", '"SECRET=DO_NOT_DISCLOSE"\n', "unexpected bare words\n",
                        "# Comment\rPHPRC=/private\n", "# Comment\\\n", "# Comment\x00\n"):
            with self.subTest(content=content):
                path = self.file(content=content)
                self.assert_rejected(self.env(path), secret="DO_NOT_DISCLOSE")

    def test_all_referenced_files_are_checked_not_just_first_or_last(self):
        first = self.file("first")
        second = self.file("second", "SECRET=DO_NOT_DISCLOSE\n")
        third = self.file("third")
        self.assert_rejected("\n".join(self.env(path) for path in (first, second, third)), secret="DO_NOT_DISCLOSE")

    def test_unknown_environment_file_serializations_are_rejected(self):
        path = self.file()
        for entry in (str(path), "-" + self.env(path), self.env(path) + " trailing",
                      "relative/file (ignore_errors=yes)", self.env(path).replace("no)", "maybe)"),
                      '"' + str(path) + '" (ignore_errors=no)',
                      str(path) + "\\x20name (ignore_errors=yes)"):
            with self.subTest(entry=entry):
                self.assert_rejected(entry)

    def test_required_missing_file_blocks_but_optional_missing_under_trusted_parent_passes(self):
        absent = self.folder / "missing"
        self.assert_rejected(self.env(absent))
        self.check(self.env(absent, optional=True))

    def test_optional_missing_file_under_writable_parent_is_not_trusted(self):
        parent = self.folder / "writable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.assert_rejected(self.env(parent / "absent", optional=True))

    def test_optional_missing_file_under_foreign_owned_parent_is_not_trusted(self):
        self.foreign_inodes.add(self.original_lstat(self.folder).st_ino)
        self.assert_rejected(self.env(self.folder / "absent", optional=True))

    def test_unreadable_optional_file_is_not_treated_as_missing(self):
        path = self.file()
        with mock.patch.object(guard.os, "open", side_effect=OSError(errno.EACCES, "PRIVATE_PATH")):
            self.assert_rejected(self.env(path, optional=True), secret="PRIVATE_PATH")

    def test_large_comment_only_file_still_requires_manual_inspection(self):
        path = self.file(content="#" + ("x" * 65536))
        self.assert_rejected(self.env(path))

    def test_file_replaced_after_trusted_path_check_is_rejected(self):
        path = self.file("original")
        replacement = self.file("replacement")
        open_file = guard.os.open

        def replace_and_open(name, flags):
            if name == str(path):
                os.replace(replacement, path)
            return open_file(name, flags)

        with mock.patch.object(guard.os, "open", side_effect=replace_and_open):
            self.assert_rejected(self.env(path))

    def test_file_changed_while_reading_is_rejected_even_when_both_versions_are_comments(self):
        path = self.file(content="# Original\n")
        read_file = guard.os.read
        changed = []

        def mutate_during_read(fd, size):
            content = read_file(fd, size)
            if content and not changed:
                changed.append(True)
                path.write_text("# New longer comment-only version\n")
            return content

        with mock.patch.object(guard.os, "read", side_effect=mutate_during_read):
            self.assert_rejected(self.env(path))

    def test_path_replaced_while_reading_old_comment_file_is_rejected(self):
        path = self.file("original", content="# Original\n")
        replacement = self.file("replacement", content="PHPRC=/private/config\n")
        read_file = guard.os.read
        changed = []

        def replace_during_read(fd, size):
            content = read_file(fd, size)
            if content and not changed:
                changed.append(True)
                os.replace(replacement, path)
            return content

        with mock.patch.object(guard.os, "read", side_effect=replace_during_read):
            self.assert_rejected(self.env(path))

    def test_writable_or_foreign_owned_files_are_rejected(self):
        for mode in (0o664, 0o646, 0o666):
            with self.subTest(mode=oct(mode)):
                path = self.file(mode=mode)
                self.assert_rejected(self.env(path))
        path = self.file(mode=0o644)
        self.foreign_inodes.add(self.original_lstat(path).st_ino)
        self.assert_rejected(self.env(path))

    def test_symlink_leaf_or_parent_and_nonregular_file_are_rejected(self):
        real = self.file()
        link = self.folder / "link"
        link.symlink_to(real)
        self.assert_rejected(self.env(link))
        directory = self.folder / "directory"
        directory.mkdir()
        inside = directory / "real"
        inside.write_text("# Empty\n")
        alias = self.folder / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        self.assert_rejected(self.env(alias / "real"))
        self.assert_rejected(self.env(directory))

    def test_php_fpm_preflight_accepts_verified_empty_environment_file(self):
        props = properties(EnvironmentFiles=self.env(self.file()))
        with mock.patch.object(guard, "_inv_trusted_executable", return_value=(True, None)), \
             mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(["/usr/sbin/php-fpm", "-t"], guard._svc_fpm_test_argv(props))

    def test_changed_environment_file_is_rechecked_before_deployment(self):
        path = self.file()
        props = properties(EnvironmentFiles=self.env(path))
        inv = dict(os=dict(id="centos", version_id="7"), package_manager="yum", packages=[],
                   services=[dict(name="php-fpm.service", active="active")], processes=[],
                   runtimes=[], containers=[], warnings=[])
        with mock.patch.object(guard, "_inv_tool", return_value="/usr/bin/systemctl"), \
             mock.patch.object(guard, "_svc_show", return_value=props), \
             mock.patch.object(guard, "_inv_trusted_executable", return_value=(True, None)), \
             mock.patch.object(guard, "collect_inventory", return_value=copy.deepcopy(inv)), \
             mock.patch.object(guard, "assess_inventory", return_value=[]), \
             mock.patch.object(guard, "check_package_integrity", return_value=[]), \
             mock.patch.object(guard, "run_cmd", return_value=response()) as command, \
             mock.patch.dict(os.environ, {}, clear=True):
            before = guard.service_preflight(inv, [], [])
            self.assertEqual([], before["blockers"], before)
            self.assertEqual(["php-fpm.service"], before["services"])
            path.write_text("SECRET=CHANGED_AFTER_PLAN\n")
            result = guard.repair_revalidate(inv, [], before["services"], {})
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["preflight"]["blockers"])
        self.assertNotIn("CHANGED_AFTER_PLAN", repr(result["preflight"]["blockers"]))
        command.assert_called_once_with(["/usr/sbin/php-fpm", "-t"], timeout=60)


if __name__ == "__main__":
    unittest.main()
