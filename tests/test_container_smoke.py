"""Validate disposable container smoke wiring without a Docker daemon/network."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/container_smoke.sh'


class ContainerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = self.root / 'docker-call.json'
        docker = self.root / 'docker'
        docker.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
                          'with open(os.environ["SMOKE_TEST_RECORD"], "w") as f:\n'
                          '    json.dump({"argv":sys.argv[1:], "stdin":sys.stdin.read()},f)\n'
                          'sys.exit(int(os.environ.get("SMOKE_TEST_EXIT", "0")))\n')
        docker.chmod(0o755)

    def run_smoke(self, args, code=0):
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ.get('PATH', ''),
                   SMOKE_TEST_RECORD=str(self.record), SMOKE_TEST_EXIT=str(code))
        return subprocess.run(['/bin/sh', str(SCRIPT)] + args, env=env,
                              capture_output=True, text=True, timeout=15)

    def test_readonly_mount_interactive_script_and_scope(self):
        result = self.run_smoke(['ubuntu:24.04', 'supported'])
        self.assertEqual(0, result.returncode, result.stderr)
        call = json.loads(self.record.read_text())
        self.assertEqual('run', call['argv'][0])
        self.assertIn('--rm', call['argv'])
        self.assertIn('--interactive', call['argv'])
        self.assertIn('linux/amd64', call['argv'])
        self.assertIn('type=bind,source=' + str(ROOT) + ',target=/workspace,readonly', call['argv'])
        self.assertIn('GUARD_SMOKE_EXPECTED=supported', call['argv'])
        self.assertEqual(['ubuntu:24.04', '/bin/sh', '-s'], call['argv'][-3:])
        self.assertIn('pg_bootstrap', call['stdin'])
        self.assertIn('./php74-patch.sh audit', call['stdin'])
        self.assertNotIn('./php74-patch.sh --yes', call['stdin'])
        self.assertNotIn('./php74-patch.sh fix', call['stdin'])
        self.assertIn("'php_install_tested': False", call['stdin'])

    def test_unsupported_platform_and_failure_code_are_preserved(self):
        result = self.run_smoke(['alpine:3.22', 'unsupported'], code=31)
        self.assertEqual(31, result.returncode)
        call = json.loads(self.record.read_text())
        self.assertIn('GUARD_SMOKE_EXPECTED=unsupported', call['argv'])
        self.assertLess(call['stdin'].index('unsupported platform identified'),
                        call['stdin'].index('pg_bootstrap'))

    def test_invalid_inputs_and_help_never_start_containers(self):
        for args, code in ((['--help'], 0), ([], 2), (['unknown:latest', 'supported'], 2),
                           (['ubuntu:24.04', 'maybe'], 2)):
            with self.subTest(args=args):
                result = self.run_smoke(args)
                self.assertEqual(code, result.returncode, result.stderr)
                self.assertFalse(self.record.exists())

    def test_workflow_uses_pinned_checkout_and_explicit_full_matrix(self):
        workflow = (ROOT / '.github/workflows/platforms.yml').read_text()
        images = re.findall(r'^\s+- image: (\S+)\s*$', workflow, re.MULTILINE)
        self.assertEqual({'ubuntu:20.04', 'ubuntu:22.04', 'ubuntu:24.04', 'ubuntu:26.04',
                          'debian:11', 'debian:12', 'debian:13', 'amazonlinux:2',
                          'amazonlinux:2023', 'rockylinux:8', 'rockylinux:9',
                          'rockylinux:10', 'alpine:3.22'}, set(images))
        self.assertIn('actions/checkout@11d5960a326750d5838078e36cf38b85af677262', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('It does not build or install PHP', workflow)
        self.assertIn('contents: read', workflow)


if __name__ == '__main__':
    unittest.main()
