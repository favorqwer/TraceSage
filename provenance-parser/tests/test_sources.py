import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dataclasses import replace  # noqa: E402

from provenance.adapters.scap.backends import (  # noqa: E402
    DockerScapSource,
    LocalScapSource,
    SshScapSource,
    WslScapSource,
    choose_backend,
    create_scap_source,
)
from provenance.adapters.scap.backends.base import stream_process_batches  # noqa: E402
from provenance.settings import Settings  # noqa: E402


class CommandTest(unittest.TestCase):
    def test_local_plain_template(self):
        src = LocalScapSource(
            __file__,
            format_string="A\tB",
            max_events=10,
            json_output=False,
            expression="evt.type=open",
        )
        cmd = src.command()
        self.assertEqual(cmd[0], "sysdig")
        self.assertNotIn("-j", cmd)
        self.assertIn("evt.type=open", cmd)
        self.assertEqual(cmd[cmd.index("-p") + 1], "A\tB")
        self.assertEqual(cmd[-2:], ["-n", "10"])

    def test_local_json_default(self):
        cmd = LocalScapSource(__file__).command()
        self.assertIn("-j", cmd)
        self.assertIn("-p", cmd)
        self.assertNotIn("-n", cmd)

    def test_wsl_uses_exec(self):
        cmd = WslScapSource(__file__, json_output=False).command()
        self.assertEqual(cmd[0], "wsl")
        self.assertIn("-e", cmd)
        self.assertNotIn("-j", cmd)

    def test_wsl_keeps_absolute_linux_path(self):
        cmd = WslScapSource("/mnt/e/data/capture.scap", json_output=False).command()
        self.assertIn("/mnt/e/data/capture.scap", cmd)
        self.assertNotIn("/mnt/e/mnt/e/data/capture.scap", cmd)

    def test_docker_mounts_parent(self):
        cmd = DockerScapSource(__file__, image="sysdig/sysdig:test").command()
        self.assertEqual(cmd[:2], ["docker", "run"])
        volume = cmd[cmd.index("-v") + 1]
        self.assertTrue(volume.endswith(":/data:ro"))
        self.assertIn("sysdig/sysdig:test", cmd)
        self.assertIn("/data/test_sources.py", cmd)

    def test_ssh_quotes_remote_command_and_uses_port(self):
        src = SshScapSource(
            "/remote/a b.scap",
            format_string="A\tB",
            json_output=False,
            host="example",
            user="ubuntu",
            port=2222,
        )
        with mock.patch.object(src, "_ensure_remote_scap", return_value="/remote/a b.scap"):
            cmd = src.command()
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("-p", cmd)
        self.assertIn("2222", cmd)
        self.assertEqual(cmd[-2], "ubuntu@example")
        remote = cmd[-1]
        self.assertIn("'/remote/a b.scap'", remote)
        self.assertIn(" -p ", remote)
        self.assertIn("'A\tB'", remote)


class SshSyncTest(unittest.TestCase):
    def test_uploads_when_remote_size_differs(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / "capture.scap"
            local.write_bytes(b"abc")
            src = SshScapSource(str(local), host="example", user="ubuntu", port=2222)
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if cmd[0] == "ssh" and "stat" in cmd[-1]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="-1", stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch(
                "provenance.adapters.scap.backends.ssh.subprocess.run", side_effect=fake_run
            ), redirect_stdout(io.StringIO()):
                remote = src._ensure_remote_scap()

            self.assertEqual(remote, f"/tmp/scap_cache/{Path(folder).name}_capture.scap")
            scp = [cmd for cmd in calls if cmd[0] == "scp"]
            self.assertEqual(len(scp), 1)
            self.assertIn("-P", scp[0])
            self.assertIn("2222", scp[0])

    def test_reuses_remote_when_size_matches(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / "capture.scap"
            local.write_bytes(b"abc")
            src = SshScapSource(str(local), host="example", user="ubuntu")
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if cmd[0] == "ssh" and "stat" in cmd[-1]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="3", stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch(
                "provenance.adapters.scap.backends.ssh.subprocess.run", side_effect=fake_run
            ), redirect_stdout(io.StringIO()):
                src._ensure_remote_scap()

            self.assertFalse([cmd for cmd in calls if cmd[0] == "scp"])


class FactoryTest(unittest.TestCase):
    def test_windows_prefers_wsl(self):
        readiness = {"local": True, "wsl": True, "ssh": True, "docker": True}
        self.assertEqual(choose_backend(readiness, "nt"), "wsl")

    def test_posix_prefers_local(self):
        readiness = {"local": True, "wsl": True, "ssh": True, "docker": True}
        self.assertEqual(choose_backend(readiness, "posix"), "local")

    def test_windows_falls_back_to_local(self):
        readiness = {"local": True, "wsl": False, "ssh": False, "docker": False}
        self.assertEqual(choose_backend(readiness, "nt"), "local")

    def test_no_backend_raises(self):
        with self.assertRaises(RuntimeError):
            choose_backend({}, "nt")

    def test_explicit_local(self):
        src = create_scap_source(__file__, backend="local", json_output=False)
        self.assertIsInstance(src, LocalScapSource)

    def test_explicit_ssh_needs_host(self):
        with self.assertRaises(ValueError):
            create_scap_source(__file__, backend="ssh")

    def test_auto_uses_readiness(self):
        readiness = {"local": False, "wsl": True, "ssh": False, "docker": False}
        with mock.patch(
            "provenance.adapters.scap.backends.factory.detect_available_backends",
            return_value=readiness,
        ):
            src = create_scap_source(__file__, backend="auto")
        self.assertIsInstance(src, WslScapSource)


class ConfigValidateTest(unittest.TestCase):
    def test_ssh_remote_path_is_not_required_locally(self):
        settings = Settings.from_env("s", "/remote/capture.scap", "h")
        settings = replace(
            settings,
            scap=replace(settings.scap, backend="ssh"),
            run=replace(settings.run, dry_run=True),
        )
        settings.validate()

    def test_explicit_local_missing_file_fails_early(self):
        settings = Settings.from_env("s", "definitely-missing.scap", "h")
        settings = replace(
            settings,
            scap=replace(settings.scap, backend="local"),
            run=replace(settings.run, dry_run=True),
        )
        with self.assertRaises(FileNotFoundError):
            settings.validate()


class BatchReaderTest(unittest.TestCase):
    def test_batches_and_stderr_on_failure(self):
        err = tempfile.TemporaryFile()
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; print('one'); print('two'); "
                "print('three'); sys.stderr.write('boom'); sys.exit(3)",
            ],
            stdout=subprocess.PIPE,
            stderr=err,
        )
        with self.assertRaises(RuntimeError) as ctx:
            list(
                stream_process_batches(
                    proc, queue_size=1, batch_size=2, stderr_file=err
                )
            )
        self.assertIn("exit=3", str(ctx.exception))
        self.assertIn("boom", str(ctx.exception))
        err.close()

    def test_successful_batches(self):
        err = tempfile.TemporaryFile()
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; [print(i) for i in range(5)]",
            ],
            stdout=subprocess.PIPE,
            stderr=err,
        )
        lines = list(
            stream_process_batches(proc, queue_size=1, batch_size=2, stderr_file=err)
        )
        self.assertEqual(
            [line.strip() for line in lines],
            [b"0", b"1", b"2", b"3", b"4"],
        )
        err.close()


if __name__ == "__main__":
    unittest.main()
