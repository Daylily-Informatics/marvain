from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

from marvain_cli.config import ResolvedEnv
from marvain_cli.ops import (
    Ctx,
    GUI_DEFAULT_HOST,
    GUI_DEFAULT_PORT,
    GUI_LOG_FILENAME,
    GUI_PID_FILENAME,
    _get_gui_log_file,
    _get_gui_pid_file,
    _is_port_in_use,
    _is_process_running,
    _read_pid_file,
    _remove_pid_file,
    _split_sql,
    _write_pid_file,
    bootstrap,
    cognito_admin_create_user,
    cognito_admin_delete_user,
    gui_logs,
    gui_restart,
    gui_start,
    gui_status,
    gui_stop,
    hub_claim_first_owner,
    init_db,
    sam_logs,
)


class TestOps(unittest.TestCase):
    def test_split_sql_ignores_comment_lines_and_splits(self) -> None:
        sql = """-- comment\nCREATE TABLE a(x int);\n\n-- another\nCREATE TABLE b(y int);"""
        stmts = _split_sql(sql)
        self.assertEqual(len(stmts), 2)
        self.assertTrue(stmts[0].startswith("CREATE TABLE a"))
        self.assertTrue(stmts[1].startswith("CREATE TABLE b"))

    def test_bootstrap_casts_uuid_params_for_rds_data_api(self) -> None:
        captured_sql: list[str] = []

        def fake_rds_execute(*_args, **kwargs):
            captured_sql.append(str(kwargs.get("sql")))
            idx = len(captured_sql)
            if idx == 1:
                v = "11111111-1111-1111-1111-111111111111"
            elif idx == 2:
                v = "22222222-2222-2222-2222-222222222222"
            else:
                v = "33333333-3333-3333-3333-333333333333"
            return {"records": [[{"stringValue": v}]]}

        cfg = {"envs": {"dev": {"bootstrap": {}}}}
        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg=cfg,
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with (
            mock.patch("marvain_cli.ops._conda_preflight", return_value=0),
            mock.patch("marvain_cli.ops._db_outputs", return_value=("db", "sec", "name")),
            mock.patch("marvain_cli.ops._rds_execute", side_effect=fake_rds_execute),
            mock.patch("marvain_cli.ops._eprint"),
            mock.patch("marvain_cli.ops.save_config_dict"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = bootstrap(
                ctx,
                dry_run=False,
                agent_name="Forge",
                space_name="home",
                device_name="dev",
                force=False,
            )

        self.assertEqual(rc, 0)
        self.assertTrue(any("INSERT INTO spaces" in s and "CAST(:a AS uuid)" in s for s in captured_sql))
        self.assertTrue(any("INSERT INTO devices" in s and "CAST(:a AS uuid)" in s for s in captured_sql))

    def test_sam_logs_since_uses_start_time_flag(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._conda_preflight", return_value=0), mock.patch("marvain_cli.ops._eprint", side_effect=cap):
            rc = sam_logs(ctx, dry_run=True, functions=["HubApiFunction"], tail=False, since="10m")
        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn(" sam logs ", joined)
        self.assertIn(" -s ", joined)
        self.assertIn("10min ago", joined)
        self.assertNotIn("--since", joined)


    def test_sam_logs_default_dry_run_does_not_use_name_flag(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._conda_preflight", return_value=0), mock.patch(
            "marvain_cli.ops._eprint", side_effect=cap
        ):
            rc = sam_logs(ctx, dry_run=True, functions=None, tail=False, since=None)
        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn(" sam logs ", joined)
        self.assertNotIn("--name", joined)

    def test_init_db_dry_run_applies_all_migrations_in_order_when_no_sql_file(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._conda_preflight", return_value=0), mock.patch(
            "marvain_cli.ops._eprint", side_effect=cap
        ):
            rc = init_db(ctx, dry_run=True, sql_file=None)

        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn("sql/001_init.sql", joined)
        self.assertIn("sql/002_users_and_memberships.sql", joined)
        self.assertIn("sql/003_owner_unique_index.sql", joined)
        self.assertLess(joined.find("sql/001_init.sql"), joined.find("sql/002_users_and_memberships.sql"))
        self.assertLess(joined.find("sql/002_users_and_memberships.sql"), joined.find("sql/003_owner_unique_index.sql"))


    def test_hub_claim_first_owner_dry_run_emits_http_request_without_leaking_token(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {"resources": {"HubRestApiBase": "https://example.com/dev"}}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._eprint", side_effect=cap):
            out = hub_claim_first_owner(
                ctx,
                agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                access_token="abcdef1234567890",
                hub_rest_api_base=None,
                dry_run=True,
            )

        self.assertEqual(out, {})
        joined = "\n".join(emitted)
        self.assertIn("HTTP POST https://example.com/dev/v1/agents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/claim_owner", joined)
        self.assertIn("Authorization: Bearer abcdef...", joined)
        self.assertNotIn("abcdef1234567890", joined)


    def test_cognito_admin_create_user_dry_run_uses_admin_create_user(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {"resources": {"CognitoUserPoolId": "pool-123"}}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._eprint", side_effect=cap):
            data = cognito_admin_create_user(ctx, email="x@example.com", dry_run=True)

        self.assertEqual(data, {})
        joined = "\n".join(emitted)
        self.assertIn("aws cognito-idp admin-create-user", joined)
        self.assertIn("--user-pool-id pool-123", joined)
        self.assertIn("--username x@example.com", joined)


    def test_cognito_admin_delete_user_dry_run_uses_admin_delete_user(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {"resources": {"CognitoUserPoolId": "pool-123"}}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._eprint", side_effect=cap):
            rc = cognito_admin_delete_user(ctx, dry_run=True, email="x@example.com")

        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn("aws cognito-idp admin-delete-user", joined)
        self.assertIn("--user-pool-id pool-123", joined)
        self.assertIn("--username x@example.com", joined)


class TestGuiLifecycle(unittest.TestCase):
    """Unit tests for GUI lifecycle management functions."""

    def _make_ctx(self) -> Ctx:
        """Create a minimal test context with resources for GUI tests."""
        return Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={
                "envs": {
                    "dev": {
                        "resources": {
                            "DbClusterArn": "arn:aws:rds:us-east-1:123456789012:cluster:test",
                            "DbSecretArn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
                            "DbName": "testdb",
                            "CognitoUserPoolId": "us-east-1_test",
                            "CognitoAppClientId": "testclientid",
                            "CognitoDomain": "test.auth.us-east-1.amazoncognito.com",
                        }
                    }
                }
            },
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

    def test_pid_file_path_is_in_repo_root(self) -> None:
        """PID file should be in repo root with expected filename."""
        pid_file = _get_gui_pid_file()
        self.assertEqual(pid_file.name, GUI_PID_FILENAME)
        self.assertTrue(pid_file.parent.exists())

    def test_log_file_path_is_in_repo_root(self) -> None:
        """Log file should be in repo root with expected filename."""
        log_file = _get_gui_log_file()
        self.assertEqual(log_file.name, GUI_LOG_FILENAME)
        self.assertTrue(log_file.parent.exists())

    def test_write_and_read_pid_file(self) -> None:
        """Test PID file write/read/remove cycle."""
        test_pid = 99999
        try:
            _write_pid_file(test_pid)
            read_pid = _read_pid_file()
            self.assertEqual(read_pid, test_pid)
        finally:
            _remove_pid_file()
        # After removal, should return None
        self.assertIsNone(_read_pid_file())

    def test_read_pid_file_returns_none_when_missing(self) -> None:
        """Read should return None when PID file doesn't exist."""
        _remove_pid_file()  # Ensure it's gone
        self.assertIsNone(_read_pid_file())

    def test_is_process_running_false_for_nonexistent_pid(self) -> None:
        """Should return False for a PID that doesn't exist."""
        # Use a very high PID that's unlikely to exist
        self.assertFalse(_is_process_running(999999999))

    def test_is_port_in_use_false_for_unused_port(self) -> None:
        """Should return False for a port that's not in use."""
        # Use a random high port that's unlikely to be in use
        import random
        unused_port = random.randint(50000, 60000)
        self.assertFalse(_is_port_in_use(unused_port))

    def test_gui_status_dry_run_emits_message(self) -> None:
        """gui_status with dry_run should emit a message and return 0."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)):
            rc = gui_status(ctx, dry_run=True, port=GUI_DEFAULT_PORT)

        self.assertEqual(rc, 0)
        self.assertTrue(any("[dry-run]" in m for m in emitted))

    def test_gui_stop_dry_run_emits_message(self) -> None:
        """gui_stop with dry_run should emit a message and return 0."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)):
            rc = gui_stop(ctx, dry_run=True, port=GUI_DEFAULT_PORT)

        self.assertEqual(rc, 0)
        self.assertTrue(any("[dry-run]" in m for m in emitted))

    def test_gui_start_dry_run_emits_command(self) -> None:
        """gui_start with dry_run should emit the uvicorn command."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with (
            mock.patch("marvain_cli.ops._conda_preflight", return_value=0),
            mock.patch("marvain_cli.ops._is_port_in_use", return_value=False),
            mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)),
            mock.patch("pathlib.Path.exists", return_value=True),
        ):
            rc = gui_start(ctx, dry_run=True, host=GUI_DEFAULT_HOST, port=GUI_DEFAULT_PORT, reload=True)

        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn("[dry-run]", joined)
        self.assertIn("uvicorn", joined)

    def test_gui_start_detects_port_conflict(self) -> None:
        """gui_start should fail when port is already in use."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with (
            mock.patch("marvain_cli.ops._conda_preflight", return_value=0),
            mock.patch("marvain_cli.ops._is_port_in_use", return_value=True),
            mock.patch("marvain_cli.ops._get_pid_on_port", return_value=12345),
            mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)),
            mock.patch("pathlib.Path.exists", return_value=True),
        ):
            rc = gui_start(ctx, dry_run=False, host=GUI_DEFAULT_HOST, port=GUI_DEFAULT_PORT, reload=True)

        self.assertEqual(rc, 1)
        joined = "\n".join(emitted)
        self.assertIn("already in use", joined)
        self.assertIn("12345", joined)

    def test_gui_logs_dry_run_emits_tail_command(self) -> None:
        """gui_logs with dry_run should emit the tail command."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)):
            rc = gui_logs(ctx, dry_run=True, follow=False, lines=50)

        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn("[dry-run]", joined)
        self.assertIn("tail", joined)

    def test_gui_logs_follow_dry_run_emits_tail_f(self) -> None:
        """gui_logs with follow=True should use tail -f."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)):
            rc = gui_logs(ctx, dry_run=True, follow=True, lines=50)

        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn("tail -f", joined)

    def test_gui_restart_dry_run_emits_message(self) -> None:
        """gui_restart with dry_run should emit a message and return 0."""
        emitted: list[str] = []
        ctx = self._make_ctx()

        with mock.patch("marvain_cli.ops._eprint", side_effect=lambda m: emitted.append(m)):
            rc = gui_restart(ctx, dry_run=True, host=GUI_DEFAULT_HOST, port=GUI_DEFAULT_PORT, reload=True)

        self.assertEqual(rc, 0)
        self.assertTrue(any("[dry-run]" in m for m in emitted))

    def test_default_constants_have_expected_values(self) -> None:
        """Verify default constants are set correctly."""
        self.assertEqual(GUI_DEFAULT_HOST, "localhost")
        self.assertEqual(GUI_DEFAULT_PORT, 8084)
        self.assertEqual(GUI_PID_FILENAME, ".marvain-gui.pid")
        self.assertEqual(GUI_LOG_FILENAME, ".marvain-gui.log")


class TestDeviceDetection(unittest.TestCase):
    """Tests for USB and direct-attach device detection."""

    def test_detect_local_devices_returns_list(self) -> None:
        """detect_local_devices should return a list."""
        from marvain_cli.ops import detect_local_devices

        devices = detect_local_devices()
        self.assertIsInstance(devices, list)

    def test_detected_device_has_required_fields(self) -> None:
        """DetectedDevice should have all required fields."""
        from marvain_cli.ops import DetectedDevice

        device = DetectedDevice(
            device_type="video",
            name="Test Camera",
            path="/dev/video0",
            connection_type="usb",
        )
        self.assertEqual(device.device_type, "video")
        self.assertEqual(device.name, "Test Camera")
        self.assertEqual(device.path, "/dev/video0")
        self.assertEqual(device.connection_type, "usb")
        self.assertIsNone(device.vendor_id)
        self.assertIsNone(device.product_id)
        self.assertIsNone(device.serial)

    def test_list_detected_devices_filters_by_type(self) -> None:
        """list_detected_devices should filter by device_type."""
        from marvain_cli.ops import list_detected_devices

        # Get all devices
        all_devices = list_detected_devices()

        # Filter by video
        video_devices = list_detected_devices(device_type="video")
        for d in video_devices:
            self.assertEqual(d["device_type"], "video")

        # Filter by audio_input
        audio_devices = list_detected_devices(device_type="audio_input")
        for d in audio_devices:
            self.assertEqual(d["device_type"], "audio_input")

    def test_list_detected_devices_filters_by_connection(self) -> None:
        """list_detected_devices should filter by connection_type."""
        from marvain_cli.ops import list_detected_devices

        # Filter by usb
        usb_devices = list_detected_devices(connection_type="usb")
        for d in usb_devices:
            self.assertEqual(d["connection_type"], "usb")

        # Filter by direct
        direct_devices = list_detected_devices(connection_type="direct")
        for d in direct_devices:
            self.assertEqual(d["connection_type"], "direct")

    def test_list_detected_devices_returns_dicts(self) -> None:
        """list_detected_devices should return list of dicts with expected keys."""
        from marvain_cli.ops import list_detected_devices

        devices = list_detected_devices()
        for d in devices:
            self.assertIsInstance(d, dict)
            self.assertIn("device_type", d)
            self.assertIn("name", d)
            self.assertIn("path", d)
            self.assertIn("connection_type", d)

    def test_detect_serial_ports_finds_patterns(self) -> None:
        """_detect_serial_ports should check common serial port patterns."""
        from marvain_cli.ops import _detect_serial_ports

        # This test just verifies the function runs without error
        # Actual detection depends on hardware
        ports = _detect_serial_ports()
        self.assertIsInstance(ports, list)

    def test_detect_video_devices_runs_without_error(self) -> None:
        """_detect_video_devices should run without error."""
        from marvain_cli.ops import _detect_video_devices

        devices = _detect_video_devices()
        self.assertIsInstance(devices, list)

    def test_detect_audio_devices_runs_without_error(self) -> None:
        """_detect_audio_devices should run without error."""
        from marvain_cli.ops import _detect_audio_devices

        devices = _detect_audio_devices()
        self.assertIsInstance(devices, list)

    def test_get_linux_video_connection_type_returns_valid_type(self) -> None:
        """_get_linux_video_connection_type should return 'usb' or 'direct'."""
        from marvain_cli.ops import _get_linux_video_connection_type

        # Test with a non-existent device path (should return 'direct' as fallback)
        result = _get_linux_video_connection_type("/dev/video999")
        self.assertIn(result, ["usb", "direct"])

    def test_get_linux_video_connection_type_usb_path_detection(self) -> None:
        """_get_linux_video_connection_type should detect USB from sysfs path."""
        from marvain_cli.ops import _get_linux_video_connection_type
        import tempfile
        import os

        # Create a mock sysfs structure with USB in the path
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock: /sys/class/video4linux/video0/device -> .../usb1/...
            video_dir = os.path.join(tmpdir, "sys", "class", "video4linux", "video0")
            usb_device_dir = os.path.join(tmpdir, "sys", "devices", "pci0000:00", "usb1", "1-2", "1-2:1.0")
            os.makedirs(video_dir, exist_ok=True)
            os.makedirs(usb_device_dir, exist_ok=True)

            # Create symlink: video0/device -> usb device path
            device_link = os.path.join(video_dir, "device")
            os.symlink(usb_device_dir, device_link)

            # Patch the sysfs base path for testing
            with mock.patch("marvain_cli.ops.os.path.exists") as mock_exists, \
                 mock.patch("marvain_cli.ops.os.path.realpath") as mock_realpath:
                mock_exists.return_value = True
                # Simulate USB device path
                mock_realpath.return_value = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"

                result = _get_linux_video_connection_type("/dev/video0")
                self.assertEqual(result, "usb")

    def test_get_linux_video_connection_type_non_usb_path(self) -> None:
        """_get_linux_video_connection_type should return 'direct' for non-USB devices."""
        from marvain_cli.ops import _get_linux_video_connection_type

        # Patch to simulate a PCI device (no 'usb' in path)
        with mock.patch("marvain_cli.ops.os.path.exists") as mock_exists, \
             mock.patch("marvain_cli.ops.os.path.realpath") as mock_realpath, \
             mock.patch("marvain_cli.ops.os.path.islink") as mock_islink:
            mock_exists.return_value = True
            mock_islink.return_value = False
            # Simulate PCI device path (no 'usb' in path)
            mock_realpath.return_value = "/sys/devices/pci0000:00/0000:00:02.0/drm/card0"

            result = _get_linux_video_connection_type("/dev/video0")
            self.assertEqual(result, "direct")


if __name__ == "__main__":
    unittest.main()