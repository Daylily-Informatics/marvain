from __future__ import annotations

import unittest
from unittest import mock

import asyncio


class _StubPaginator:
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def paginate(self):
        yield from self._pages


class _StubCloudFormation:
    def __init__(self, *, stack_name: str, outputs: dict[str, str], params: dict[str, str] | None = None):
        self._stack_name = stack_name
        self._outputs = outputs
        self._params = params or {}

    def get_paginator(self, name: str):
        assert name == "list_stacks"
        return _StubPaginator(
            pages=[
                {
                    "StackSummaries": [
                        {
                            "StackName": self._stack_name,
                            "StackStatus": "CREATE_COMPLETE",
                            "StackId": "arn:aws:cloudformation:us-west-2:123:stack/x/y",
                        }
                    ]
                }
            ]
        )

    def describe_stacks(self, *, StackName: str):
        if StackName != self._stack_name:
            raise RuntimeError(f"unexpected stack name: {StackName}")
        return {
            "Stacks": [
                {
                    "Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in self._outputs.items()],
                    "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in self._params.items()],
                }
            ]
        }


class TestGuiStackDiscovery(unittest.TestCase):
    def test_list_stacks_accepts_hub_outputs(self) -> None:
        # Import inside test so failures are attributed correctly.
        try:
            from archive.client import gui
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"GUI deps not available: {e}")

        stub = _StubCloudFormation(
            stack_name="marvain-demo-dev",
            outputs={
                "HubRestApiBase": "https://example.execute-api.us-west-2.amazonaws.com/dev",
                "HubWebSocketUrl": "wss://example.execute-api.us-west-2.amazonaws.com/dev",
            },
            params={"AgentIdParam": "marvain-agent"},
        )

        with mock.patch.object(gui, "cf_client", return_value=stub):
            stacks, _, _, _ = gui._list_stacks_by_status("marvain-")

        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]["name"], "marvain-demo-dev")
        self.assertIn("https://example.execute-api", stacks[0]["endpoint"])
        self.assertIn("wss://example.execute-api", stacks[0]["ws_url"])


    def test_select_stack_accepts_hub_outputs(self) -> None:
        try:
            from archive.client import gui
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"GUI deps not available: {e}")

        gui.STATE.stack_prefix = "marvain"  # ensure prefixing behavior is stable

        stub = _StubCloudFormation(
            stack_name="marvain-demo-dev",
            outputs={
                "HubRestApiBase": "https://example.execute-api.us-west-2.amazonaws.com/dev",
            },
            params={"AgentIdParam": "marvain-agent"},
        )

        with mock.patch.object(gui, "cf_client", return_value=stub):
            resp = gui.select_stack("demo-dev")

        self.assertEqual(gui.STATE.selected_stack, "marvain-demo-dev")
        self.assertEqual(gui.STATE.selected_endpoint, "https://example.execute-api.us-west-2.amazonaws.com/dev")
        self.assertEqual(getattr(resp, "status_code", None), 302)


    def test_list_stacks_still_accepts_legacy_broker_output(self) -> None:
        try:
            from archive.client import gui
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"GUI deps not available: {e}")

        stub = _StubCloudFormation(
            stack_name="marvain-legacy-dev",
            outputs={
                "BrokerEndpointURL": "https://legacy.example/Prod/agent",
            },
        )

        with mock.patch.object(gui, "cf_client", return_value=stub):
            stacks, _, _, _ = gui._list_stacks_by_status("marvain-")

        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]["endpoint"], "https://legacy.example/Prod/agent")


    def test_build_debug_command_uses_archive_bin_paths(self) -> None:
        try:
            from archive.client import gui
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"GUI deps not available: {e}")

        gui.STATE.aws_region = "us-west-2"
        cmd = gui._build_debug_command("print_stack_outputs", {"stack": "marvain-demo-dev"})
        self.assertEqual(cmd[0], "python3")
        self.assertEqual(cmd[1], str(gui.ARCHIVE_BIN_DIR / "print_stack_outputs.py"))


    def test_debug_tool_timeout_is_short_for_tail_logs(self) -> None:
        try:
            from archive.client import gui
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"GUI deps not available: {e}")

        class _Req:
            def __init__(self, data):
                self._data = data

            async def json(self):
                return self._data

        req = _Req({"tool": "tail_cloud_logs", "params": {"stack": "marvain-demo-dev"}})

        fake_proc = mock.Mock(returncode=0, stdout="ok\n", stderr="")
        with mock.patch.object(gui, "_build_debug_command", return_value=["echo", "ok"]), mock.patch(
            "archive.client.gui.subprocess.run", return_value=fake_proc
        ) as mrun:
            asyncio.run(gui.run_debug_tool(req))
        self.assertEqual(mrun.call_args.kwargs.get("timeout"), 20)
