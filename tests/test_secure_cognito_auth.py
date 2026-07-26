from __future__ import annotations

import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from cli_core_yo.conformance import assert_exit_code, invoke

from marvain_cli.config import ConfigError, ResolvedEnv
from marvain_cli.ops import (
    Ctx,
    cognito_password_access_token,
    hub_claim_first_owner,
    hub_list_memberships,
    read_password_stdin,
    resolve_user_access_token,
)


def _ctx() -> Ctx:
    resources = {
        "CognitoUserPoolId": "us-west-1_test",
        "CognitoAppClientId": "test-client-id",
        "HubRestApiBase": "https://hub.example.test",
    }
    return Ctx(
        config_path=Path("/tmp/marvain.yaml"),
        cfg={"envs": {"cleanroom": {"resources": resources}}},
        env=ResolvedEnv(
            env="cleanroom",
            aws_profile="lsmc",
            aws_region="us-west-1",
            stack_name="marvain-cleanroom-test",
            raw={"resources": resources},
        ),
    )


class TestSecureCognitoAuthOps(unittest.TestCase):
    def test_read_password_stdin_preserves_spaces_and_removes_one_line_ending(self) -> None:
        with mock.patch("sys.stdin", io.StringIO(" leading and trailing spaces \r\n")):
            password = read_password_stdin()

        self.assertEqual(password, " leading and trailing spaces ")

    def test_read_password_stdin_rejects_empty_input(self) -> None:
        with mock.patch("sys.stdin", io.StringIO("\n")):
            with self.assertRaisesRegex(ConfigError, "Password input is empty"):
                read_password_stdin()

    def test_read_password_stdin_uses_hidden_prompt_for_a_tty(self) -> None:
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        with (
            mock.patch("sys.stdin", stdin),
            mock.patch("marvain_cli.ops.getpass.getpass", return_value="unit-password") as prompt,
        ):
            password = read_password_stdin()

        self.assertEqual(password, "unit-password")
        prompt.assert_called_once_with("Cognito password: ")

    def test_cognito_password_access_token_uses_selected_pool_and_client(self) -> None:
        admin = mock.Mock()
        admin.cognito.initiate_auth.return_value = {"AuthenticationResult": {"AccessToken": "unit-access-token"}}

        with mock.patch("daylily_auth_cognito.admin.client.CognitoAdminClient", return_value=admin) as client:
            token = cognito_password_access_token(_ctx(), email="owner@example.test", password="unit-password")

        self.assertEqual(token, "unit-access-token")
        client.assert_called_once_with(
            region="us-west-1",
            aws_profile="lsmc",
            user_pool_id="us-west-1_test",
            app_client_id="test-client-id",
        )
        admin.cognito.initiate_auth.assert_called_once_with(
            ClientId="test-client-id",
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": "owner@example.test", "PASSWORD": "unit-password"},
        )

    def test_cognito_password_access_token_requires_an_access_token_response(self) -> None:
        admin = mock.Mock()
        admin.cognito.initiate_auth.return_value = {"ChallengeName": "NEW_PASSWORD_REQUIRED"}

        with (
            mock.patch("daylily_auth_cognito.admin.client.CognitoAdminClient", return_value=admin),
            self.assertRaisesRegex(ConfigError, "did not return an access token"),
        ):
            cognito_password_access_token(_ctx(), email="owner@example.test", password="unit-password")

    def test_secure_resolver_reads_password_only_for_explicit_secure_mode(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("marvain_cli.ops.read_password_stdin", return_value="unit-password") as read_password,
            mock.patch(
                "marvain_cli.ops.cognito_password_access_token", return_value="unit-access-token"
            ) as authenticate,
        ):
            token = resolve_user_access_token(
                _ctx(),
                access_token=None,
                cognito_email="owner@example.test",
                password_stdin=True,
                dry_run=False,
            )

        self.assertEqual(token, "unit-access-token")
        read_password.assert_called_once_with()
        authenticate.assert_called_once_with(_ctx(), email="owner@example.test", password="unit-password")

    def test_secure_resolver_rejects_ambient_access_token(self) -> None:
        with (
            mock.patch.dict(os.environ, {"MARVAIN_ACCESS_TOKEN": "ambient-token"}, clear=True),
            self.assertRaisesRegex(ConfigError, "cannot be combined with an access token"),
        ):
            resolve_user_access_token(
                _ctx(),
                access_token=None,
                cognito_email="owner@example.test",
                password_stdin=True,
                dry_run=False,
            )

    def test_secure_resolver_dry_run_does_not_read_or_authenticate(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("marvain_cli.ops.read_password_stdin") as read_password,
            mock.patch("marvain_cli.ops.cognito_password_access_token") as authenticate,
        ):
            token = resolve_user_access_token(
                _ctx(),
                access_token=None,
                cognito_email="owner@example.test",
                password_stdin=True,
                dry_run=True,
            )

        self.assertEqual(token, "dry-run-cognito-access-token")
        read_password.assert_not_called()
        authenticate.assert_not_called()

    def test_claim_owner_uses_the_secure_resolver(self) -> None:
        ctx = _ctx()
        with (
            mock.patch("marvain_cli.ops.resolve_user_access_token", return_value="unit-access-token") as resolve_token,
            mock.patch("marvain_cli.ops.hub_api_json", return_value={"role": "owner"}) as request,
        ):
            receipt = hub_claim_first_owner(
                ctx,
                agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                access_token=None,
                hub_rest_api_base=None,
                dry_run=False,
                cognito_email="owner@example.test",
                password_stdin=True,
            )

        self.assertEqual(receipt, {"role": "owner"})
        resolve_token.assert_called_once_with(
            ctx,
            access_token=None,
            cognito_email="owner@example.test",
            password_stdin=True,
            dry_run=False,
        )
        self.assertEqual(request.call_args.kwargs["access_token"], "unit-access-token")

    def test_list_memberships_uses_the_secure_resolver(self) -> None:
        ctx = _ctx()
        with (
            mock.patch("marvain_cli.ops.resolve_user_access_token", return_value="unit-access-token") as resolve_token,
            mock.patch("marvain_cli.ops.hub_api_json", return_value={"memberships": []}) as request,
        ):
            receipt = hub_list_memberships(
                ctx,
                agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                access_token=None,
                hub_rest_api_base=None,
                dry_run=False,
                cognito_email="owner@example.test",
                password_stdin=True,
            )

        self.assertEqual(receipt, {"memberships": []})
        resolve_token.assert_called_once_with(
            ctx,
            access_token=None,
            cognito_email="owner@example.test",
            password_stdin=True,
            dry_run=False,
        )
        self.assertEqual(request.call_args.kwargs["access_token"], "unit-access-token")


class TestSecureCognitoAuthCli(unittest.TestCase):
    def test_claim_owner_wires_password_stdin_without_an_access_token_argument(self) -> None:
        from marvain_cli import cli

        app = cli.build_app()
        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch("marvain_cli.commands.hub_claim_first_owner", return_value={"role": "owner"}) as claim,
        ):
            result = invoke(
                app,
                [
                    "members",
                    "claim-owner",
                    "--agent-id",
                    "agent-1",
                    "--cognito-email",
                    "owner@example.test",
                    "--password-stdin",
                ],
                prog_name="marvain",
            )

        assert_exit_code(result, 0)
        claim.assert_called_once_with(
            mock.ANY,
            agent_id="agent-1",
            access_token=None,
            hub_rest_api_base=None,
            dry_run=False,
            cognito_email="owner@example.test",
            password_stdin=True,
        )

    def test_set_password_requires_password_stdin_and_never_echoes_the_password(self) -> None:
        from marvain_cli import cli

        app = cli.build_app()
        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch("marvain_cli.commands.cognito_set_password") as set_password,
        ):
            missing = invoke(app, ["cognito", "set-password", "owner@example.test"], prog_name="marvain")

        self.assertNotEqual(missing.exit_code, 0)
        self.assertIn("requires --password-stdin", missing.output)
        set_password.assert_not_called()

        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch("marvain_cli.commands.read_password_stdin", return_value="unit-password"),
            mock.patch("marvain_cli.commands.cognito_set_password") as set_password,
        ):
            result = invoke(
                app,
                ["cognito", "set-password", "owner@example.test", "--password-stdin"],
                prog_name="marvain",
            )

        assert_exit_code(result, 0)
        self.assertNotIn("unit-password", result.output)
        set_password.assert_called_once_with(
            mock.ANY,
            email="owner@example.test",
            password="unit-password",
            permanent=True,
            dry_run=False,
        )

    def test_secure_owner_claim_help_has_no_access_token_option(self) -> None:
        from marvain_cli import cli

        result = invoke(cli.build_app(), ["members", "claim-owner", "--help"], prog_name="marvain")

        assert_exit_code(result, 0)
        self.assertIn("--password-stdin", result.output)
        self.assertIn("--cognito-email", result.output)
        self.assertNotIn("--access-token", result.output)

    def test_finalize_deployment_help_exposes_the_same_secure_auth_mode(self) -> None:
        from marvain_cli import cli

        result = invoke(cli.build_app(), ["agent", "finalize-deployment", "--help"], prog_name="marvain")

        assert_exit_code(result, 0)
        self.assertIn("--password-stdin", result.output)
        self.assertIn("--cognito-email", result.output)
        self.assertNotIn("--access-token", result.output)

    def test_members_list_help_exposes_the_same_secure_auth_mode(self) -> None:
        from marvain_cli import cli

        result = invoke(cli.build_app(), ["members", "list", "--help"], prog_name="marvain")

        assert_exit_code(result, 0)
        self.assertIn("--password-stdin", result.output)
        self.assertIn("--cognito-email", result.output)
        self.assertIn("--owner-count-only", result.output)
        self.assertNotIn("--access-token", result.output)

    def test_members_list_owner_count_only_redacts_membership_details(self) -> None:
        from marvain_cli import cli

        app = cli.build_app()
        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch(
                "marvain_cli.commands.hub_list_memberships",
                return_value={
                    "memberships": [
                        {"email": "owner@example.test", "role": "owner"},
                        {"email": "member@example.test", "role": "member"},
                    ]
                },
            ),
        ):
            result = invoke(
                app,
                [
                    "members",
                    "list",
                    "--agent-id",
                    "agent-1",
                    "--cognito-email",
                    "owner@example.test",
                    "--password-stdin",
                    "--owner-count-only",
                ],
                prog_name="marvain",
            )

        assert_exit_code(result, 0)
        self.assertEqual(json.loads(result.output), {"active_owner_memberships": 1})
        self.assertNotIn("owner@example.test", result.output)
        self.assertNotIn("member@example.test", result.output)

    def test_members_list_owner_count_only_rejects_non_object_membership(self) -> None:
        from marvain_cli import cli

        app = cli.build_app()
        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch(
                "marvain_cli.commands.hub_list_memberships",
                return_value={"memberships": ["not-a-membership-object"]},
            ),
        ):
            result = invoke(
                app,
                [
                    "members",
                    "list",
                    "--agent-id",
                    "agent-1",
                    "--cognito-email",
                    "owner@example.test",
                    "--password-stdin",
                    "--owner-count-only",
                ],
                prog_name="marvain",
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("non-object membership", result.output)


if __name__ == "__main__":
    unittest.main()
