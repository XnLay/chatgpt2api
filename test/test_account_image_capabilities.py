from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.account_service import AccountService
from services.auth_service import AuthService
from services.config import config
from services.openai_backend_api import InvalidAccessTokenError
import services.register_service as register_service_module
from services.register_service import RegisterService
from services.storage.json_storage import JSONStorageBackend
from utils.helper import anonymize_token, split_image_model


class AccountCapabilityTests(unittest.TestCase):
    def test_unknown_quota_accounts_are_available_only_when_not_throttled(self) -> None:
        self.assertFalse(
            AccountService._is_image_account_available(
                {"status": "限流", "image_quota_unknown": True, "quota": 0}
            )
        )
        self.assertTrue(
            AccountService._is_image_account_available(
                {"status": "正常", "image_quota_unknown": True, "quota": 0}
            )
        )

    def test_prolite_variants_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            self.assertEqual(service._normalize_account_type("prolite"), "ProLite")
            self.assertEqual(service._normalize_account_type("pro_lite"), "ProLite")

    def test_search_account_type_ignores_unrelated_scalar_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            self.assertIsNone(
                service._search_account_type(
                    {
                        "amr": ["pwd", "otp", "mfa"],
                        "chatgpt_compute_residency": "no_constraint",
                        "chatgpt_data_residency": "no_constraint",
                        "user_id": "user-I52GFfLGFM0dokFk2dBiKEBn",
                    }
                )
            )

    def test_mark_image_result_does_not_consume_unknown_quota(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_accounts(["token-1"])
            service.update_account(
                "token-1",
                {
                    "status": "正常",
                    "quota": 0,
                    "image_quota_unknown": True,
                },
            )

            updated = service.mark_image_result("token-1", success=True)

            self.assertIsNotNone(updated)
            self.assertEqual(updated["quota"], 0)
            self.assertEqual(updated["status"], "正常")
            self.assertTrue(updated["image_quota_unknown"])

    def test_split_image_model_supports_plan_type_prefix(self) -> None:
        self.assertEqual(split_image_model("gpt-image-2"), (None, "gpt-image-2"))
        self.assertEqual(split_image_model("plus-codex-gpt-image-2"), ("plus", "codex-gpt-image-2"))
        self.assertEqual(split_image_model("team-codex-gpt-image-2"), ("team", "codex-gpt-image-2"))
        self.assertEqual(split_image_model("pro-codex-gpt-image-2"), ("pro", "codex-gpt-image-2"))
        self.assertEqual(split_image_model("plus-gpt-image-2"), (None, None))
        self.assertEqual(split_image_model("unknown-image-model"), (None, None))

    def test_get_available_access_token_filters_by_plan_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_account_items(
                [
                    {"access_token": "token-plus", "type": "Plus", "status": "正常", "quota": 3},
                    {"access_token": "token-pro", "type": "Pro", "status": "正常", "quota": 3},
                ]
            )

            service.fetch_remote_info = lambda access_token, event="fetch_remote_info": service.get_account(access_token)

            plus_token = service.get_available_access_token(plan_type="plus")
            pro_token = service.get_available_access_token(plan_type="pro")
            service.release_image_slot(plus_token)
            service.release_image_slot(pro_token)

            self.assertEqual(plus_token, "token-plus")
            self.assertEqual(pro_token, "token-pro")

    def test_invalid_token_is_eventually_removed_after_repeated_confirmations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_accounts(["token-invalid"])
            service.update_account(
                "token-invalid",
                {
                    "status": "正常",
                    "quota": 3,
                    "created_at": "2000-01-01T00:00:00+00:00",
                },
            )

            decisions = [
                service._record_invalid_token_seen("token-invalid", "test", "401")
                for _ in range(4)
            ]

            self.assertEqual(decisions, [False, False, False, True])
            self.assertEqual(service.list_invalid_tokens(), ["token-invalid"])

            old_auto_remove = config.data.get("auto_remove_invalid_accounts")
            config.data["auto_remove_invalid_accounts"] = True
            try:
                removed = service.remove_invalid_token("token-invalid", "test")
                self.assertTrue(removed)
                self.assertIsNone(service.get_account("token-invalid"))
            finally:
                if old_auto_remove is None:
                    config.data.pop("auto_remove_invalid_accounts", None)
                else:
                    config.data["auto_remove_invalid_accounts"] = old_auto_remove

    def test_confirm_invalid_refresh_removes_invalid_account_in_one_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_accounts(["token-invalid"])
            service.update_account(
                "token-invalid",
                {
                    "status": "正常",
                    "quota": 3,
                    "created_at": "2000-01-01T00:00:00+00:00",
                },
            )

            def fake_fetch_remote_info(access_token: str, event: str = "fetch_remote_info") -> dict | None:
                if service._record_invalid_token_seen(access_token, event, "HTTP 401"):
                    service.remove_invalid_token(access_token, event)
                raise InvalidAccessTokenError("HTTP 401")

            service.fetch_remote_info = fake_fetch_remote_info
            old_auto_remove = config.data.get("auto_remove_invalid_accounts")
            config.data["auto_remove_invalid_accounts"] = True
            try:
                result = service.refresh_accounts(["token-invalid"], confirm_invalid=True)

                self.assertEqual(result["errors"], [])
                self.assertIsNone(service.get_account("token-invalid"))
            finally:
                if old_auto_remove is None:
                    config.data.pop("auto_remove_invalid_accounts", None)
                else:
                    config.data["auto_remove_invalid_accounts"] = old_auto_remove

    def test_register_pool_metrics_ignore_pending_invalid_accounts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_account_items(
                [
                    {"access_token": "token-ok", "status": "正常", "quota": 2},
                    {
                        "access_token": "token-pending",
                        "status": "正常",
                        "quota": 2,
                        "invalid_count": 1,
                        "first_invalid_at": "2000-01-01T00:00:00+00:00",
                    },
                    {"access_token": "token-zero", "status": "正常", "quota": 0},
                ]
            )

            original_account_service = register_service_module.account_service
            register_service_module.account_service = service
            refresh_calls = []

            def fake_refresh_accounts(tokens: list[str], **kwargs) -> dict:
                refresh_calls.append((tokens, kwargs))
                return {"refreshed": len(tokens), "errors": [], "items": service.list_accounts()}

            service.refresh_accounts = fake_refresh_accounts
            try:
                register_service = RegisterService(Path(tmp_dir) / "register.json")
                metrics = register_service._pool_metrics()

                self.assertEqual(metrics["current_available"], 1)
                self.assertEqual(metrics["current_quota"], 2)
                self.assertFalse(register_service._target_reached({"mode": "available", "target_available": 2}, 0))
                self.assertTrue(refresh_calls)
                self.assertTrue(refresh_calls[0][1]["confirm_invalid"])
            finally:
                register_service_module.account_service = original_account_service

    def test_register_normalize_applies_env_mail_provider_overrides(self) -> None:
        raw = {
            "mail": {
                "request_timeout": 30,
                "wait_timeout": 30,
                "wait_interval": 2,
                "providers": [{"enable": True, "type": "cloudmail_gen"}],
            }
        }
        env = {
            "CHATGPT2API_AUTH_KEY": "test-auth",
            "REGISTER_MAIL_PROVIDER": "inbucket",
            "REGISTER_MAIL_PROVIDER_CONFIG": json.dumps({"api_base": "https://mail.example", "domain": "env.example"}),
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = register_service_module._normalize(raw)

        self.assertEqual(cfg["mail"]["providers"][0]["type"], "inbucket")
        self.assertEqual(cfg["mail"]["providers"][0]["domain"], ["env.example"])

    def test_register_default_config_uses_available_pool_monitor(self) -> None:
        with patch.dict(os.environ, {"CHATGPT2API_AUTH_KEY": "test-auth"}, clear=True):
            cfg = register_service_module._normalize({})

        self.assertEqual(cfg["mode"], "available")
        self.assertEqual(cfg["target_available"], 10)
        self.assertEqual(cfg["check_interval"], 600)

    def test_register_stop_wakes_idle_available_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            service.add_account_items(
                [
                    {"access_token": "token-1", "status": "正常", "quota": 3},
                    {"access_token": "token-2", "status": "正常", "quota": 3},
                ]
            )

            original_account_service = register_service_module.account_service
            register_service_module.account_service = service
            service.refresh_accounts = lambda tokens, **kwargs: {
                "refreshed": len(tokens),
                "errors": [],
                "items": service.list_accounts(),
            }
            try:
                register_service = RegisterService(Path(tmp_dir) / "register.json")
                register_service.update(
                    {
                        "mode": "available",
                        "target_available": 1,
                        "check_interval": 60,
                        "threads": 1,
                    }
                )
                register_service.start()
                self.assertIsNotNone(register_service._runner)

                time.sleep(0.05)
                register_service.stop()

                deadline = time.monotonic() + 2
                while register_service._runner and register_service._runner.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.02)

                self.assertFalse(register_service._runner and register_service._runner.is_alive())
                logs = [item["text"] for item in register_service.get()["logs"]]
                self.assertIn("注册任务结束，成功0，失败0", logs)
            finally:
                register_service_module.account_service = original_account_service


class TokenLogTests(unittest.TestCase):
    def test_anonymize_token_hides_raw_value(self) -> None:
        token = "super-secret-token"
        token_ref = anonymize_token(token)

        self.assertTrue(token_ref.startswith("token:"))
        self.assertNotIn(token, token_ref)


class AuthServiceTests(unittest.TestCase):
    def test_create_authenticate_disable_and_delete_user_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AuthService(JSONStorageBackend(Path(tmp_dir) / "accounts.json", Path(tmp_dir) / "auth_keys.json"))

            item, raw_key = service.create_key(role="user", name="Alice")

            self.assertEqual(item["role"], "user")
            self.assertEqual(item["name"], "Alice")
            self.assertTrue(item["enabled"])
            self.assertTrue(raw_key.startswith("sk-"))

            authed = service.authenticate(raw_key)
            self.assertIsNotNone(authed)
            self.assertEqual(authed["id"], item["id"])
            self.assertEqual(authed["role"], "user")
            self.assertIsNotNone(authed["last_used_at"])

            updated = service.update_key(item["id"], {"enabled": False}, role="user")
            self.assertIsNotNone(updated)
            self.assertFalse(updated["enabled"])
            self.assertIsNone(service.authenticate(raw_key))

            self.assertTrue(service.delete_key(item["id"], role="user"))
            self.assertFalse(service.delete_key(item["id"], role="user"))
            self.assertEqual(service.list_keys(role="user"), [])

    def test_authenticate_ignores_last_used_save_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AuthService(JSONStorageBackend(Path(tmp_dir) / "accounts.json", Path(tmp_dir) / "auth_keys.json"))
            item, raw_key = service.create_key(role="user", name="Alice")

            def fail_save() -> None:
                raise OSError("disk unavailable")

            service._save = fail_save

            authed = service.authenticate(raw_key)

            self.assertIsNotNone(authed)
            self.assertEqual(authed["id"], item["id"])
            self.assertIsNotNone(authed["last_used_at"])

    def test_update_user_key_replaces_raw_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AuthService(JSONStorageBackend(Path(tmp_dir) / "accounts.json", Path(tmp_dir) / "auth_keys.json"))
            item, raw_key = service.create_key(role="user", name="Alice")

            updated = service.update_key(item["id"], {"key": "sk-user-custom-key"}, role="user")

            self.assertIsNotNone(updated)
            self.assertIsNone(service.authenticate(raw_key))

            authed = service.authenticate("sk-user-custom-key")
            self.assertIsNotNone(authed)
            self.assertEqual(authed["id"], item["id"])

    def test_user_key_name_must_be_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = AuthService(JSONStorageBackend(Path(tmp_dir) / "accounts.json", Path(tmp_dir) / "auth_keys.json"))
            first, _ = service.create_key(role="user", name="Alice")
            second, _ = service.create_key(role="user", name="Bob")

            with self.assertRaisesRegex(ValueError, "这个名称已经在使用中了"):
                service.create_key(role="user", name="Alice")

            with self.assertRaisesRegex(ValueError, "这个名称已经在使用中了"):
                service.update_key(second["id"], {"name": "Alice"}, role="user")

            updated = service.update_key(first["id"], {"name": "Alice"}, role="user")
            self.assertIsNotNone(updated)
            self.assertEqual(updated["name"], "Alice")


if __name__ == "__main__":
    unittest.main()
