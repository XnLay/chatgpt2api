import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import requests

from services.register import openai_register


class _FakeCookies:
    def __init__(self):
        self.items = []

    def set(self, *args, **kwargs):
        self.items.append((args, kwargs))


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", url="https://auth.openai.com/test", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.cookies = _FakeCookies()
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return self.response


class OpenAIRegisterCloudflareTests(unittest.TestCase):
    def test_create_session_uses_requests_for_plain_and_http_proxy(self):
        plain_session = openai_register.create_session("")
        proxied_session = openai_register.create_session("http://127.0.0.1:8080")

        try:
            self.assertIsInstance(plain_session, requests.Session)
            self.assertIsInstance(proxied_session, requests.Session)
            self.assertEqual(proxied_session.proxies["http"], "http://127.0.0.1:8080")
            self.assertEqual(proxied_session.proxies["https"], "http://127.0.0.1:8080")
        finally:
            plain_session.close()
            proxied_session.close()

    def test_create_session_keeps_curl_for_socks_proxy(self):
        session = openai_register.create_session("socks5://127.0.0.1:1080")

        try:
            self.assertNotIsInstance(session, requests.Session)
            self.assertEqual(session.proxies["all"], "socks5://127.0.0.1:1080")
        finally:
            session.close()

    def test_cloudflare_server_header_alone_is_not_challenge(self):
        resp = _FakeResponse(
            status_code=409,
            headers={"server": "cloudflare", "content-type": "application/json"},
            text='{"error":"authorization_pending"}',
        )

        self.assertFalse(openai_register._is_cloudflare_challenge(resp))

    def test_cloudflare_challenge_html_is_detected(self):
        resp = _FakeResponse(
            status_code=403,
            headers={"server": "cloudflare", "content-type": "text/html"},
            text="<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/h/b'></script></html>",
        )

        self.assertTrue(openai_register._is_cloudflare_challenge(resp))

    def test_platform_authorize_continues_for_non_challenge_cloudflare_gateway_response(self):
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar.session = _FakeSession(
            _FakeResponse(
                status_code=409,
                headers={"server": "cloudflare", "content-type": "application/json"},
                text='{"error":"authorization_pending"}',
            )
        )
        registrar.device_id = "device-id"
        registrar.code_verifier = ""
        registrar.platform_auth_code = ""

        registrar._platform_authorize("user@example.com", 1)

        self.assertTrue(registrar.code_verifier)
        self.assertEqual(len(registrar.session.requests), 1)

    def test_platform_authorize_continues_for_cloudflare_challenge_compatibility(self):
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar.session = _FakeSession(
            _FakeResponse(
                status_code=403,
                headers={"server": "cloudflare", "content-type": "text/html", "cf-mitigated": "challenge"},
                text="<html><title>Just a moment...</title></html>",
            )
        )
        registrar.device_id = "device-id"
        registrar.code_verifier = ""
        registrar.platform_auth_code = ""

        registrar._platform_authorize("user@example.com", 1)

        self.assertTrue(registrar.code_verifier)
        self.assertEqual(len(registrar.session.requests), 1)

    def test_platform_authorize_cloudflare_challenge_log_is_concise(self):
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar.session = _FakeSession(
            _FakeResponse(
                status_code=403,
                headers={"server": "cloudflare", "content-type": "text/html; charset=utf-8", "cf-mitigated": "challenge"},
                text="<!DOCTYPE html><html><head><title>Create a password - OpenAI</title></head><body>challenge</body></html>",
                url="https://auth.openai.com/create-account/password",
            )
        )
        registrar.device_id = "device-id"
        registrar.code_verifier = ""
        registrar.platform_auth_code = ""
        logs = []
        old_sink = openai_register.register_log_sink
        openai_register.register_log_sink = lambda text, color: logs.append((text, color))
        try:
            registrar._platform_authorize("user@example.com", 10)
        finally:
            openai_register.register_log_sink = old_sink

        challenge_logs = [text for text, _color in logs if "Cloudflare challenge" in text]
        self.assertEqual(challenge_logs, ["[任务10] platform authorize 返回 Cloudflare challenge，按 1.1.7 兼容策略继续尝试；"])
        self.assertNotIn("<!DOCTYPE html>", challenge_logs[0])
        self.assertNotIn("body=", challenge_logs[0])
        self.assertNotIn("url=", challenge_logs[0])

    def test_create_account_sends_sentinel_so_token(self):
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar.session = _FakeSession(
            _FakeResponse(
                status_code=200,
                json_data={"continue_url": "https://platform.openai.com/auth/callback?code=oauth-code&state=ok"},
            )
        )
        registrar.device_id = "device-id"
        artifacts = openai_register.SentinelArtifacts(
            token='{"p":"proof","t":"","c":"challenge","id":"device-id","flow":"oauth_create_account"}',
            oai_sc_value="0challenge",
            so_token="so-token-value",
            sdk_version="test-sdk",
        )

        with patch.object(openai_register, "build_sentinel_artifacts", return_value=artifacts):
            registrar._create_account("Test User", "2000-01-01", 1)

        request_headers = registrar.session.requests[0][2]["headers"]
        self.assertEqual(request_headers["openai-sentinel-token"], artifacts.token)
        self.assertEqual(request_headers["openai-sentinel-so-token"], "so-token-value")
        self.assertEqual(registrar.platform_auth_code, "oauth-code")
        self.assertTrue(any(args == ("oai-sc", "0challenge") for args, _kwargs in registrar.session.cookies.items))


class OpenAIRegisterPasswordlessTests(unittest.TestCase):
    def _registrar(self, response=None):
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar.proxy = ""
        registrar.session = _FakeSession(response or _FakeResponse())
        registrar.device_id = "device-id"
        registrar.code_verifier = ""
        registrar.platform_auth_code = ""
        registrar.passwordless_signup = False
        return registrar

    def test_platform_authorize_uses_passwordless_hint_and_detects_verification_page(self):
        registrar = self._registrar(_FakeResponse(url="https://auth.openai.com/email-verification"))

        registrar._platform_authorize("new@example.com", 1)

        request_url = registrar.session.requests[0][1]
        query = parse_qs(urlparse(request_url).query)
        self.assertEqual(query["screen_hint"], ["login_or_signup"])
        self.assertTrue(registrar.passwordless_signup)

    def test_start_passwordless_signup_posts_current_endpoint(self):
        registrar = self._registrar()

        registrar._start_passwordless_signup(1)

        method, url, kwargs = registrar.session.requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://auth.openai.com/api/accounts/passwordless/send-otp")
        self.assertEqual(kwargs["headers"]["referer"], "https://auth.openai.com/create-account/password")
        self.assertTrue(registrar.passwordless_signup)

    def test_start_passwordless_signup_reports_response_detail(self):
        registrar = self._registrar(
            _FakeResponse(status_code=400, json_data={"error": {"code": "email_not_allowed"}})
        )

        with self.assertRaisesRegex(RuntimeError, "email_not_allowed"):
            registrar._start_passwordless_signup(1)

    def test_validate_otp_follows_continue_url(self):
        registrar = self._registrar()
        otp_response = _FakeResponse(
            json_data={"page": {"payload": {"continueUrl": "/authorize/continue?state=test"}}}
        )

        with patch.object(openai_register, "validate_otp", return_value=(otp_response, "")), patch.object(
            registrar,
            "_authorize_continue",
        ) as authorize_continue:
            registrar._validate_otp("123456", 7)

        authorize_continue.assert_called_once_with("/authorize/continue?state=test", 7)

    def test_extract_continue_url_supports_known_response_shapes(self):
        self.assertEqual(
            openai_register.extract_continue_url({"continue_url": "https://auth.openai.com/next"}),
            "https://auth.openai.com/next",
        )
        self.assertEqual(
            openai_register.extract_continue_url(
                {"oai-client-auth-session": {"continueUrl": "/authorize/continue"}}
            ),
            "/authorize/continue",
        )
        self.assertEqual(openai_register.extract_continue_url({"page": {"payload": {}}}), "")

    def test_authorize_continue_resolves_relative_url(self):
        registrar = self._registrar(_FakeResponse(url="https://auth.openai.com/about-you"))

        registrar._authorize_continue("/authorize/continue?state=test", 2)

        method, url, kwargs = registrar.session.requests[0]
        self.assertEqual(method, "GET")
        self.assertEqual(url, "https://auth.openai.com/authorize/continue?state=test")
        self.assertTrue(kwargs["allow_redirects"])

    def test_authorize_continue_rejects_failed_response(self):
        registrar = self._registrar(_FakeResponse(status_code=401))

        with self.assertRaisesRegex(RuntimeError, "authorize_continue_http_401"):
            registrar._authorize_continue("https://auth.openai.com/authorize/continue", 2)

    def test_oauth_token_rejects_empty_code_before_request(self):
        class _NoRequestSession:
            def post(self, *_args, **_kwargs):
                self.fail("不应发起 token 请求")

            def fail(self, message):
                raise AssertionError(message)

        with self.assertRaisesRegex(RuntimeError, "OAuth code 为空"):
            openai_register.request_platform_oauth_token(_NoRequestSession(), "", "verifier")

    def test_create_account_rejects_missing_oauth_callback_code(self):
        registrar = self._registrar(_FakeResponse(json_data={}))
        artifacts = openai_register.SentinelArtifacts(token="sentinel-token")

        with patch.object(registrar, "_build_sentinel", return_value=artifacts):
            with self.assertRaisesRegex(RuntimeError, "未获得 OAuth code"):
                registrar._create_account("Test User", "2000-01-01", 1)

    def test_register_starts_passwordless_flow_and_keeps_password_empty(self):
        registrar = self._registrar()
        tokens = {"access_token": "access", "refresh_token": "refresh", "id_token": "id"}

        with patch.object(
            openai_register,
            "create_mailbox",
            return_value={"address": "new@example.com", "label": "test"},
        ), patch.object(openai_register, "wait_for_code", return_value="123456"), patch.object(
            registrar,
            "_platform_authorize",
        ), patch.object(registrar, "_start_passwordless_signup") as start_passwordless, patch.object(
            registrar,
            "_validate_otp",
        ), patch.object(registrar, "_create_account"), patch.object(
            registrar,
            "_exchange_registered_tokens",
            return_value=tokens,
        ):
            result = registrar.register(1)

        start_passwordless.assert_called_once_with(1)
        self.assertEqual(result["password"], "")
        self.assertEqual(result["access_token"], "access")

    def test_register_does_not_send_duplicate_otp_after_direct_verification_landing(self):
        registrar = self._registrar()
        tokens = {"access_token": "access", "refresh_token": "refresh", "id_token": "id"}

        def authorize(_email, _index):
            registrar.passwordless_signup = True

        with patch.object(
            openai_register,
            "create_mailbox",
            return_value={"address": "new@example.com", "label": "test"},
        ), patch.object(openai_register, "wait_for_code", return_value="123456"), patch.object(
            registrar,
            "_platform_authorize",
            side_effect=authorize,
        ), patch.object(registrar, "_start_passwordless_signup") as start_passwordless, patch.object(
            registrar,
            "_validate_otp",
        ), patch.object(registrar, "_create_account"), patch.object(
            registrar,
            "_exchange_registered_tokens",
            return_value=tokens,
        ):
            registrar.register(1)

        start_passwordless.assert_not_called()


class OpenAIRegisterEnvConfigTests(unittest.TestCase):
    def test_apply_env_mail_provider_uses_single_provider_config(self):
        base = {
            "mail": {
                "request_timeout": 30,
                "wait_timeout": 30,
                "wait_interval": 2,
                "providers": [{"enable": True, "type": "cloudmail_gen"}],
            }
        }
        env = {
            "REGISTER_MAIL_PROVIDER": "tempmail_lol",
            "REGISTER_MAIL_PROVIDER_CONFIG": json.dumps({"api_key": "secret", "domain": "a.example,b.example"}),
            "REGISTER_MAIL_WAIT_TIMEOUT": "45",
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = openai_register.apply_env_overrides(base)

        self.assertEqual(base["mail"]["providers"][0]["type"], "cloudmail_gen")
        self.assertEqual(cfg["mail"]["wait_timeout"], 45.0)
        self.assertEqual(
            cfg["mail"]["providers"],
            [{"api_key": "secret", "domain": ["a.example", "b.example"], "type": "tempmail_lol", "enable": True}],
        )

    def test_apply_env_mail_accepts_mail_json_object(self):
        base = {"mail": {"request_timeout": 30, "wait_timeout": 30, "wait_interval": 2, "providers": []}}
        env = {
            "REGISTER_MAIL": json.dumps(
                {
                    "request_timeout": 12,
                    "providers": [
                        {"type": "inbucket", "api_base": "https://mail.example", "domain": "example.com"},
                    ],
                }
            )
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = openai_register.apply_env_overrides(base)

        self.assertEqual(cfg["mail"]["request_timeout"], 12)
        self.assertEqual(
            cfg["mail"]["providers"],
            [{"type": "inbucket", "api_base": "https://mail.example", "domain": ["example.com"], "enable": True}],
        )

    def test_apply_env_mail_providers_accepts_full_mail_object(self):
        base = {"mail": {"request_timeout": 30, "wait_timeout": 30, "wait_interval": 2, "providers": []}}
        env = {
            "REGISTER_MAIL_PROVIDERS": json.dumps(
                {
                    "request_timeout": 20,
                    "providers": [{"type": "inbucket", "api_base": "https://mail.example", "domain": ["example.com"]}],
                }
            )
        }

        with patch.dict(os.environ, env, clear=True):
            cfg = openai_register.apply_env_overrides(base)

        self.assertEqual(cfg["mail"]["request_timeout"], 20)
        self.assertEqual(cfg["mail"]["providers"][0]["type"], "inbucket")

    def test_apply_env_mail_provider_rejects_invalid_json(self):
        with patch.dict(os.environ, {"REGISTER_MAIL_PROVIDER_CONFIG": "not-json", "REGISTER_MAIL_PROVIDER": "tempmail_lol"}, clear=True):
            with self.assertRaisesRegex(ValueError, "REGISTER_MAIL_PROVIDER_CONFIG"):
                openai_register.apply_env_overrides({"mail": {"providers": []}})


if __name__ == "__main__":
    unittest.main()
