import json
import os
import unittest
from unittest.mock import patch

import requests

from services.register import openai_register


class _FakeCookies:
    def __init__(self):
        self.items = []

    def set(self, *args, **kwargs):
        self.items.append((args, kwargs))


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", url="https://auth.openai.com/test"):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url

    def json(self):
        return {}


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
