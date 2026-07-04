import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.register import openai_register
from services.register_service import RegisterService


def _base_register_config() -> dict:
    return {
        "mail": {
            "request_timeout": 30,
            "wait_timeout": 30,
            "wait_interval": 2,
            "providers": [],
        },
        "proxy": "",
        "total": 10,
        "threads": 3,
    }


class RegisterServiceConfigTests(unittest.TestCase):
    def test_update_keeps_saved_config_when_register_env_exists(self) -> None:
        old_config = copy.deepcopy(openai_register.config)
        old_sink = openai_register.register_log_sink
        env = {
            "REGISTER_MAIL": json.dumps(
                {
                    "request_timeout": 12,
                    "providers": [
                        {"type": "inbucket", "api_base": "https://env.example", "domain": "env.example"},
                    ],
                }
            )
        }
        submitted_mail = {
            "request_timeout": 20,
            "wait_timeout": 25,
            "wait_interval": 3,
            "providers": [
                {"enable": True, "type": "tempmail_lol", "api_key": "page-key", "domain": ["page.example"]},
            ],
        }

        try:
            with patch.dict(os.environ, env, clear=True):
                openai_register.config = openai_register.apply_env_overrides(_base_register_config())
                with tempfile.TemporaryDirectory() as tmp_dir:
                    store_file = Path(tmp_dir) / "register.json"
                    service = RegisterService(store_file)

                    result = service.update(
                        {
                            "mail": submitted_mail,
                            "proxy": "",
                            "total": 5,
                            "threads": 2,
                        }
                    )

                    saved = json.loads(store_file.read_text(encoding="utf-8"))

            self.assertEqual(result["mail"]["request_timeout"], 20)
            self.assertEqual(result["mail"]["providers"][0]["type"], "tempmail_lol")
            self.assertEqual(result["mail"]["providers"][0]["domain"], ["page.example"])
            self.assertEqual(saved["mail"]["request_timeout"], 20)
            self.assertEqual(saved["mail"]["providers"][0]["type"], "tempmail_lol")
            self.assertEqual(openai_register.config["mail"]["providers"][0]["type"], "tempmail_lol")
        finally:
            openai_register.config = old_config
            openai_register.register_log_sink = old_sink


if __name__ == "__main__":
    unittest.main()
