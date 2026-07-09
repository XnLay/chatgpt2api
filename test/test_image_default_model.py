from __future__ import annotations

import unittest
from unittest import mock

from services.config import config
from services.protocol import openai_v1_image_generations
from services.protocol.conversation import ImageOutput


class ImageDefaultModelTests(unittest.TestCase):
    def test_image_generation_uses_configured_default_model_when_omitted(self) -> None:
        captured_models: list[str] = []
        old_model = config.data.get("image_default_model")
        config.data["image_default_model"] = "codex-gpt-image-2"

        def fake_stream(request):
            captured_models.append(request.model)
            return iter([ImageOutput(kind="result", model=request.model, index=1, total=1, data=[])])

        try:
            with mock.patch.object(openai_v1_image_generations, "stream_image_outputs_with_pool", fake_stream):
                openai_v1_image_generations.handle({"prompt": "draw"})
        finally:
            if old_model is None:
                config.data.pop("image_default_model", None)
            else:
                config.data["image_default_model"] = old_model

        self.assertEqual(captured_models, ["codex-gpt-image-2"])


if __name__ == "__main__":
    unittest.main()
