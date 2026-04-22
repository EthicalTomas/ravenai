from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock
from ai.llm_client import LLMRequest, OpenAIClient, OpenRouterClient, LocalOllamaClient

class TestLLMProviders(unittest.TestCase):
    def setUp(self) -> None:
        self.request = LLMRequest(prompt="Hello", temperature=0.7, max_tokens=100)

    @patch("requests.post")
    def test_openai_provider(self, mock_post) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "OpenAI Response"}}]}
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        client = OpenAIClient(api_key="test-key", model="gpt-4")
        response = client.generate(self.request)

        self.assertEqual(response.content, "OpenAI Response")
        self.assertEqual(response.metadata["provider"], "openai")
        
        # Verify request
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(kwargs["json"]["model"], "gpt-4")

    @patch("requests.post")
    def test_openrouter_provider(self, mock_post) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "OpenRouter Response"}}]}
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        client = OpenRouterClient(api_key="test-key", model="meta-llama/llama-3-70b")
        response = client.generate(self.request)

        self.assertEqual(response.content, "OpenRouter Response")
        self.assertEqual(response.metadata["provider"], "openrouter")
        
        # Verify request
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://openrouter.ai/api/v1/chat/completions")

    @patch("requests.post")
    def test_local_ollama_provider(self, mock_post) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "Ollama Response"}
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        client = LocalOllamaClient(model="llama3")
        response = client.generate(self.request)

        self.assertEqual(response.content, "Ollama Response")
        self.assertEqual(response.metadata["provider"], "local")
        
        # Verify request
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://localhost:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "llama3")
        self.assertFalse(kwargs["json"]["stream"])

if __name__ == "__main__":
    unittest.main()
