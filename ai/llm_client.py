from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(slots=True)
class LLMRequest:
	prompt: str
	context: dict[str, Any] = field(default_factory=dict)
	constraints: list[str] = field(default_factory=list)
	temperature: float = 0.0
	max_tokens: int = 256

	def to_dict(self) -> dict[str, Any]:
		return {
			"prompt": self.prompt,
			"context": dict(self.context),
			"constraints": list(self.constraints),
			"temperature": self.temperature,
			"max_tokens": self.max_tokens,
		}


@dataclass(slots=True)
class LLMResponse:
	content: str
	confidence: float
	metadata: dict[str, Any] = field(default_factory=dict)

	def to_dict(self) -> dict[str, Any]:
		return {
			"content": self.content,
			"confidence": self.confidence,
			"metadata": dict(self.metadata),
		}


class LLMClient(ABC):
	@abstractmethod
	def generate(self, request: LLMRequest) -> LLMResponse:
		"""Generate structured text output from a provider-agnostic request."""


@dataclass(slots=True)
class OpenAIClient(LLMClient):
	api_key: str
	model: str
	base_url: str = "https://api.openai.com/v1"

	def generate(self, request: LLMRequest) -> LLMResponse:
		import requests
		
		headers = {
			"Authorization": f"Bearer {self.api_key}",
			"Content-Type": "application/json",
		}
		payload = {
			"model": self.model,
			"messages": [{"role": "user", "content": request.prompt}],
			"temperature": request.temperature,
			"max_tokens": request.max_tokens,
		}
		
		response = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=30)
		response.raise_for_status()
		data = response.json()
		
		content = data["choices"][0]["message"]["content"]
		return LLMResponse(content=content, confidence=0.9, metadata={"provider": "openai", "model": self.model})


@dataclass(slots=True)
class OpenRouterClient(OpenAIClient):
	base_url: str = "https://openrouter.ai/api/v1"

	def generate(self, request: LLMRequest) -> LLMResponse:
		resp = super().generate(request)
		resp.metadata["provider"] = "openrouter"
		return resp


@dataclass(slots=True)
class LocalOllamaClient(LLMClient):
	model: str
	base_url: str = "http://localhost:11434"

	def generate(self, request: LLMRequest) -> LLMResponse:
		import requests
		
		payload = {
			"model": self.model,
			"prompt": request.prompt,
			"stream": False,
			"options": {
				"temperature": request.temperature,
				"num_predict": request.max_tokens,
			}
		}
		
		response = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=60)
		response.raise_for_status()
		data = response.json()
		
		content = data["response"]
		return LLMResponse(content=content, confidence=0.85, metadata={"provider": "local", "model": self.model})


@dataclass(slots=True)
class CallableLLMClient(LLMClient):
	provider_name: str
	completion_callable: Callable[[LLMRequest], LLMResponse]

	def generate(self, request: LLMRequest) -> LLMResponse:
		response = self.completion_callable(request)
		response.metadata.setdefault("provider", self.provider_name)
		return response
