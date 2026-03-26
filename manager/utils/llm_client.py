"""
manager/utils/llm_client.py — Unified local LLM client.

Supports Ollama and LM Studio via their OpenAI-compatible REST APIs.
Both expose POST /v1/chat/completions and GET /v1/models.
"""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from manager.config import settings


class LLMClient:
    """HTTP client for OpenAI-compatible local LLM servers."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def list_models(self) -> list[str]:
        """Return list of model IDs available on the backend."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{self.base_url}/v1/models")
            r.raise_for_status()
            data = r.json()
            return sorted(m["id"] for m in data.get("data", []))

    async def stream_chat(
        self,
        messages: list[dict],
        model: str,
        timeout: int = 120,
    ) -> AsyncIterator[str]:
        """
        Stream chat completion chunks from the LLM.

        Yields individual text chunks as they arrive.
        Parses NDJSON SSE lines from /v1/chat/completions with stream=true.
        """
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "temperature": 0.3,   # lower = more deterministic for security analysis
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/chat/completions",
                json=payload,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    chunk_str = line[6:]
                    if chunk_str.strip() == "[DONE]":
                        return
                    try:
                        chunk = json.loads(chunk_str)
                        delta = chunk["choices"][0]["delta"]
                        content = delta.get("content") or ""
                        if content:
                            yield content
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue

    async def complete(
        self,
        messages: list[dict],
        model: str,
        response_format: dict | None = None,
    ) -> tuple[str, int, int]:
        """
        Non-streaming chat completion.

        Returns (content, prompt_tokens, completion_tokens).
        Use for structured JSON output (triage_assist).
        """
        payload: dict = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": 0.1,
        }
        if response_format:
            payload["response_format"] = response_format

        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            return content, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))


def get_llm_client() -> LLMClient:
    """Factory: returns a client configured for the active backend."""
    if settings.llm_base_url:
        return LLMClient(settings.llm_base_url)
    if settings.llm_backend == "lmstudio":
        return LLMClient(settings.lm_studio_base_url)
    return LLMClient(settings.ollama_base_url)
