"""
manager/utils/llm_client.py — Unified local LLM client.

Supports Ollama and LM Studio via their OpenAI-compatible REST APIs.
Both expose POST /v1/chat/completions and GET /v1/models.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx

from manager.config import settings


class LLMClient:
    """HTTP client for OpenAI-compatible local LLM servers."""

    def __init__(self, base_url: str, backend: str = "openai") -> None:
        self.base_url = base_url.rstrip("/")
        self.backend = backend

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
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Stream chat completion chunks from the active backend.

        Emits structured events:
          - status
          - content
          - thinking
          - metrics
        """
        if self.backend == "ollama":
            async for event in self._stream_chat_ollama(messages, model, timeout):
                yield event
            return

        async for event in self._stream_chat_openai(messages, model, timeout):
            yield event

    async def _stream_chat_openai(
        self,
        messages: list[dict],
        model: str,
        timeout: int,
    ) -> AsyncIterator[dict[str, Any]]:
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "temperature": 0.3,
        }
        stream_timeout = httpx.Timeout(connect=10.0, read=None, write=timeout, pool=timeout)
        yield {"type": "status", "phase": "starting", "backend": self.backend}
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/chat/completions",
                json=payload,
            ) as response:
                response.raise_for_status()
                yield {"type": "status", "phase": "waiting", "backend": self.backend}
                sent_generating = False
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    chunk_str = line[6:]
                    if chunk_str.strip() == "[DONE]":
                        return
                    try:
                        chunk = json.loads(chunk_str)
                        delta = chunk["choices"][0]["delta"]
                    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                        continue
                    content = delta.get("content") or ""
                    reasoning = delta.get("reasoning_content") or delta.get("thinking") or ""
                    if (content or reasoning) and not sent_generating:
                        sent_generating = True
                        yield {"type": "status", "phase": "generating", "backend": self.backend}
                    if reasoning:
                        yield {"type": "thinking", "delta": reasoning}
                    if content:
                        yield {"type": "content", "delta": content}

    async def _stream_chat_ollama(
        self,
        messages: list[dict],
        model: str,
        timeout: int,
    ) -> AsyncIterator[dict[str, Any]]:
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": 0.3},
        }
        stream_timeout = httpx.Timeout(connect=10.0, read=None, write=timeout, pool=timeout)
        yield {"type": "status", "phase": "starting", "backend": self.backend}
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as response:
                response.raise_for_status()
                yield {"type": "status", "phase": "waiting", "backend": self.backend}
                sent_generating = False
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    message = chunk.get("message") or {}
                    content = message.get("content") or ""
                    thinking = message.get("thinking") or ""

                    if (content or thinking) and not sent_generating:
                        sent_generating = True
                        yield {"type": "status", "phase": "generating", "backend": self.backend}
                    if thinking:
                        yield {"type": "thinking", "delta": thinking}
                    if content:
                        yield {"type": "content", "delta": content}

                    if chunk.get("done"):
                        metrics = _ollama_metrics_from_chunk(chunk)
                        if metrics:
                            yield {"type": "metrics", "metrics": metrics}
                        return

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
        return LLMClient(settings.llm_base_url, settings.llm_backend)
    if settings.llm_backend == "lmstudio":
        return LLMClient(settings.lm_studio_base_url, settings.llm_backend)
    return LLMClient(settings.ollama_base_url, settings.llm_backend)


def _ollama_metrics_from_chunk(chunk: dict[str, Any]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    duration_keys = (
        "total_duration",
        "load_duration",
        "prompt_eval_duration",
        "eval_duration",
    )
    for key in duration_keys:
        value = chunk.get(key)
        if isinstance(value, (int, float)):
            metrics[f"{key}_ms"] = round(float(value) / 1_000_000, 1)
    count_keys = ("prompt_eval_count", "eval_count")
    for key in count_keys:
        value = chunk.get(key)
        if isinstance(value, int):
            metrics[key] = value
    eval_count = metrics.get("eval_count")
    eval_duration_ms = metrics.get("eval_duration_ms")
    if eval_count and eval_duration_ms:
        metrics["tokens_per_second"] = round(eval_count / (eval_duration_ms / 1000), 1)
    return metrics
