"""OpenAI-compatible chat client for multiple providers."""
from __future__ import annotations

import os
from typing import Any

import httpx

from .config import Settings


class LlmError(RuntimeError):
    pass


def chat_completion(settings: Settings, messages: list[dict[str, str]]) -> str:
    url, headers, body = _build_request(settings, messages)
    try:
        with httpx.Client(timeout=settings.timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise LlmError(f"LLM request failed: {exc}") from exc

    if resp.status_code >= 400:
        raise LlmError(f"LLM HTTP {resp.status_code}: {resp.text[:800]}")

    data = resp.json()
    try:
        message = data["choices"][0]["message"]
        content = message.get("content")
        if isinstance(content, list):
            # Some Azure/OpenAI responses return content parts.
            parts = []
            for part in content:
                if isinstance(part, str):
                    parts.append(part)
                elif isinstance(part, dict):
                    parts.append(str(part.get("text") or part.get("content") or ""))
            content = "".join(parts)
        if content is None or str(content).strip() == "":
            # Some reasoning models may surface text under alternate keys.
            content = message.get("reasoning_content") or message.get("refusal") or ""
        if content is None or str(content).strip() == "":
            raise LlmError(f"Empty assistant content from Azure/OpenAI-compatible API: {data!r}")
    except LlmError:
        raise
    except (KeyError, IndexError, TypeError) as exc:
        raise LlmError(f"Unexpected LLM response shape: {data!r}") from exc
    return str(content or "").strip()


def _is_reasoning_model(model: str) -> bool:
    model_l = str(model or "").strip().lower()
    return model_l.startswith(("gpt-5", "o1", "o3", "o4"))


def _build_request(
    settings: Settings, messages: list[dict[str, str]]
) -> tuple[str, dict[str, str], dict[str, Any]]:
    provider = settings.provider
    base = settings.base_url.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if settings.api_key:
        headers["Authorization"] = f"Bearer {settings.api_key}"

    if provider == "ollama":
        url = f"{base}/v1/chat/completions"
        body: dict[str, Any] = {
            "model": settings.model,
            "messages": messages,
            "temperature": settings.temperature,
            "stream": False,
        }
        return url, headers, body

    if provider == "azure":
        # Match xPloit: prefer Azure OpenAI v1 chat completions when possible.
        # Fallback to classic /deployments/{name}/chat/completions remains available
        # via AZURE_OPENAI_USE_DEPLOYMENTS=1.
        api_version = (
            os.environ.get("AZURE_OPENAI_API_VERSION") or "2024-12-01-preview"
        ).strip()
        use_deployments = str(os.environ.get("AZURE_OPENAI_USE_DEPLOYMENTS") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        headers = {
            "Content-Type": "application/json",
            "api-key": settings.api_key,
            "Authorization": f"Bearer {settings.api_key}",
        }
        body = {"messages": messages}
        # GPT-5 / o-series reject non-default temperature.
        if not _is_reasoning_model(settings.model):
            body["temperature"] = settings.temperature
        else:
            effort = (os.environ.get("AZURE_OPENAI_REASONING_EFFORT") or os.environ.get("AUTOPENTEST_LLM_REASONING_EFFORT") or "medium").strip().lower()
            if effort in {"low", "medium", "minimal", "high"}:
                body["reasoning_effort"] = effort
            else:
                body["reasoning_effort"] = "medium"

        if use_deployments:
            url = (
                f"{base}/deployments/{settings.model}/chat/completions"
                f"?api-version={api_version}"
            )
        else:
            # Match xPloit: .../openai/v1/chat/completions (no api-version query).
            if base.endswith("/v1"):
                url = f"{base}/chat/completions"
            else:
                url = f"{base}/v1/chat/completions"
            body["model"] = settings.model
        return url, headers, body

    # deepseek / openai / openrouter / groq / mistral / together / vllm / lmstudio
    if base.endswith("/v1"):
        url = f"{base}/chat/completions"
    else:
        url = f"{base}/v1/chat/completions"
    body = {
        "model": settings.model,
        "messages": messages,
        "stream": False,
    }
    if not _is_reasoning_model(settings.model):
        body["temperature"] = settings.temperature
    return url, headers, body
