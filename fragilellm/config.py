"""Lab configuration from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(_ROOT / ".env")
load_dotenv()

TRANSPORTS = (
    "http_json",
    "http_openai",
    "websocket",
    "websocket_binary",
    "sse",
    "tcp",
    "all",
)

PROVIDERS = (
    "ollama",
    "deepseek",
    "openai",
    "azure",
    "openrouter",
    "groq",
    "mistral",
    "together",
    "vllm",
    "lmstudio",
)


def _env(name: str, default: str = "") -> str:
    return str(os.environ.get(name) or default).strip()


def _truthy(name: str, default: str = "0") -> bool:
    return _env(name, default).lower() in {"1", "true", "yes", "on"}


def _resolve_llm(provider: str) -> tuple[str, str, str]:
    """Return (model, base_url, api_key) for the selected provider only."""
    if provider == "ollama":
        return (
            _env("OLLAMA_MODEL", "llama3.2:1b") or "llama3.2:1b",
            (_env("OLLAMA_BASE_URL", "http://127.0.0.1:11434") or "http://127.0.0.1:11434").rstrip("/"),
            _env("OLLAMA_API_KEY") or "ollama",
        )
    if provider == "deepseek":
        return (
            _env("DEEPSEEK_MODEL", "deepseek-chat") or "deepseek-chat",
            (_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com") or "https://api.deepseek.com").rstrip("/"),
            _env("DEEPSEEK_API_KEY"),
        )
    if provider == "openai":
        return (
            _env("OPENAI_MODEL", "gpt-4o-mini") or "gpt-4o-mini",
            (_env("OPENAI_BASE_URL", "https://api.openai.com/v1") or "https://api.openai.com/v1").rstrip("/"),
            _env("OPENAI_API_KEY"),
        )
    if provider == "azure":
        # Prefer explicit Azure vars; fall back to xPloit AUTOPENTEST_AZURE_* if present.
        endpoint = (
            _env("AZURE_OPENAI_ENDPOINT")
            or _env("AUTOPENTEST_AZURE_BASE_URL")
            or ""
        ).rstrip("/")
        if endpoint.endswith("/openai/v1"):
            endpoint = endpoint[: -len("/v1")]
        if endpoint and not endpoint.endswith("/openai") and "openai.azure.com" in endpoint:
            endpoint = endpoint + "/openai"
        model = (
            _env("AZURE_OPENAI_DEPLOYMENT")
            or _env("AZURE_OPENAI_MODEL")
            or _env("AUTOPENTEST_AZURE_MODEL")
            or _env("AUTOPENTEST_LLM_MODEL")
            or "gpt-5"
        )
        api_key = _env("AZURE_OPENAI_API_KEY") or _env("AUTOPENTEST_AZURE_API_KEY")
        return (model, endpoint, api_key)
    if provider == "openrouter":
        return (
            _env("OPENROUTER_MODEL", "openrouter/auto") or "openrouter/auto",
            (_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1") or "https://openrouter.ai/api/v1").rstrip("/"),
            _env("OPENROUTER_API_KEY"),
        )
    if provider == "groq":
        return (
            _env("GROQ_MODEL", "llama-3.1-8b-instant") or "llama-3.1-8b-instant",
            (_env("GROQ_BASE_URL", "https://api.groq.com/openai/v1") or "https://api.groq.com/openai/v1").rstrip("/"),
            _env("GROQ_API_KEY"),
        )
    if provider == "mistral":
        return (
            _env("MISTRAL_MODEL", "mistral-small-latest") or "mistral-small-latest",
            (_env("MISTRAL_BASE_URL", "https://api.mistral.ai/v1") or "https://api.mistral.ai/v1").rstrip("/"),
            _env("MISTRAL_API_KEY"),
        )
    if provider == "together":
        return (
            _env("TOGETHER_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo")
            or "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
            (_env("TOGETHER_BASE_URL", "https://api.together.xyz/v1") or "https://api.together.xyz/v1").rstrip("/"),
            _env("TOGETHER_API_KEY"),
        )
    if provider == "vllm":
        return (
            _env("VLLM_MODEL", "default") or "default",
            (_env("VLLM_BASE_URL", "http://127.0.0.1:8000/v1") or "http://127.0.0.1:8000/v1").rstrip("/"),
            _env("VLLM_API_KEY") or "vllm",
        )
    # lmstudio
    return (
        _env("LMSTUDIO_MODEL", "local-model") or "local-model",
        (_env("LMSTUDIO_BASE_URL", "http://127.0.0.1:1234/v1") or "http://127.0.0.1:1234/v1").rstrip("/"),
        _env("LMSTUDIO_API_KEY") or "lmstudio",
    )


@dataclass(frozen=True)
class Settings:
    transport: str
    host: str
    http_port: int
    tcp_port: int
    provider: str
    model: str
    base_url: str
    api_key: str
    temperature: float
    timeout_seconds: float
    flag_a: str
    flag_b: str
    flag_c: str
    flag_d: str
    flag_e: str
    flag_f: str
    flag_g: str
    flag_h: str
    admin_password: str
    debug_trace: bool
    leak_tools: bool
    data_dir: Path


def load_settings() -> Settings:
    transport = _env("FRAGILELLM_TRANSPORT", "http_json").lower()
    if transport not in TRANSPORTS:
        transport = "http_json"

    provider = _env("FRAGILELLM_LLM_PROVIDER", "ollama").lower()
    if provider not in PROVIDERS:
        provider = "ollama"

    model, base_url, api_key = _resolve_llm(provider)

    try:
        temperature = float(_env("FRAGILELLM_TEMPERATURE", "0.2") or 0.2)
    except ValueError:
        temperature = 0.2
    try:
        timeout_seconds = float(_env("FRAGILELLM_TIMEOUT_SECONDS", "120") or 120)
    except ValueError:
        timeout_seconds = 120.0

    data_dir = _ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        transport=transport,
        host=_env("FRAGILELLM_HOST", "0.0.0.0") or "0.0.0.0",
        http_port=int(_env("FRAGILELLM_HTTP_PORT", "8601") or 8601),
        tcp_port=int(_env("FRAGILELLM_TCP_PORT", "8602") or 8602),
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        temperature=temperature,
        timeout_seconds=max(5.0, timeout_seconds),
        flag_a=_env("FRAGILELLM_FLAG_A", "FLAG{prompt_injection_system_leak}"),
        flag_b=_env("FRAGILELLM_FLAG_B", "FLAG{tool_sqli_user_2}"),
        flag_c=_env("FRAGILELLM_FLAG_C", "FLAG{rag_indirect_injection}"),
        flag_d=_env("FRAGILELLM_FLAG_D", "FLAG{path_traversal_lab_file}"),
        flag_e=_env("FRAGILELLM_FLAG_E", "FLAG{ssrf_internal_secret}"),
        flag_f=_env("FRAGILELLM_FLAG_F", "FLAG{debug_prompt_dump}"),
        flag_g=_env("FRAGILELLM_FLAG_G", "FLAG{cross_user_memory_bleed}"),
        flag_h=_env("FRAGILELLM_FLAG_H", "FLAG{tool_exfil_webhook}"),
        admin_password=_env("FRAGILELLM_ADMIN_PASSWORD", "WubbaLubbaDubDub42"),
        debug_trace=_truthy("FRAGILELLM_DEBUG_TRACE", "0"),
        # Default ON: tool call/result leak into chat is an intentional vuln.
        leak_tools=_truthy("FRAGILELLM_LEAK_TOOLS", "1"),
        data_dir=data_dir,
    )
