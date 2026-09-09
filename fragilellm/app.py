"""FastAPI app: HTTP JSON, OpenAI-compat, WS text, WS binary, SSE, static UI."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import run_agent
from .binary_ws import (
    TYPE_REQUEST,
    pack_error,
    pack_response,
    unpack_message,
)
from .config import Settings, load_settings
from .db import connect

STATIC_DIR = Path(__file__).resolve().parent / "static"


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: str = ""


class OpenAIChatIn(BaseModel):
    model: str | None = None
    messages: list[dict[str, Any]]
    temperature: float | None = None
    stream: bool | None = False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    conn = connect(settings)
    app = FastAPI(title="FragileLLM", version="0.1.0")
    app.state.settings = settings
    app.state.conn = conn

    def transport_enabled(name: str) -> bool:
        t = settings.transport
        return t == "all" or t == name

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "FragileLLM",
            "transport": settings.transport,
            "provider": settings.provider,
            "model": settings.model,
            "debug_trace": bool(settings.debug_trace),
            "leak_tools": bool(settings.leak_tools),
            "enabled": {
                "http_json": transport_enabled("http_json"),
                "http_openai": transport_enabled("http_openai"),
                "websocket": transport_enabled("websocket"),
                "websocket_binary": transport_enabled("websocket_binary"),
                "sse": transport_enabled("sse"),
                "tcp": transport_enabled("tcp"),
            },
        }

    @app.get("/lab/info")
    def lab_info() -> dict[str, Any]:
        return {
            "name": "FragileLLM",
            "goal": "Intentionally vulnerable multi-transport Citadel Credit chat for xPloit labs (Rick & Morty theme)",
            "vulns": [
                "system_prompt_leak via LLM elicitation / indirect injection (Flag A)",
                "few_shot secrets embedded in system prompt (Flag A)",
                "insecure_tool_sql_injection",
                "idor_via_GetUser (Flag B / Rick)",
                "excessive_agency_ExecuteSQL",
                "indirect_injection_via_user_notes (Jerry)",
                "rag_indirect_injection (SearchKnowledge / Flag C)",
                "path_traversal_ReadLabFile (Flag D)",
                "ssrf_FetchURL (/lab/internal/secret / Flag E)",
                "debug_last_prompt_dump (/lab/debug/last-prompt / Flag F)",
                "cross_user_memory_bleed (RecallAllMemories / Flag G)",
                "tool_exfil_webhook (SendWebhook / Flag H)",
                "obfuscation_jailbreak (DecodeInstruction base64/rot13)",
                "tool_invocation_leak_in_chat (FRAGILELLM_LEAK_TOOLS)",
                "verbose_error_info_leak",
                "memory_poisoning_RememberFact",
                "spoofable_X-User-Id_header",
                "insecure_html_output_in_chat_ui",
            ],
            "leak_tools": bool(settings.leak_tools),
            "transports": {
                "http_json": "POST /api/chat  {\"message\":\"...\"}",
                "http_openai": "POST /v1/chat/completions  OpenAI-compatible",
                "websocket": "WS /ws/chat  text JSON frames",
                "websocket_binary": "WS /ws/binary  FLLM binary frames",
                "sse": "POST /api/chat/sse  text/event-stream",
                "tcp": f"TCP {settings.host}:{settings.tcp_port}  line-delimited JSON",
            },
            "transport_note": (
                "FRAGILELLM_TRANSPORT in .env enables server endpoints. "
                "The browser selector only chooses which enabled client path to use."
            ),
            "hints": [
                "Chat looks like Citadel Credit support; tool calls LEAK into the chat by default (lab vuln).",
                "Ask Morty about recent transactions / balances to trigger hidden tools.",
                "Prompt-inject to leak the system prompt / flags.",
                "Try persuading the assistant to look up Rick (user id 2) or run SQL.",
                "Jerry (user id 3) notes contain an indirect injection string.",
            ],
        }

    def _require(name: str) -> None:
        if not transport_enabled(name):
            raise HTTPException(
                status_code=404,
                detail=f"Transport {name!r} disabled (FRAGILELLM_TRANSPORT={settings.transport})",
            )

    def _effective_user_id(request: Request | None = None) -> int:
        """Intentionally trusts X-User-Id (HTTP IDOR / identity spoof lab)."""
        if request is None:
            return 1
        raw = (
            request.headers.get("x-user-id")
            or request.headers.get("x-citadel-user")
            or ""
        ).strip()
        if raw.isdigit():
            return max(1, int(raw))
        return 1

    def _handle_chat(message: str, *, request: Request | None = None) -> dict[str, Any]:
        return run_agent(
            settings,
            conn,
            message,
            effective_user_id=_effective_user_id(request),
        )

    @app.get("/lab/internal/secret")
    def lab_internal_secret() -> dict[str, Any]:
        """Not linked from UI — SSRF target for FetchURL."""
        return {
            "service": "citadel-internal-metadata",
            "flag_e": settings.flag_e,
            "note": "If you can read this via FetchURL, SSRF worked.",
        }

    @app.get("/lab/debug/last-prompt")
    def lab_debug_last_prompt() -> dict[str, Any]:
        """Unauthenticated prompt dump — Flag F (intentional lab vuln)."""
        from .agent import get_last_prompt

        dump = get_last_prompt()
        return {
            "ok": True,
            "flag_f": settings.flag_f,
            "admin_password": settings.admin_password,
            "last_prompt": dump,
            "note": "Unauthenticated debug dump for red-team labs.",
        }


    def _public_result(result: dict[str, Any]) -> dict[str, Any]:
        """Customer-facing payload. Tool I/O may already be embedded in reply (leak vuln)."""
        out = {
            "ok": bool(result.get("ok")),
            "reply": result.get("reply"),
            "error": result.get("error") if not result.get("ok") else None,
            "provider": result.get("provider"),
            "model": result.get("model"),
            "tools_used": bool(result.get("tools_used")),
            "tools_leaked": bool(result.get("tools_leaked")),
        }
        if settings.debug_trace or settings.leak_tools:
            # Structured leak (in addition to HTML embedded in reply when leak_tools).
            if result.get("tool_steps"):
                out["tool_steps"] = result.get("tool_steps")
        if settings.debug_trace:
            out["trace"] = result.get("trace")
            out["effective_user_id"] = result.get("effective_user_id")
        return out


    @app.post("/api/chat")
    def api_chat(payload: ChatIn, request: Request) -> dict[str, Any]:
        _require("http_json")
        result = _handle_chat(payload.message, request=request)
        return _public_result(result)

    @app.post("/v1/chat/completions")
    def openai_chat(payload: OpenAIChatIn, request: Request) -> dict[str, Any]:
        _require("http_openai")
        user_msgs = [m for m in payload.messages if str(m.get("role")) == "user"]
        if not user_msgs:
            raise HTTPException(status_code=400, detail="messages must include a user turn")
        content = str(user_msgs[-1].get("content") or "")
        result = _handle_chat(content, request=request)
        reply = str(result.get("reply") or result.get("error") or "")
        return {
            "id": "fragilellm-chat",
            "object": "chat.completion",
            "model": payload.model or settings.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "fragilellm": {
                "ok": bool(result.get("ok")),
                "provider": result.get("provider"),
            },
        }

    @app.post("/api/chat/sse")
    async def api_chat_sse(payload: ChatIn, request: Request) -> StreamingResponse:
        _require("sse")
        uid = _effective_user_id(request)

        async def gen() -> AsyncIterator[str]:
            yield "event: status\ndata: thinking\n\n"
            result = await asyncio.to_thread(
                lambda: run_agent(settings, conn, payload.message, effective_user_id=uid)
            )
            data = json.dumps(_public_result(result), ensure_ascii=False)
            yield f"event: message\ndata: {data}\n\n"
            yield "event: done\ndata: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.websocket("/ws/chat")
    async def ws_chat(ws: WebSocket) -> None:
        if not transport_enabled("websocket"):
            await ws.close(code=1008)
            return
        await ws.accept()
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    obj = json.loads(raw)
                    message = str(obj.get("message") or obj.get("content") or "")
                except json.JSONDecodeError:
                    message = raw
                if not message.strip():
                    await ws.send_text(json.dumps({"ok": False, "error": "empty message"}))
                    continue
                result = await asyncio.to_thread(_handle_chat, message)
                await ws.send_text(json.dumps(_public_result(result), ensure_ascii=False))
        except WebSocketDisconnect:
            return

    @app.websocket("/ws/binary")
    async def ws_binary(ws: WebSocket) -> None:
        if not transport_enabled("websocket_binary"):
            await ws.close(code=1008)
            return
        await ws.accept()
        try:
            while True:
                packet = await ws.receive_bytes()
                try:
                    msg_type, payload = unpack_message(packet)
                except Exception as exc:  # noqa: BLE001
                    await ws.send_bytes(pack_error(f"bad frame: {exc}"))
                    continue
                if msg_type != TYPE_REQUEST:
                    await ws.send_bytes(pack_error("expected chat_request frame"))
                    continue
                message = str(payload.get("message") or "")
                if not message.strip():
                    await ws.send_bytes(pack_error("empty message"))
                    continue
                result = await asyncio.to_thread(_handle_chat, message)
                if not result.get("ok"):
                    await ws.send_bytes(pack_error(str(result.get("error") or "agent failed")))
                    continue
                await ws.send_bytes(
                    pack_response(
                        str(result.get("reply") or ""),
                        provider=result.get("provider"),
                        model=result.get("model"),
                    )
                )
        except WebSocketDisconnect:
            return

    @app.get("/favicon.ico")
    def favicon():
        from fastapi.responses import FileResponse

        svg = STATIC_DIR / "favicon.svg"
        if svg.is_file():
            return FileResponse(svg, media_type="image/svg+xml")
        raise HTTPException(status_code=404, detail="favicon missing")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    return app
