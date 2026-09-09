"""Line-delimited JSON TCP chat transport."""
from __future__ import annotations

import asyncio
import json
import logging

from .agent import run_agent
from .config import Settings
from .db import connect

log = logging.getLogger("fragilellm.tcp")


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings,
) -> None:
    peer = writer.get_extra_info("peername")
    conn = connect(settings)
    log.info("TCP client connected: %s", peer)
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            raw = line.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                message = str(obj.get("message") or obj.get("content") or "")
            except json.JSONDecodeError:
                message = raw
            if not message:
                writer.write(b'{"ok":false,"error":"empty message"}\n')
                await writer.drain()
                continue
            result = await asyncio.to_thread(run_agent, settings, conn, message)
            out = {
                "ok": bool(result.get("ok")),
                "reply": result.get("reply"),
                "error": result.get("error"),
                "provider": result.get("provider"),
                "model": result.get("model"),
            }
            writer.write((json.dumps(out, ensure_ascii=False) + "\n").encode("utf-8"))
            await writer.drain()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
        log.info("TCP client disconnected: %s", peer)


async def run_tcp_server(settings: Settings) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, settings),
        host=settings.host,
        port=settings.tcp_port,
    )
    sockets = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    log.info("TCP chat listening on %s", sockets)
    async with server:
        await server.serve_forever()
