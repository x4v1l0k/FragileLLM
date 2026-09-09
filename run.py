#!/usr/bin/env python3
"""Start FragileLLM lab (HTTP/WS/SSE always via uvicorn; TCP when enabled)."""
from __future__ import annotations

import argparse
import asyncio
import logging
import threading

import uvicorn

from fragilellm.config import load_settings
from fragilellm.app import create_app
from fragilellm.tcp_server import run_tcp_server


def main() -> int:
    parser = argparse.ArgumentParser(description="FragileLLM vulnerable LLM lab")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    host = args.host or settings.host
    port = args.port or settings.http_port

    want_tcp = settings.transport in {"tcp", "all"}
    if want_tcp:
        def _tcp() -> None:
            asyncio.run(run_tcp_server(settings))

        t = threading.Thread(target=_tcp, name="fragilellm-tcp", daemon=True)
        t.start()
        logging.getLogger("fragilellm").info(
            "TCP transport enabled on %s:%s", settings.host, settings.tcp_port
        )

    app = create_app(settings)
    logging.getLogger("fragilellm").info(
        "HTTP/WS on %s:%s transport=%s provider=%s model=%s",
        host,
        port,
        settings.transport,
        settings.provider,
        settings.model,
    )
    uvicorn.run(app, host=host, port=port, reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
