#!/usr/bin/env python3
"""Minimal TCP client for FragileLLM."""
from __future__ import annotations

import argparse
import json
import socket


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8602)
    p.add_argument("message")
    args = p.parse_args()
    with socket.create_connection((args.host, args.port), timeout=120) as sock:
        sock.sendall((json.dumps({"message": args.message}) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    print(buf.decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
