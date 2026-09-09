"""Simple binary WebSocket framing for xPloit capture/replay labs.

Frame layout (big-endian):
  magic: 4 bytes = b'FLLM'
  version: 1 byte = 1
  msg_type: 1 byte (1=chat_request, 2=chat_response, 3=error)
  flags: 1 byte (reserved)
  reserved: 1 byte = 0
  length: uint32 body length
  body: UTF-8 JSON

This is intentionally simpler than Streamlit protobuf while still being
WebSocket BINARY traffic for transport testing.
"""
from __future__ import annotations

import json
import struct
from typing import Any

MAGIC = b"FLLM"
VERSION = 1
TYPE_REQUEST = 1
TYPE_RESPONSE = 2
TYPE_ERROR = 3

HEADER_FMT = "!4sBBBBI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def pack_message(msg_type: int, payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, msg_type, 0, 0, len(body))
    return header + body


def unpack_message(data: bytes) -> tuple[int, dict[str, Any]]:
    if len(data) < HEADER_SIZE:
        raise ValueError("frame too short")
    magic, version, msg_type, _flags, _res, length = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError(f"bad magic: {magic!r}")
    if version != VERSION:
        raise ValueError(f"unsupported version: {version}")
    body = data[HEADER_SIZE : HEADER_SIZE + length]
    if len(body) != length:
        raise ValueError("truncated body")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    return int(msg_type), payload


def pack_request(message: str, session_id: str = "") -> bytes:
    return pack_message(TYPE_REQUEST, {"message": message, "session_id": session_id})


def pack_response(reply: str, **extra: Any) -> bytes:
    payload = {"reply": reply}
    payload.update(extra)
    return pack_message(TYPE_RESPONSE, payload)


def pack_error(error: str) -> bytes:
    return pack_message(TYPE_ERROR, {"error": error})
