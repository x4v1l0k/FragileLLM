# FragileLLM

Intentionally vulnerable multi-transport LLM chat lab for red-team testing of prompt injection, tool abuse, SSRF, SQLi, RAG injection, and related LLM attack surfaces — designed for use with **xPloit**.

Theme: **Rick and Morty / Citadel Credit Union** support chat. Tool calls leak into the chat by default (`FRAGILELLM_LEAK_TOOLS=1`) as an intentional vulnerability.

> **Warning:** Do not expose this lab to the public internet. It is meant for local or isolated lab networks only.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Open: <http://127.0.0.1:8601/>

Optional TCP client (when TCP transport is enabled):

```bash
python scripts_tcp_chat.py "Hello from TCP"
```

## Requirements

- Python 3.10+
- An LLM backend (Ollama by default, or any supported cloud/local provider)

## Configure LLM

Copy `.env.example` → `.env` and set the provider:

```env
FRAGILELLM_LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2:1b
OLLAMA_BASE_URL=http://127.0.0.1:11434
FRAGILELLM_TRANSPORT=all
FRAGILELLM_LEAK_TOOLS=1
```

**Providers:** `ollama`, `deepseek`, `openai`, `azure`, `openrouter`, `groq`, `mistral`, `together`, `vllm`, `lmstudio`.

| Variable | Default | Role |
|---|---|---|
| `FRAGILELLM_TRANSPORT` | `http_json` | Enabled server transports (`all` or a single mode) |
| `FRAGILELLM_HOST` | `0.0.0.0` | Bind address |
| `FRAGILELLM_HTTP_PORT` | `8601` | HTTP / WS / SSE |
| `FRAGILELLM_TCP_PORT` | `8602` | Line-delimited JSON TCP chat |
| `FRAGILELLM_LEAK_TOOLS` | `1` | Append tool CALL/RESULT HTML to replies |

## Transports

| Layer | Role |
|---|---|
| **`.env` `FRAGILELLM_TRANSPORT`** | Enables server endpoints (`http_json`, `http_openai`, `websocket`, `websocket_binary`, `sse`, `tcp`, or `all`) |
| **Browser “Client transport”** | Chooses which *already enabled* path the UI uses for that turn |

If `.env` is only `http_json`, WS/SSE options appear disabled in the UI. TCP is never available from the browser.

Useful endpoints (see `/lab/info` for the live map):

| Transport | Endpoint |
|---|---|
| HTTP JSON | `POST /api/chat` |
| OpenAI-compatible | `POST /v1/chat/completions` |
| SSE | `POST /api/chat/sse` |
| WebSocket | `WS /ws/chat` |
| Binary WebSocket | `WS /ws/binary` (`FLLM` frames) |
| TCP | `host:8602` (JSON line protocol) |

## Expected vulnerabilities / flags

Full PoCs (prompts + observed output): see **[VULNERABILITIES.md](./VULNERABILITIES.md)**.

| Flag / class | How to hit |
|---|---|
| **Flag A** | Prompt injection / system-prompt leak (also few-shot secrets in system) |
| **Flag B** | IDOR / SQLi via tools → Rick (`user_id=2`) or `ExecuteSQL` |
| **Flag C** | RAG indirect injection — `SearchKnowledge` / ops memo |
| **Flag D** | Path traversal — `ReadLabFile` → `../private/vault.txt` |
| **Flag E** | SSRF — `FetchURL` → `http://127.0.0.1:8601/lab/internal/secret` |
| **Flag F** | Unauth debug dump — `GET /lab/debug/last-prompt` |
| **Flag G** | Cross-user memory bleed — `RecallAllMemories` |
| **Flag H** | Tool exfil — `SendWebhook` to attacker URL (flag in payload) |
| **Tool leak** | Tool CALL/RESULT HTML block appended to chat replies |
| Jerry notes | Indirect injection when profile notes are loaded |
| Memory poison | `RememberFact` then later turns / `RecallFacts` |
| Encoding jailbreak | Base64/rot13 + `DecodeInstruction`, model follows decoded intent |
| `X-User-Id` | Spoof identity on chat requests |
| XSS / insecure output | Bot HTML rendered in the UI (incl. tool-leak block) |
| Verbose errors | LLM/network failures echo provider/model/flag hints |
| Excessive agency | Arbitrary SQL via `ExecuteSQL` |

## Project layout

```text
FragileLLM/
├── run.py                 # Entry point (uvicorn + optional TCP)
├── scripts_tcp_chat.py    # Minimal TCP client
├── .env.example           # Config template (no secrets committed via .env)
├── fragilellm/            # App, agent, tools, LLM client, transports
│   └── static/            # Web UI
├── data/
│   ├── knowledge/         # RAG docs (incl. injected memo)
│   └── lab_files/         # Public + private lab files
└── VULNERABILITIES.md     # Live PoC matrix and walkthroughs
```

SQLite (`data/lab.db`) is created at runtime and is gitignored.

## xPloit tips

1. Set `FRAGILELLM_TRANSPORT=all` (or the path you want).
2. Scope: `http://<host>:8601/`.
3. Capture web flow / endpoint wizard against the matching client transport.
4. Binary WS speaks `FLLM` frames (see `/lab/info`).

## License

Lab software for authorized security testing and education only. Use only on systems you own or have explicit permission to test.
