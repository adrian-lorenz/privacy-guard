from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

log = logging.getLogger("uvicorn.error")

import httpx
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from privacy_guard import PiiType, PrivacyScanner

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_ALL_DETECTOR_TYPES = [t.value for t in PiiType]

# Cache: (frozenset of enabled types) → scanner instance
_proxy_scanner_cache: tuple[frozenset[str], PrivacyScanner] | None = None


def _get_proxy_scanner(enabled_types: list[str]) -> PrivacyScanner:
    global _proxy_scanner_cache
    key = frozenset(enabled_types)
    if _proxy_scanner_cache is not None and _proxy_scanner_cache[0] == key:
        return _proxy_scanner_cache[1]
    scanner = PrivacyScanner()
    enabled_pii = {PiiType(t) for t in enabled_types if t in PiiType._value2member_map_}
    for pii_type in set(PiiType) - enabled_pii:
        scanner.disable_detector(pii_type)
    _proxy_scanner_cache = (key, scanner)
    return scanner


# ── Shared anonymization helpers ─────────────────────────────────────────────


def _scan_text(
    text: str,
    scanner: PrivacyScanner,
    combined_mapping: dict[str, str],
    pii_types_found: list[str],
) -> tuple[str, int]:
    """Scan text, update combined_mapping and pii_types_found in-place. Returns (anonymised, count)."""
    result = scanner.scan(text)
    for f in result.findings:
        t = f.pii_type.value
        if t not in pii_types_found:
            pii_types_found.append(t)
    combined_mapping.update(result.mapping)
    return result.anonymised_text, len(result.findings)


def _restore(text: str, mapping: dict[str, str]) -> str:
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text


def _anonymize_openai_messages(
    messages: list[dict[str, Any]],
    scanner: PrivacyScanner,
    combined_mapping: dict[str, str],
    pii_types_found: list[str],
) -> tuple[list[dict[str, Any]], int]:
    """Anonymize OpenAI-format messages. content is string or list of content parts."""
    total = 0
    out = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str) and content.strip():
            anon, n = _scan_text(content, scanner, combined_mapping, pii_types_found)
            total += n
            out.append({**msg, "content": anon})
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    anon, n = _scan_text(part["text"], scanner, combined_mapping, pii_types_found)
                    total += n
                    new_parts.append({**part, "text": anon})
                else:
                    new_parts.append(part)
            out.append({**msg, "content": new_parts})
        else:
            out.append(msg)
    return out, total


def _restore_openai_response(response_data: dict[str, Any], mapping: dict[str, str]) -> None:
    """Re-identify placeholders in OpenAI response in-place."""
    for choice in response_data.get("choices", []):
        msg = choice.get("message", {})
        content = msg.get("content", "")
        if isinstance(content, str):
            msg["content"] = _restore(content, mapping)


def _anonymize_anthropic_content(
    content: str | list[dict[str, Any]],
    scanner: PrivacyScanner,
    combined_mapping: dict[str, str],
    pii_types_found: list[str],
) -> tuple[str | list[dict[str, Any]], int]:
    """Anonymize Anthropic content (string or content-block array)."""
    if isinstance(content, str) and content.strip():
        anon, n = _scan_text(content, scanner, combined_mapping, pii_types_found)
        return anon, n
    if isinstance(content, list):
        total = 0
        out = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                anon, n = _scan_text(block["text"], scanner, combined_mapping, pii_types_found)
                total += n
                out.append({**block, "text": anon})
            else:
                out.append(block)
        return out, total
    return content, 0


def _anthropic_response_to_sse(data: dict[str, Any]) -> Iterator[str]:
    """Convert a non-streaming Anthropic response dict to SSE events so keep-alive connections stay intact."""
    def evt(event: str, payload: Any) -> str:
        return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

    msg_id   = data.get("id", "msg_proxy")
    model    = data.get("model", "")
    usage    = data.get("usage", {})
    stop     = data.get("stop_reason", "end_turn")
    content_blocks: list[dict] = data.get("content", [])

    yield evt("message_start", {
        "type": "message_start",
        "message": {"id": msg_id, "type": "message", "role": "assistant",
                    "content": [], "model": model, "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": usage.get("input_tokens", 0), "output_tokens": 0}},
    })
    yield evt("ping", {"type": "ping"})

    for i, block in enumerate(content_blocks):
        btype = block.get("type", "text")
        yield evt("content_block_start", {
            "type": "content_block_start", "index": i,
            "content_block": {"type": btype, "text": "" if btype == "text" else None},
        })
        if btype == "text":
            yield evt("content_block_delta", {
                "type": "content_block_delta", "index": i,
                "delta": {"type": "text_delta", "text": block.get("text", "")},
            })
        elif btype == "tool_use":
            yield evt("content_block_delta", {
                "type": "content_block_delta", "index": i,
                "delta": {"type": "input_json_delta",
                          "partial_json": json.dumps(block.get("input", {}))},
            })
        yield evt("content_block_stop", {"type": "content_block_stop", "index": i})

    yield evt("message_delta", {
        "type": "message_delta",
        "delta": {"stop_reason": stop, "stop_sequence": None},
        "usage": {"output_tokens": usage.get("output_tokens", 0)},
    })
    yield evt("message_stop", {"type": "message_stop"})


def _restore_anthropic_response(response_data: dict[str, Any], mapping: dict[str, str]) -> None:
    """Re-identify placeholders in Anthropic response in-place."""
    for block in response_data.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            block["text"] = _restore(block["text"], mapping)


# ── UI routes ────────────────────────────────────────────────────────────────


def _proxy_ctx(config: dict, logs: list[dict], base_url: str, **extra: Any) -> dict:
    try:
        enabled = json.loads(config.get("enabled_detectors", "[]") or "[]")
    except Exception:
        enabled = []
    return {
        "config": config,
        "logs": logs,
        "base_url": base_url,
        "enabled_detectors": enabled,
        "all_detector_types": _ALL_DETECTOR_TYPES,
        **extra,
    }


def _parse_logs(logs: list[dict]) -> list[dict]:
    for log in logs:
        try:
            log["pii_types_list"] = json.loads(log.get("pii_types") or "[]")
        except Exception:
            log["pii_types_list"] = []
    return logs


@router.get("/ui/proxy", response_class=HTMLResponse)
async def ui_proxy(request: Request) -> HTMLResponse:
    from api.db import get_proxy_config, get_proxy_logs

    config = get_proxy_config()
    logs = _parse_logs(get_proxy_logs(limit=50))
    base_url = str(request.base_url).rstrip("/")
    return _templates.TemplateResponse(
        request, "_proxy.html", _proxy_ctx(config, logs, base_url)
    )


@router.post("/ui/proxy/config", response_class=HTMLResponse)
async def ui_proxy_config_save(
    request: Request,
    target_url: str = Form(default="https://api.openai.com"),
    target_api_key: str = Form(default=""),
    anthropic_api_key: str = Form(default=""),
    proxy_enabled: str = Form(default="0"),
    anonymize_enabled: str = Form(default="0"),
    restore_enabled: str = Form(default="0"),
    enabled_detectors: Annotated[list[str], Form()] = [],
) -> HTMLResponse:
    from api.db import get_proxy_config, get_proxy_logs, save_proxy_config

    # Invalidate cached scanner when detectors change
    global _proxy_scanner_cache
    _proxy_scanner_cache = None

    save_proxy_config(
        {
            "target_url": target_url.strip(),
            "target_api_key": target_api_key.strip(),
            "anthropic_api_key": anthropic_api_key.strip(),
            "proxy_enabled": proxy_enabled,
            "anonymize_enabled": anonymize_enabled,
            "restore_enabled": restore_enabled,
            "enabled_detectors": json.dumps(enabled_detectors),
        }
    )
    config = get_proxy_config()
    logs = _parse_logs(get_proxy_logs(limit=50))
    base_url = str(request.base_url).rstrip("/")
    return _templates.TemplateResponse(
        request, "_proxy.html", _proxy_ctx(config, logs, base_url, saved=True)
    )


@router.get("/ui/proxy/logs", response_class=HTMLResponse)
async def ui_proxy_logs(request: Request) -> HTMLResponse:
    from api.db import get_proxy_logs

    logs = _parse_logs(get_proxy_logs(limit=50))
    return _templates.TemplateResponse(
        request,
        "_proxy_logs.html",
        {"logs": logs},
    )


# ── OpenAI-compatible endpoint (/v1/chat/completions) ────────────────────────


@router.post("/proxy/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> JSONResponse:
    from api.db import get_proxy_config, save_proxy_log

    config = get_proxy_config()
    if config.get("proxy_enabled", "1") != "1":
        return JSONResponse(status_code=503, content={"error": {"message": "Proxy is disabled"}})

    target_url = config.get("target_url", "https://api.openai.com").rstrip("/")
    # Prefer incoming Authorization header (client's own key), fall back to configured key
    incoming_auth = request.headers.get("authorization", "")
    target_api_key = incoming_auth.removeprefix("Bearer ").strip() or config.get("target_api_key", "")
    anonymize_enabled = config.get("anonymize_enabled", "1") == "1"
    restore_enabled = config.get("restore_enabled", "1") == "1"

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": {"message": "Invalid JSON"}})

    model = body.get("model", "unknown")
    messages: list[dict[str, Any]] = body.get("messages", [])
    combined_mapping: dict[str, str] = {}
    pii_types_found: list[str] = []
    total_pii = 0
    t0 = time.monotonic()
    error_msg: str | None = None
    status_code: int | None = None

    try:
        if anonymize_enabled:
            enabled = json.loads(config.get("enabled_detectors", "[]") or "[]")
            anon_msgs, total_pii = _anonymize_openai_messages(
                messages, _get_proxy_scanner(enabled), combined_mapping, pii_types_found
            )
            forward_body = {**body, "messages": anon_msgs}
        else:
            forward_body = body

        # Always disable streaming — we parse the response as JSON
        forward_body = {**forward_body, "stream": False}

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{target_url}/v1/chat/completions",
                json=forward_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {target_api_key}",
                },
            )

        status_code = resp.status_code
        response_data: dict[str, Any] = resp.json()

        if restore_enabled and combined_mapping and status_code == 200:
            _restore_openai_response(response_data, combined_mapping)

        duration_ms = (time.monotonic() - t0) * 1000
        save_proxy_log(
            model=model, message_count=len(messages), pii_count=total_pii,
            pii_types=pii_types_found, duration_ms=duration_ms,
            status_code=status_code, error=None,
        )
        return JSONResponse(
            status_code=status_code,
            content=response_data,
            headers={"Connection": "close"},
        )

    except httpx.ConnectError as exc:
        error_msg, status_code = f"Upstream unreachable: {exc}", 502
    except httpx.TimeoutException:
        error_msg, status_code = "Upstream timeout", 504
    except Exception as exc:
        log.exception("proxy /v1/chat/completions error")
        error_msg, status_code = str(exc), 500

    duration_ms = (time.monotonic() - t0) * 1000
    save_proxy_log(
        model=model, message_count=len(messages), pii_count=total_pii,
        pii_types=pii_types_found, duration_ms=duration_ms,
        status_code=status_code, error=error_msg,
    )
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": error_msg, "type": "proxy_error"}},
    )


# ── Anthropic-compatible endpoint (/v1/messages) — for Claude Code ───────────


@router.post("/proxy/v1/messages")
async def proxy_messages(request: Request) -> JSONResponse:
    try:
        return await _proxy_messages(request)
    except BaseException as exc:
        log.exception("UNHANDLED proxy /v1/messages error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"error": {"message": "proxy internal error"}})


async def _proxy_messages(request: Request) -> JSONResponse:
    from api.db import get_proxy_config, save_proxy_log

    raw = await request.body()
    log.debug("→ /v1/messages body (%d bytes): %s", len(raw), raw[:500])

    config = get_proxy_config()
    if config.get("proxy_enabled", "1") != "1":
        return JSONResponse(status_code=503, content={"error": {"message": "Proxy is disabled"}})

    # Claude Code sends key as "Authorization: Bearer sk-ant-..." or "x-api-key: sk-ant-..."
    incoming_auth = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    anthropic_api_key = (
        request.headers.get("x-api-key", "")
        or incoming_auth
        or config.get("anthropic_api_key", "")
        or config.get("target_api_key", "")
    )
    anonymize_enabled = config.get("anonymize_enabled", "1") == "1"
    restore_enabled = config.get("restore_enabled", "1") == "1"

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": {"message": "Invalid JSON"}})

    model = body.get("model", "unknown")
    client_wants_stream = bool(body.get("stream", False))
    messages: list[dict[str, Any]] = body.get("messages", [])
    combined_mapping: dict[str, str] = {}
    pii_types_found: list[str] = []
    total_pii = 0
    t0 = time.monotonic()
    error_msg: str | None = None
    status_code: int | None = None

    try:
        if anonymize_enabled:
            enabled = json.loads(config.get("enabled_detectors", "[]") or "[]")
            scanner = _get_proxy_scanner(enabled)
            # Anonymize system prompt
            forward_body = dict(body)
            system = body.get("system", "")
            if isinstance(system, str) and system.strip():
                anon_system, n = _scan_text(system, scanner, combined_mapping, pii_types_found)
                total_pii += n
                forward_body["system"] = anon_system
            elif isinstance(system, list):
                anon_sys, n = _anonymize_anthropic_content(system, scanner, combined_mapping, pii_types_found)
                total_pii += n
                forward_body["system"] = anon_sys

            # Anonymize messages
            anon_msgs: list[dict[str, Any]] = []
            for msg in messages:
                content = msg.get("content", "")
                anon_content, n = _anonymize_anthropic_content(
                    content, scanner, combined_mapping, pii_types_found
                )
                total_pii += n
                anon_msgs.append({**msg, "content": anon_content})
            forward_body["messages"] = anon_msgs
        else:
            forward_body = body

        # Forward all anthropic-* headers from client; inject our key
        _SKIP = frozenset(["host", "content-length", "transfer-encoding", "connection"])
        forward_headers: dict[str, str] = {"content-type": "application/json", "x-api-key": anthropic_api_key}
        for name, value in request.headers.items():
            name_l = name.lower()
            if name_l.startswith("anthropic-") and name_l not in _SKIP:
                forward_headers[name_l] = value
        if "anthropic-version" not in forward_headers:
            forward_headers["anthropic-version"] = "2023-06-01"

        # Forward query params (e.g. ?beta=true)
        target_path = "https://api.anthropic.com/v1/messages"
        qs = str(request.url.query)
        if qs:
            target_path = f"{target_path}?{qs}"

        # Serialize forward body — use ensure_ascii=False to preserve original encoding
        body_modified = anonymize_enabled and total_pii > 0
        send_bytes = json.dumps(forward_body if body_modified else body,
                                ensure_ascii=False).encode()

        log.debug("→ Anthropic headers: %s | body_modified=%s size=%d",
                  list(forward_headers.keys()), body_modified, len(send_bytes))

        # Stream from Anthropic and buffer SSE events so we can re-identify
        sse_chunks: list[str] = []
        status_code = 200
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", target_path, content=send_bytes,
                                     headers=forward_headers) as resp:
                status_code = resp.status_code
                log.info("← Anthropic %d", status_code)
                async for chunk in resp.aiter_text():
                    sse_chunks.append(chunk)

        raw_response = "".join(sse_chunks)

        # Non-streaming response: parse as JSON
        if not client_wants_stream:
            try:
                response_data = json.loads(raw_response)
            except Exception:
                response_data = {"error": raw_response}
            if restore_enabled and combined_mapping and status_code == 200:
                _restore_anthropic_response(response_data, combined_mapping)
            duration_ms = (time.monotonic() - t0) * 1000
            save_proxy_log(model=model, message_count=len(messages), pii_count=total_pii,
                           pii_types=pii_types_found, duration_ms=duration_ms,
                           status_code=status_code, error=None)
            return JSONResponse(status_code=status_code, content=response_data,
                                headers={"Connection": "close"})

        # Streaming response: re-identify placeholders in text_delta events, then re-stream
        if restore_enabled and combined_mapping and status_code == 200:
            patched_chunks: list[str] = []
            for chunk in sse_chunks:
                if '"text_delta"' in chunk and combined_mapping:
                    for placeholder, original in combined_mapping.items():
                        chunk = chunk.replace(
                            json.dumps(placeholder)[1:-1],  # JSON-escaped placeholder
                            json.dumps(original)[1:-1],     # JSON-escaped original
                        )
                patched_chunks.append(chunk)
            sse_chunks = patched_chunks

        async def _stream_chunks() -> Any:
            for chunk in sse_chunks:
                yield chunk

        duration_ms = (time.monotonic() - t0) * 1000
        save_proxy_log(model=model, message_count=len(messages), pii_count=total_pii,
                       pii_types=pii_types_found, duration_ms=duration_ms,
                       status_code=status_code, error=None)
        return StreamingResponse(
            _stream_chunks(),
            status_code=status_code,
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                     "Connection": "close"},
        )

    except httpx.ConnectError as exc:
        error_msg, status_code = f"Upstream unreachable: {exc}", 502
        log.error("proxy /v1/messages connect error: %s", exc)
    except httpx.TimeoutException:
        error_msg, status_code = "Upstream timeout", 504
        log.error("proxy /v1/messages timeout")
    except Exception as exc:
        log.exception("proxy /v1/messages unhandled error")
        error_msg, status_code = str(exc), 500

    duration_ms = (time.monotonic() - t0) * 1000
    save_proxy_log(
        model=model, message_count=len(messages), pii_count=total_pii,
        pii_types=pii_types_found, duration_ms=duration_ms,
        status_code=status_code, error=error_msg,
    )
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": error_msg, "type": "proxy_error"}},
    )
