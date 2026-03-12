from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from privacy_guard import PrivacyScanner

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _get_scanner() -> PrivacyScanner:
    from api.main import _scanner  # reuse the singleton

    assert _scanner is not None
    return _scanner


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


def _restore_anthropic_response(response_data: dict[str, Any], mapping: dict[str, str]) -> None:
    """Re-identify placeholders in Anthropic response in-place."""
    for block in response_data.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            block["text"] = _restore(block["text"], mapping)


# ── UI routes ────────────────────────────────────────────────────────────────


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
        request,
        "_proxy.html",
        {"config": config, "logs": logs, "base_url": base_url},
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
) -> HTMLResponse:
    from api.db import get_proxy_config, get_proxy_logs, save_proxy_config

    save_proxy_config(
        {
            "target_url": target_url.strip(),
            "target_api_key": target_api_key.strip(),
            "anthropic_api_key": anthropic_api_key.strip(),
            "proxy_enabled": proxy_enabled,
            "anonymize_enabled": anonymize_enabled,
            "restore_enabled": restore_enabled,
        }
    )
    config = get_proxy_config()
    logs = _parse_logs(get_proxy_logs(limit=50))
    base_url = str(request.base_url).rstrip("/")
    return _templates.TemplateResponse(
        request,
        "_proxy.html",
        {"config": config, "logs": logs, "base_url": base_url, "saved": True},
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
    target_api_key = config.get("target_api_key", "")
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
            anon_msgs, total_pii = _anonymize_openai_messages(
                messages, _get_scanner(), combined_mapping, pii_types_found
            )
            forward_body = {**body, "messages": anon_msgs}
        else:
            forward_body = body

        if restore_enabled and forward_body.get("stream"):
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
        return JSONResponse(status_code=status_code, content=response_data)

    except httpx.ConnectError as exc:
        error_msg, status_code = f"Upstream unreachable: {exc}", 502
    except httpx.TimeoutException:
        error_msg, status_code = "Upstream timeout", 504
    except Exception as exc:
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
    from api.db import get_proxy_config, save_proxy_log

    config = get_proxy_config()
    if config.get("proxy_enabled", "1") != "1":
        return JSONResponse(status_code=503, content={"error": {"message": "Proxy is disabled"}})

    anthropic_api_key = config.get("anthropic_api_key", "") or config.get("target_api_key", "")
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
            scanner = _get_scanner()
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

        if restore_enabled and forward_body.get("stream"):
            forward_body = {**forward_body, "stream": False}

        # Pass through anthropic-specific headers from the incoming request
        incoming_headers = dict(request.headers)
        forward_headers: dict[str, str] = {
            "Content-Type": "application/json",
            "x-api-key": anthropic_api_key,
            "anthropic-version": incoming_headers.get("anthropic-version", "2023-06-01"),
        }
        if "anthropic-beta" in incoming_headers:
            forward_headers["anthropic-beta"] = incoming_headers["anthropic-beta"]

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                json=forward_body,
                headers=forward_headers,
            )

        status_code = resp.status_code
        response_data = resp.json()

        if restore_enabled and combined_mapping and status_code == 200:
            _restore_anthropic_response(response_data, combined_mapping)

        duration_ms = (time.monotonic() - t0) * 1000
        save_proxy_log(
            model=model, message_count=len(messages), pii_count=total_pii,
            pii_types=pii_types_found, duration_ms=duration_ms,
            status_code=status_code, error=None,
        )
        return JSONResponse(status_code=status_code, content=response_data)

    except httpx.ConnectError as exc:
        error_msg, status_code = f"Upstream unreachable: {exc}", 502
    except httpx.TimeoutException:
        error_msg, status_code = "Upstream timeout", 504
    except Exception as exc:
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
