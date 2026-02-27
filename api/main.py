from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Security,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from privacy_guard import PiiType, PrivacyScanner, ScanResult

# ── Auth / API key ───────────────────────────────────────────────────────────

_API_KEY = os.getenv("API_KEY")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: Annotated[str | None, Security(_api_key_header)]) -> None:
    if not _API_KEY:
        return  # Auth disabled — no env var configured
    if key == _API_KEY:
        return  # Env-var key always valid (backward compat)
    if key:
        from api.db import check_api_key

        if check_api_key(key):
            return  # Active DB key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
    )


# ── Session management (in-process, no extra dependencies) ──────────────────

_sessions: dict[str, dict[str, Any]] = {}  # token → {id, username, role}


def _get_session(session: str = Cookie(default="")) -> dict[str, Any] | None:
    return _sessions.get(session)


def _require_session(
    sess: dict[str, Any] | None = Depends(_get_session),
) -> dict[str, Any]:
    if sess is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return sess


# ── Pydantic models (JSON API) ───────────────────────────────────────────────


class ScanRequest(BaseModel):
    text: str
    detectors: list[PiiType] | None = None
    whitelist: list[str] | None = None


class FindingOut(BaseModel):
    start: int
    end: int
    text: str
    pii_type: str
    confidence: float
    placeholder: str


class ScanResponse(BaseModel):
    anonymised_text: str
    findings: list[FindingOut]
    mapping: dict[str, str]


class AnonymizeResponse(BaseModel):
    anonymised_text: str


# ── Scanner singleton ────────────────────────────────────────────────────────

_scanner: PrivacyScanner | None = None

_ALL_PII_TYPES = [t.value for t in PiiType]


@asynccontextmanager
async def lifespan(_: FastAPI):
    from api.db import init_db

    init_db()
    global _scanner
    _scanner = PrivacyScanner()
    yield
    _scanner = None


def _get_scanner(
    detectors: list[PiiType] | None, whitelist: list[str] | None
) -> PrivacyScanner:
    if detectors is None and not whitelist:
        assert _scanner is not None
        return _scanner
    scanner = PrivacyScanner(extra_whitelist_names=whitelist or [])
    if detectors is not None:
        for pii_type in set(PiiType) - set(detectors):
            scanner.disable_detector(pii_type)
    return scanner


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="privacy-guard", lifespan=lifespan)

_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATES_DIR = Path(__file__).parent / "templates"

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ── UI routes ────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def root(
    request: Request, sess: dict[str, Any] | None = Depends(_get_session)
) -> HTMLResponse:
    if sess is None:
        return templates.TemplateResponse(request, "login.html", {})
    return templates.TemplateResponse(request, "app.html", {"user": sess})


@app.post("/login")
async def login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    request: Request,
) -> Any:
    from api.db import verify_login

    user = verify_login(username, password)
    if user is None:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Ung\u00fcltige Anmeldedaten."},
            status_code=401,
        )
    token = secrets.token_hex(32)
    _sessions[token] = user
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("session", token, httponly=True, samesite="lax")
    return response


@app.post("/logout")
async def logout(session: str = Cookie(default="")) -> RedirectResponse:
    _sessions.pop(session, None)
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session")
    return response


@app.get("/ui/scan", response_class=HTMLResponse)
async def ui_scan_form(
    request: Request,
    _: dict[str, Any] = Depends(_require_session),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_scan_result.html",
        {
            "text": "",
            "result": None,
            "all_types": _ALL_PII_TYPES,
            "selected_types": _ALL_PII_TYPES,
        },
    )


@app.post("/ui/scan", response_class=HTMLResponse)
async def ui_scan_post(
    request: Request,
    sess: dict[str, Any] = Depends(_require_session),
    text: Annotated[str, Form()] = "",
    detectors: Annotated[list[str], Form()] = [],
) -> HTMLResponse:
    from api.db import save_scan

    selected = detectors if detectors else _ALL_PII_TYPES

    pii_types: list[PiiType] | None = None
    if selected != _ALL_PII_TYPES:
        pii_types = [PiiType(d) for d in selected]

    result: ScanResult | None = None
    if text.strip():
        t0 = time.monotonic()
        result = _get_scanner(pii_types, None).scan(text)
        duration_ms = (time.monotonic() - t0) * 1000

        findings_out = [
            {
                "pii_type": f.pii_type.value,
                "text": f.text,
                "confidence": f.confidence,
                "placeholder": f.placeholder,
                "start": f.start,
                "end": f.end,
            }
            for f in result.findings
        ]
        save_scan(
            user_id=sess["id"],
            input_text=text,
            anonymised_text=result.anonymised_text,
            findings_json=json.dumps(findings_out),
            pii_count=len(result.findings),
            duration_ms=duration_ms,
        )

        # Attach serialisable findings for template
        result_dict = {
            "anonymised_text": result.anonymised_text,
            "findings": findings_out,
            "mapping": result.mapping,
        }
    else:
        result_dict = None  # type: ignore[assignment]

    return templates.TemplateResponse(
        request,
        "_scan_result.html",
        {
            "text": text,
            "result": result_dict,
            "all_types": _ALL_PII_TYPES,
            "selected_types": selected,
        },
    )


@app.get("/ui/history", response_class=HTMLResponse)
async def ui_history(
    request: Request,
    sess: dict[str, Any] = Depends(_require_session),
) -> HTMLResponse:
    from api.db import get_history

    is_admin = sess["role"] == "admin"
    rows = get_history(user_id=None if is_admin else sess["id"])
    return templates.TemplateResponse(
        request,
        "_history.html",
        {
            "rows": rows,
            "rows_json": json.dumps(rows),
            "is_admin": is_admin,
        },
    )


@app.get("/ui/stats", response_class=HTMLResponse)
async def ui_stats(
    request: Request,
    sess: dict[str, Any] = Depends(_require_session),
) -> HTMLResponse:
    from api.db import get_daily_counts, get_pii_type_stats, get_totals

    is_admin = sess["role"] == "admin"
    uid = None if is_admin else sess["id"]

    totals = get_totals(user_id=uid)
    pii_stats = get_pii_type_stats(user_id=uid)
    daily = get_daily_counts(days=30, user_id=uid)

    most_common = max(pii_stats, key=lambda k: pii_stats[k]) if pii_stats else "\u2014"

    sorted_pii = sorted(pii_stats.items(), key=lambda x: x[1], reverse=True)
    pii_data = {
        "labels": [k for k, _ in sorted_pii],
        "values": [v for _, v in sorted_pii],
    }
    daily_data = {
        "labels": [r["day"] for r in daily],
        "values": [r["count"] for r in daily],
    }

    return templates.TemplateResponse(
        request,
        "_stats.html",
        {
            "totals": totals,
            "most_common": most_common,
            "pii_data": pii_data,
            "daily_data": daily_data,
        },
    )


def _require_admin(sess: dict[str, Any] = Depends(_require_session)) -> dict[str, Any]:
    if sess["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    return sess


def _apikeys_ctx(keys: list[dict], new_key: str | None) -> dict[str, Any]:
    return {"keys": keys, "new_key": new_key, "env_key_set": bool(_API_KEY)}


@app.get("/ui/apikeys", response_class=HTMLResponse)
async def ui_apikeys(
    request: Request,
    _: dict[str, Any] = Depends(_require_admin),
) -> HTMLResponse:
    from api.db import list_api_keys

    return templates.TemplateResponse(
        request, "_apikeys.html", _apikeys_ctx(list_api_keys(), None)
    )


@app.post("/ui/apikeys", response_class=HTMLResponse)
async def ui_apikeys_create(
    request: Request,
    sess: dict[str, Any] = Depends(_require_admin),
    name: Annotated[str, Form()] = "",
) -> HTMLResponse:
    from api.db import create_api_key, list_api_keys

    new_key: str | None = (
        create_api_key(name.strip(), sess["id"]) if name.strip() else None
    )
    return templates.TemplateResponse(
        request, "_apikeys.html", _apikeys_ctx(list_api_keys(), new_key)
    )


@app.post("/ui/apikeys/{key_id}/revoke", response_class=HTMLResponse)
async def ui_apikeys_revoke(
    request: Request,
    key_id: int,
    _: dict[str, Any] = Depends(_require_admin),
) -> HTMLResponse:
    from api.db import list_api_keys, revoke_api_key

    revoke_api_key(key_id)
    return templates.TemplateResponse(
        request, "_apikeys.html", _apikeys_ctx(list_api_keys(), None)
    )


# ── JSON API routes (unchanged) ──────────────────────────────────────────────


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, dependencies=[Depends(verify_api_key)])
async def scan(request: ScanRequest) -> ScanResponse:
    result: ScanResult = _get_scanner(request.detectors, request.whitelist).scan(
        request.text
    )
    findings = [
        FindingOut(
            start=f.start,
            end=f.end,
            text=f.text,
            pii_type=f.pii_type.value,
            confidence=f.confidence,
            placeholder=f.placeholder,
        )
        for f in result.findings
    ]
    return ScanResponse(
        anonymised_text=result.anonymised_text,
        findings=findings,
        mapping=result.mapping,
    )


@app.post(
    "/anonymize",
    response_model=AnonymizeResponse,
    dependencies=[Depends(verify_api_key)],
)
async def anonymize(request: ScanRequest) -> AnonymizeResponse:
    result: ScanResult = _get_scanner(request.detectors, request.whitelist).scan(
        request.text
    )
    return AnonymizeResponse(anonymised_text=result.anonymised_text)
