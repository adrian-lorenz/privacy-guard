from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from privacy_guard import PiiType, PrivacyScanner, ScanResult

_API_KEY = os.getenv("API_KEY")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: Annotated[str | None, Security(_api_key_header)]) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


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


_scanner: PrivacyScanner | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
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


app = FastAPI(title="privacy-guard", lifespan=lifespan)

_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
