from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
import pandas as pd
import streamlit as st

# Allow importing db.py from the same directory
sys.path.insert(0, str(Path(__file__).parent))
from db import (  # noqa: E402
    get_daily_counts,
    get_history,
    get_pii_type_stats,
    get_totals,
    init_db,
    save_scan,
    verify_login,
)

_API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
_API_KEY = os.getenv("API_KEY", "")
_ALL_TYPES = [
    "NAME", "IBAN", "CREDIT_CARD", "PERSONAL_ID", "SOCIAL_SECURITY",
    "TAX_ID", "PHONE", "EMAIL", "ADDRESS", "SECRET", "URL_SECRET",
]

st.set_page_config(
    page_title="privacy-guard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

init_db()


# ── Login ─────────────────────────────────────────────────────────────────────

def _login_page() -> None:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, col, _ = st.columns([1, 1, 1])
    with col:
        st.markdown("## 🔒 privacy-guard")
        st.caption("PII-Anonymisierungs-Dashboard")
        st.divider()
        with st.form("login"):
            username = st.text_input("Benutzername")
            password = st.text_input("Passwort", type="password")
            if st.form_submit_button("Anmelden", width="stretch", type="primary"):
                user = verify_login(username, password)
                if user:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Ungültige Anmeldedaten.")


user: dict | None = st.session_state.get("user")
if not user:
    _login_page()
    st.stop()
assert user is not None  # guaranteed by st.stop() above

# ── Header ────────────────────────────────────────────────────────────────────

c1, c2 = st.columns([5, 1])
with c1:
    st.title("🔒 privacy-guard")
with c2:
    st.caption(f"👤 **{user['username']}** ({user['role']})")
    if st.button("Logout", width="stretch"):
        for key in ("user", "last_scan"):
            st.session_state.pop(key, None)
        st.rerun()

tab_live, tab_history, tab_dashboard = st.tabs(["🔍 Live Test", "📋 History", "📊 Dashboard"])


# ── Live Test ─────────────────────────────────────────────────────────────────

with tab_live:
    text_input: str = st.text_area(
        "Text eingeben",
        key="live_text",
        height=180,
        placeholder="Füge hier den zu scannenden Text ein …",
    )

    with st.expander("Detektoren", expanded=False):
        selected_types: list[str] = st.multiselect(
            "Aktive Detektoren",
            _ALL_TYPES,
            default=_ALL_TYPES,
            label_visibility="collapsed",
        )

    if st.button("🔍 Scannen", type="primary", disabled=not text_input.strip()):
        headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
        payload: dict = {"text": text_input}
        if selected_types != _ALL_TYPES:
            payload["detectors"] = selected_types
        scan_data: dict | None = None
        scan_duration_ms: float = 0.0
        try:
            with st.spinner("Scanne …"):
                t0 = time.monotonic()
                resp = httpx.post(
                    f"{_API_BASE}/scan", json=payload, headers=headers, timeout=30
                )
                scan_duration_ms = (time.monotonic() - t0) * 1000
                resp.raise_for_status()
                scan_data = resp.json()
        except httpx.ConnectError:
            st.error(f"API nicht erreichbar unter `{_API_BASE}`. Ist der Server gestartet?")
        except httpx.HTTPStatusError as exc:
            st.error(f"API-Fehler {exc.response.status_code}: {exc.response.text}")

        if scan_data is not None:
            save_scan(
                user_id=user["id"],
                input_text=text_input,
                anonymised_text=scan_data["anonymised_text"],
                findings_json=json.dumps(scan_data["findings"]),
                pii_count=len(scan_data["findings"]),
                duration_ms=scan_duration_ms,
            )
            st.session_state.last_scan = {"data": scan_data, "text": text_input}

    result = st.session_state.get("last_scan")
    if result:
        data = result["data"]
        findings = data["findings"]

        col_o, col_a = st.columns(2)
        with col_o:
            st.subheader("Original")
            st.text_area(
                "orig", result["text"], height=160,
                disabled=True, label_visibility="collapsed",
            )
        with col_a:
            st.subheader("Anonymisiert")
            st.text_area(
                "anon", data["anonymised_text"], height=160,
                disabled=True, label_visibility="collapsed",
            )

        if findings:
            st.subheader(f"Findings — {len(findings)} Treffer")
            df_findings = pd.DataFrame([
                {
                    "Typ": f["pii_type"],
                    "Originaltext": f["text"],
                    "Konfidenz": f"{f['confidence']:.0%}",
                    "Platzhalter": f["placeholder"],
                }
                for f in findings
            ])
            st.dataframe(df_findings, width="stretch", hide_index=True)
            with st.expander("Mapping (JSON)"):
                st.json(data["mapping"])
        else:
            st.info("Keine PII gefunden.")


# ── History ───────────────────────────────────────────────────────────────────

with tab_history:
    is_admin = user["role"] == "admin"
    history = get_history(user_id=None if is_admin else user["id"])

    if not history:
        st.info("Noch keine Scans gespeichert.")
    else:
        df_hist = pd.DataFrame([
            {
                "Zeitstempel": row["created_at"],
                **({"Benutzer": row["username"]} if is_admin else {}),
                "PII-Treffer": row["pii_count"],
                "Dauer (ms)": f"{row['duration_ms']:.0f}" if row["duration_ms"] else "—",
                "Eingabe (Vorschau)": (
                    row["input_text"][:70] + "…"
                    if len(row["input_text"]) > 70
                    else row["input_text"]
                ),
            }
            for row in history
        ])
        st.dataframe(df_hist, width="stretch", hide_index=True)

        st.divider()
        st.subheader("Scan-Details")
        idx = st.selectbox(
            "Scan auswählen",
            range(len(history)),
            format_func=lambda i: (
                f"{history[i]['created_at']}  —  {history[i]['pii_count']} Treffer  —  "
                f"{history[i]['input_text'][:50]}…"
            ),
            label_visibility="collapsed",
        )
        if idx is not None:
            row = history[idx]
            c_left, c_right = st.columns(2)
            with c_left:
                st.markdown("**Anonymisierter Text**")
                st.text_area(
                    "at", row["anonymised_text"], height=140,
                    disabled=True, label_visibility="collapsed",
                )
            with c_right:
                st.markdown("**Findings**")
                findings_data = json.loads(row["findings_json"])
                if findings_data:
                    st.dataframe(
                        pd.DataFrame([
                            {"Typ": f["pii_type"], "Text": f["text"],
                             "Konfidenz": f"{f['confidence']:.0%}"}
                            for f in findings_data
                        ]),
                        width="stretch",
                        hide_index=True,
                    )
                else:
                    st.info("Keine PII gefunden.")


# ── Dashboard ─────────────────────────────────────────────────────────────────

with tab_dashboard:
    scope_uid = None if is_admin else user["id"]
    totals = get_totals(user_id=scope_uid)
    pii_stats = get_pii_type_stats(user_id=scope_uid)
    daily = get_daily_counts(days=30, user_id=scope_uid)

    m1, m2, m3 = st.columns(3)
    m1.metric("Gesamte Scans", totals["total_scans"])
    m2.metric("Gefundene PII", totals["total_pii"])
    most_common = max(pii_stats, key=lambda k: pii_stats[k]) if pii_stats else "—"
    m3.metric("Häufigster Typ", most_common)

    st.divider()

    col_bar, col_line = st.columns(2)

    with col_bar:
        st.subheader("PII-Typen")
        if pii_stats:
            df_pii = (
                pd.DataFrame(pii_stats.items(), columns=["Typ", "Anzahl"])
                .sort_values("Anzahl", ascending=False)
                .set_index("Typ")
            )
            st.bar_chart(df_pii)
        else:
            st.info("Noch keine Daten.")

    with col_line:
        st.subheader("Scans pro Tag (30 Tage)")
        if daily:
            df_daily = pd.DataFrame(daily).set_index("day").rename(columns={"count": "Scans"})
            st.line_chart(df_daily)
        else:
            st.info("Noch keine Daten.")

    if is_admin:
        st.divider()
        st.subheader("Alle Benutzer-Aktivitäten")
        history_all = get_history(limit=20)
        if history_all:
            df_recent = pd.DataFrame([
                {
                    "Zeitstempel": r["created_at"],
                    "Benutzer": r["username"],
                    "PII": r["pii_count"],
                }
                for r in history_all
            ])
            st.dataframe(df_recent, width="stretch", hide_index=True)
