"""Streamlit review UI.

    streamlit run app/streamlit_app.py

Flow: paste text → review highlighted spans (accept / reject / add) → see exactly what the model
will receive → copy it or send it → paste the response → re-hydrated answer with warnings.
Everything runs locally; only the scrubbed prompt is ever sent, and only when you press Send.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scrubber import Session, Span  # noqa: E402
from scrubber.llm_client import LLMClient  # noqa: E402
from scrubber.pipeline import Scrubber  # noqa: E402
from scrubber.policy import default_policy  # noqa: E402
from scrubber.rehydrate import rehydrate  # noqa: E402

st.set_page_config(page_title="PII Scrubber", page_icon="🛡️", layout="wide")

COLOURS = {
    "secret": "#ff6b6b", "card": "#ff8787", "iban": "#ffa8a8", "nhs_number": "#ffc9c9", "ni_number": "#fcc2d7",
    "person": "#74c0fc", "email": "#63e6be", "phone": "#8ce99a", "username": "#a9e34b", "user_id": "#d8f5a2",
    "uuid": "#e9ecef", "ip": "#ffd43b", "address": "#b197fc", "postcode": "#d0bfff", "date_of_birth": "#ffa94d",
    "date": "#ffe8cc", "organisation": "#99e9f2", "location": "#c5f6fa", "quasi_identifier": "#f783ac",
}
TYPES = sorted(set(COLOURS) | set(default_policy().modes["balanced"]))
KNOWN_LIMITS = """
- English text and UK identifier formats only.
- Quasi-identifiers in free text ("the only female professor in…") are only partially covered (L5, optional).
- Unknown custom ID formats (e.g. `CUST-88231`) are missed unless the key name matches or a custom pattern is added in `config/policy.yaml`.
- **Pseudonymised data is still personal data.** This tool reduces risk; it does not make data anonymous or compliant.
"""
EXAMPLE = """Hi team, I'm Jane Doe (jane.doe+shop@gmail.com, 07911 123456). Ms Doe's NHS number is 943 476 5919.
2024-05-01T10:00:00Z WARN auth failed user=jdoe92 src=10.0.0.12 token=sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGhJk
{"customer": "Jane Doe", "dob": "03/05/1988", "address": "12 High Street, Southampton SO17 1BJ", "note": "Jane asked about her refund"}"""


@st.cache_resource(show_spinner="Loading detectors (first run downloads the local NER model)…")
def get_scrubber(layers: tuple[str, ...]) -> Scrubber:
    return Scrubber(list(layers))


def state() -> dict:
    ss = st.session_state
    ss.setdefault("session", Session())
    ss.setdefault("spans", [])  # list[dict]: span fields + keep flag
    ss.setdefault("detected_for", None)
    ss.setdefault("result", None)
    ss.setdefault("response", "")
    return ss


def highlight(text: str, spans: list[dict]) -> str:
    out, pos = [], 0
    for s in sorted(spans, key=lambda x: x["start"]):
        if s["start"] < pos:
            continue
        out.append(html.escape(text[pos : s["start"]]))
        colour = COLOURS.get(s["type"], "#dee2e6")
        tip = html.escape(f"{s['type']} · {s['source']} · {s['reason']}", quote=True)
        out.append(f'<mark title="{tip}" style="background:{colour};color:#111;padding:0 2px;border-radius:3px">'
                   f'{html.escape(text[s["start"]:s["end"]])}<sub style="font-size:0.65em;opacity:.7"> {s["type"]}</sub></mark>')
        pos = s["end"]
    out.append(html.escape(text[pos:]))
    return _box("".join(out))


def highlight_output(text: str, session: Session) -> str:
    keys = sorted(session.vault.reverse, key=len, reverse=True)
    pats = [re.escape(k) for k in keys] + [r"\[[A-Z_]+(?:_\d+)?(?:_REMOVED)?\]", r"\[AGE \d+-\d+\]"]
    rx = re.compile("|".join(pats)) if pats else None
    out, pos = [], 0
    for m in rx.finditer(text) if rx else []:
        out.append(html.escape(text[pos : m.start()]))
        out.append(f'<mark style="background:#e7f5ff;color:#1864ab;padding:0 2px;border-radius:3px">{html.escape(m.group())}</mark>')
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return _box("".join(out))


def _box(inner: str) -> str:
    return (f'<div style="white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:0.85rem;'
            f'border:1px solid #ccc;border-radius:6px;padding:10px;line-height:1.7">{inner}</div>')


def main() -> None:
    ss = state()
    policy = default_policy()

    with st.sidebar:
        st.header("Settings")
        mode = st.radio("Mode", ["balanced", "strict"], help="strict generalises more (shifted dates, IPs removed, …)")
        layers = st.multiselect("Detector layers", ["L1", "L2", "L3", "L4", "L5"], default=policy.enabled_layers,
                                help="L1 secrets · L2 structured · L3 key-aware · L4 local NER (GLiNER) · L5 local LLM (Ollama)")
        st.caption(f"Session `{ss.session.id}` · {len(ss.session.vault.reverse)} mappings in memory")
        if st.button("New session (forget mappings)"):
            for k in ("session", "spans", "detected_for", "result", "response"):
                ss.pop(k, None)
            st.rerun()
        with st.expander("Known limits", expanded=False):
            st.markdown(KNOWN_LIMITS)
        st.markdown("**Legend**")
        st.markdown(" ".join(f'<span style="background:{c};padding:0 4px;border-radius:3px;font-size:0.75rem">{t}</span>'
                             for t, c in COLOURS.items()), unsafe_allow_html=True)

    st.title("🛡️ Local PII scrubber")
    st.caption("Detection runs on this machine. Only the scrubbed text below is ever sent to a model.")

    # 1. paste text
    ss.setdefault("input", EXAMPLE)
    text = st.text_area("1 · Paste text (prose, logs, JSON, key=value…)", height=180, key="input")
    if st.button("Detect", type="primary") or (ss.detected_for and ss.detected_for != (text, tuple(layers))):
        with st.spinner("Detecting…"):
            spans, warns = get_scrubber(tuple(sorted(layers))).detect(text)
        ss.spans = [{**s.model_dump(), "keep": True} for s in spans]
        ss.detect_warnings = warns
        ss.detected_for = (text, tuple(layers))
        ss.result = None
    if not ss.detected_for:
        st.info("Press **Detect** to find personal data and secrets.")
        st.warning(KNOWN_LIMITS)
        return
    text = ss.detected_for[0]
    for w in ss.get("detect_warnings", []):
        st.warning(w)

    # 2. highlighted spans
    st.subheader("2 · Detected spans")
    st.caption("Hover a highlight for the type, detector layer and reason.")
    st.markdown(highlight(text, [s for s in ss.spans if s["keep"]]), unsafe_allow_html=True)

    # 3. accept / reject / add
    st.subheader("3 · Review")
    rows = [{"keep": s["keep"], "type": s["type"],
             "text": s["text"] if s["type"] != "secret" else "•" * min(8, len(s["text"])),
             "source": s["source"], "confidence": round(s["confidence"], 2), "reason": s["reason"]}
            for s in ss.spans]
    edited = st.data_editor(
        rows, key=f"editor_{hash(ss.detected_for)}_{len(ss.spans)}", use_container_width=True, hide_index=True,
        column_config={
            "keep": st.column_config.CheckboxColumn("scrub?", help="untick to leave this text as it is"),
            "type": st.column_config.SelectboxColumn("type", options=TYPES),
        },
        disabled=["text", "source", "confidence", "reason"],
    )
    for s, row in zip(ss.spans, edited):
        s["keep"], s["type"] = bool(row["keep"]), row["type"]

    with st.form("add_span", clear_on_submit=True):
        c1, c2, c3 = st.columns([3, 2, 1])
        manual = c1.text_input("Add a span manually: exact text (every occurrence is added)")
        mtype = c2.selectbox("type", TYPES, index=TYPES.index("person"))
        if c3.form_submit_button("Add") and manual:
            n = 0
            for m in re.finditer(re.escape(manual), text):
                ss.spans.append({"start": m.start(), "end": m.end(), "text": manual, "type": mtype, "source": "manual",
                                 "confidence": 1.0, "reason": "added by reviewer", "keep": True})
                n += 1
            if n:
                st.rerun()
            st.error("Not found in the text.")

    if st.button("Apply / re-run transform", type="primary") or ss.result is None or ss.get("applied_mode") != mode:
        ss.applied_mode = mode
        kept = [Span(**{k: v for k, v in s.items() if k != "keep"}) for s in ss.spans if s["keep"]]
        rejected = frozenset(s["text"] for s in ss.spans if not s["keep"])
        ss.result = get_scrubber(tuple(sorted(layers))).apply(text, kept, ss.session, mode, allow=rejected)
    result = ss.result

    # 4. side-by-side
    st.subheader("4 · What the model will see")
    left, right = st.columns(2)
    left.markdown("**Original (stays here)**")
    left.markdown(highlight(text, [s for s in ss.spans if s["keep"]]), unsafe_allow_html=True)
    right.markdown("**Scrubbed prompt (sent)**")
    right.markdown(highlight_output(result.scrubbed_text, ss.session), unsafe_allow_html=True)
    rep = result.report
    st.caption(f"actions: {rep['counts_by_action']} · leak-check fixes: {len(rep['leak_fixes'])}")
    for w in rep["warnings"]:
        st.warning(w)

    # 5. copy or send
    st.subheader("5 · Copy or send")
    st.code(result.scrubbed_text, language=None)  # has a copy button
    instruction = st.text_input("Instruction to prepend (optional)", value="")
    client = LLMClient()
    c1, c2 = st.columns([1, 3])
    if c1.button(f"Send via {client.provider}", disabled=client.provider == "dryrun",
                 help="Set LLM_PROVIDER and an API key in .env to enable"):
        prompt = (instruction + "\n\n" if instruction else "") + result.scrubbed_text
        with st.spinner(f"Calling {client.provider}:{client.model}…"):
            try:
                ss.response = client.send(prompt, {"purpose": "app", "session_id": ss.session.id})
                st.session_state["response_box"] = ss.response
            except Exception as exc:  # noqa: BLE001
                st.error(f"LLM call failed: {type(exc).__name__}: {exc}")
    c2.caption(f"provider `{client.provider}` · model `{client.model}` · exact payload logged to `{client.log_path.name}`")

    # 6. response → re-hydrate
    st.subheader("6 · Response → re-hydrated")
    response = st.text_area("Paste or receive the model's response", key="response_box", height=150)
    if response:
        restored, warnings = rehydrate(response, ss.session)
        st.markdown("**Re-hydrated (local only)**")
        st.markdown(_box(html.escape(restored)), unsafe_allow_html=True)
        for w in warnings:
            st.warning(w)
        if not warnings:
            st.success("All surrogates restored. Removed values (secrets, cards…) are never restored.")


main()
