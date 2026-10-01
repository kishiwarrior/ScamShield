"""ScamShield: an explainable scam investigation agent for Indian users."""
import html
import json
import os
import socket
import requests
import streamlit as st

from engine import (
    MODEL,
    GEMINI_API_KEY_SETTING,
    MAX_REDIRECTS,
    REQUEST_TIMEOUT,
    KNOWN_UPI_HANDLES,
    SUSPICIOUS_TLDS,
    SHORTENERS,
    BRANDS,
    TOOL_FUNCS,
    TOOLS,
    GEMINI_TOOLS,
    SYSTEM,
    extract_entities,
    _validate_public_url,
    analyze_url,
    check_upi_id,
    check_domain_reputation,
    draft_complaint,
    evaluate_heuristic,
    investigate,
    _parse_report,
    _get_gemini_client,
)

# Keep genai reference in app for tests / inspection
try:
    from google import genai
except ImportError:
    genai = None


def run_agent(user_text: str, ui):
    """Run agent with Gemini function calling and automatic heuristic fallback resilience."""
    try:
        client = _get_gemini_client()
        history = [{"type": "user_input", "content": [{"type": "text", "text": user_text}]}]
        for _ in range(8):
            interaction = client.interactions.create(
                model=MODEL, input=history, tools=GEMINI_TOOLS,
                system_instruction=SYSTEM, store=False,
            )
            history.extend(step.model_dump() for step in interaction.steps)
            function_calls = [step for step in interaction.steps if step.type == "function_call"]
            if not function_calls:
                return interaction.output_text

            for call in function_calls:
                try:
                    out = TOOL_FUNCS[call.name](**call.arguments)
                except Exception as exc:
                    out = {"error": f"Tool could not complete ({type(exc).__name__})"}
                if hasattr(ui, "write"):
                    ui.write(f"Tool: **{call.name}**")
                if hasattr(ui, "json"):
                    ui.json(out)
                history.append({
                    "type": "function_result", "name": call.name, "call_id": call.id,
                    "result": [{"type": "text", "text": json.dumps(out) if not isinstance(out, str) else out}],
                })
        return "Investigation stopped: step limit reached."
    except Exception as exc:
        fallback = evaluate_heuristic(user_text)
        if hasattr(ui, "info"):
            ui.info(f"⚡ LLM unavailable ({type(exc).__name__}). Evaluated via Local Threat Intelligence Engine.")
        return fallback["raw_text"]


def render_ui():
    """Render the Streamlit dashboard."""
    st.set_page_config(page_title="ScamShield | Cyber Threat Intelligence", page_icon="🛡️", layout="centered")

    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    :root {
        --ss-bg: #080c15;
        --ss-surface: #0e1626;
        --ss-surface-card: rgba(15, 23, 42, 0.75);
        --ss-border: rgba(255, 255, 255, 0.08);
        --ss-border-focus: #10b981;
        --ss-emerald: #10b981;
        --ss-emerald-glow: rgba(16, 185, 129, 0.25);
        --ss-crimson: #ef4444;
        --ss-crimson-glow: rgba(239, 68, 68, 0.25);
        --ss-amber: #f59e0b;
        --ss-amber-glow: rgba(245, 158, 11, 0.25);
        --ss-cyan: #06b6d4;
        --ss-text: #f8fafc;
        --ss-text-muted: #94a3b8;
    }

    .stApp {
        background-color: var(--ss-bg) !important;
        background-image: 
            radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
            radial-gradient(at 100% 0%, rgba(6, 182, 212, 0.08) 0px, transparent 50%),
            radial-gradient(at 50% 100%, rgba(15, 23, 42, 0.5) 0px, transparent 50%) !important;
        color: var(--ss-text) !important;
    }

    [data-testid="stHeader"] {
        background: transparent !important;
    }

    .block-container {
        max-width: 920px !important;
        padding-top: 2rem !important;
        padding-bottom: 5rem !important;
    }

    div[data-testid="stTextArea"] textarea {
        background-color: #0d1527 !important;
        color: #f8fafc !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 12px !important;
        font-size: 0.95rem !important;
        line-height: 1.5 !important;
        padding: 1rem !important;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.4) !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: var(--ss-emerald) !important;
        box-shadow: 0 0 0 2px var(--ss-emerald-glow) !important;
    }
    div[data-testid="stTextArea"] label p {
        color: var(--ss-text) !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
    }

    div[data-testid="stButton"] button[kind="primary"] {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 1.02rem !important;
        letter-spacing: 0.02em !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.75rem 1.5rem !important;
        box-shadow: 0 4px 20px var(--ss-emerald-glow) !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stButton"] button[kind="primary"]:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 24px rgba(16, 185, 129, 0.45) !important;
    }

    div[data-testid="stButton"] button[kind="secondary"] {
        background: rgba(15, 23, 42, 0.8) !important;
        color: #cbd5e1 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        font-size: 0.84rem !important;
        font-weight: 500 !important;
        padding: 0.5rem 0.6rem !important;
        transition: all 0.2s ease !important;
        width: 100% !important;
    }
    div[data-testid="stButton"] button[kind="secondary"]:hover {
        background: rgba(30, 41, 59, 0.9) !important;
        color: #ffffff !important;
        border-color: rgba(255, 255, 255, 0.25) !important;
        transform: translateY(-1px) !important;
    }

    div[data-testid="stStatusWidget"] {
        background: rgba(15, 23, 42, 0.85) !important;
        border: 1px solid var(--ss-border) !important;
        border-radius: 12px !important;
        color: #f8fafc !important;
    }

    [data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid var(--ss-border) !important;
        border-radius: 12px !important;
    }

    .ss-hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 5px 14px;
        border-radius: 9999px;
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34d399;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.09em;
        text-transform: uppercase;
    }
    .ss-pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        box-shadow: 0 0 8px #10b981;
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(0.85); }
    }

    .ss-title {
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.025em;
        background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 55%, #94a3b8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-top: 0.6rem;
        margin-bottom: 0.3rem;
    }
    .ss-subtitle {
        color: #94a3b8;
        font-size: 0.98rem;
        line-height: 1.5;
        margin-bottom: 1.25rem;
    }

    .ss-alert-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        padding: 0.85rem 1.1rem;
        background: rgba(245, 158, 11, 0.08);
        border: 1px solid rgba(245, 158, 11, 0.25);
        border-radius: 10px;
        color: #fde68a;
        font-size: 0.86rem;
        margin-bottom: 1.5rem;
    }
    .ss-hotlines {
        display: flex;
        gap: 10px;
        align-items: center;
    }
    .ss-badge-pill {
        background: rgba(245, 158, 11, 0.2);
        border: 1px solid rgba(245, 158, 11, 0.4);
        padding: 2px 7px;
        border-radius: 6px;
        font-weight: 700;
        color: #fbbf24;
    }

    .ss-verdict-card {
        border-radius: 14px;
        padding: 1.5rem;
        margin-top: 1rem;
        margin-bottom: 1.25rem;
        border: 1px solid;
        backdrop-filter: blur(12px);
    }
    .ss-verdict-scam {
        background: linear-gradient(145deg, rgba(239, 68, 68, 0.12) 0%, rgba(15, 23, 42, 0.85) 100%);
        border-color: rgba(239, 68, 68, 0.45);
        box-shadow: 0 8px 30px rgba(239, 68, 68, 0.18);
    }
    .ss-verdict-suspicious {
        background: linear-gradient(145deg, rgba(245, 158, 11, 0.12) 0%, rgba(15, 23, 42, 0.85) 100%);
        border-color: rgba(245, 158, 11, 0.45);
        box-shadow: 0 8px 30px rgba(245, 158, 11, 0.18);
    }
    .ss-verdict-safe {
        background: linear-gradient(145deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.85) 100%);
        border-color: rgba(16, 185, 129, 0.45);
        box-shadow: 0 8px 30px rgba(16, 185, 129, 0.18);
    }

    .ss-score-bar-bg {
        width: 100%;
        height: 10px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 9999px;
        overflow: hidden;
        margin: 10px 0;
    }
    .ss-score-bar-fill {
        height: 100%;
        border-radius: 9999px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .ss-section-box {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
    .ss-section-title {
        font-size: 0.84rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    </style>

    <div class="ss-hero-badge">
        <span class="ss-pulse-dot"></span>
        ScamShield AI · India Cyber Defense
    </div>
    <div class="ss-title">Scam & Threat Intelligence</div>
    <div class="ss-subtitle">Explainable AI investigation agent for suspicious SMS, phishing URLs, and fraudulent UPI payment requests.</div>

    <div class="ss-alert-banner">
        <div>⚠️ <strong>Advisory Only:</strong> ScamShield investigates evidence and drafts reports; it never blocks accounts or auto-submits.</div>
        <div class="ss-hotlines">
            <span>Helpline: <span class="ss-badge-pill">📞 1930</span></span>
            <span>Portal: <span class="ss-badge-pill">🌐 cybercrime.gov.in</span></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<p style='font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #94a3b8; margin-bottom: 8px;'>💡 Quick Load Sample Scenarios</p>", unsafe_allow_html=True)

    samples = {
        "🚨 Fake KYC SMS": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login",
        "💸 UPI Refund Scam": "Hi, I am sending your refund of Rs. 4,999. Please approve the collect request from refund.support8834@okybl and enter your UPI PIN.",
        "⚡ Electricity Cutoff": "URGENT: Your electricity connection will be DISCONNECTED tonight at 9:30 PM due to unpaid bill of Rs. 1,450. Call executive at +919876543210 or pay at http://bijli-bill-update.xyz/pay",
        "✅ Legitimate Alert": "Dear SBI Customer, your A/C ending with 4821 has been debited by INR 350.00 on 01-Oct-26 via UPI. Ref No 427819382104. If not done by you, visit https://www.sbi.co.in or call 18001234. Never share your OTP, UPI PIN, or CVV.",
    }

    cols = st.columns(len(samples))
    for c, (name, txt) in zip(cols, samples.items()):
        if c.button(name, key=f"sample_{name}", use_container_width=True):
            st.session_state["msg"] = txt

    msg = st.text_area(
        "Paste Suspicious Message, URL, or UPI Request",
        key="msg",
        height=150,
        placeholder="Paste suspicious text here (e.g. SMS, WhatsApp message, Telegram task, or payment link). Never paste OTPs or UPI PINs."
    )

    st.markdown(
        "<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; font-size: 0.8rem; color: #64748b;'>"
        "<span>🔒 Stateless Gemini requests; provider data policies still apply. Avoid sensitive details.</span>"
        "<span>🛡️ Heuristic Resilience & AI Defense</span>"
        "</div>",
        unsafe_allow_html=True
    )

    investigate_clicked = st.button("⚡ Run Threat Investigation", type="primary", use_container_width=True)

    if investigate_clicked and msg.strip():
        with st.status("Agent is investigating indicators...", expanded=True) as status:
            try:
                answer = run_agent(msg, st)
                status.update(label="✓ Investigation Completed", state="complete")
                error_msg = None
            except Exception as exc:
                answer = str(exc)
                error_msg = answer
                status.update(label="✕ Investigation Encountered An Error", state="error")

        if error_msg:
            error_html = html.escape(str(error_msg))
            st.markdown(f"""
            <div class="ss-section-box" style="border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.08);">
                <div style="color: #f87171; font-weight: 700; font-size: 1rem; margin-bottom: 6px;">Investigation Error</div>
                <div style="color: #cbd5e1; font-size: 0.88rem;">{error_html}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            parsed = _parse_report(answer)
            verdict = parsed["verdict"]
            score = parsed["risk_score"]

            if verdict == "SCAM":
                card_class = "ss-verdict-scam"
                verdict_badge = "<span style='background: #ef4444; color: white; padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.85rem;'>🚨 HIGH RISK SCAM</span>"
                bar_color = "linear-gradient(90deg, #f59e0b 0%, #ef4444 100%)"
            elif verdict == "SUSPICIOUS":
                card_class = "ss-verdict-suspicious"
                verdict_badge = "<span style='background: #f59e0b; color: #1e1b4b; padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.85rem;'>⚠️ SUSPICIOUS ACTIVITY</span>"
                bar_color = "linear-gradient(90deg, #10b981 0%, #f59e0b 100%)"
            else:
                card_class = "ss-verdict-safe"
                verdict_badge = "<span style='background: #10b981; color: white; padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.85rem;'>🛡️ LOW RISK / NO STRONG SIGNALS</span>"
                bar_color = "#10b981"

            st.markdown(f"""
            <div class="ss-verdict-card {card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div>{verdict_badge}</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.15rem; font-weight: 700; color: #f8fafc;">
                        RISK SCORE: <span style="font-size: 1.4rem;">{score}</span><span style="color: #64748b; font-size: 0.9rem;">/100</span>
                    </div>
                </div>
                <div class="ss-score-bar-bg">
                    <div class="ss-score-bar-fill" style="width: {score}%; background: {bar_color};"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col1, col2 = st.columns(2)
            why_html = "<br>• ".join([""] + [html.escape(str(item)) for item in parsed["why"]]) if parsed["why"] else "No specific threat markers flagged."
            actions_html = "<br>".join(html.escape(str(item)) for item in parsed["actions"]) if parsed["actions"] else "1. Verify sender through official app or statement."
            with col1:
                st.markdown(f"""
                <div class="ss-section-box">
                    <div class="ss-section-title">🔍 Evidence & Risk Signals (WHY)</div>
                    <div style="color: #e2e8f0; font-size: 0.88rem; line-height: 1.6;">
                        {why_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                <div class="ss-section-box">
                    <div class="ss-section-title">🛡️ Recommended Next Steps</div>
                    <div style="color: #e2e8f0; font-size: 0.88rem; line-height: 1.6;">
                        {actions_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            if verdict in {"SCAM", "SUSPICIOUS"}:
                complaint_text = parsed.get("complaint") or ""
                if not complaint_text:
                    complaint_text = draft_complaint(
                        scam_type="Online Phishing / Fraud",
                        summary=f"Suspicious message investigated: {msg[:120]}...",
                        evidence="; ".join(parsed["why"][:3]),
                        amount_lost="None"
                    )

                st.markdown("""
                <div class="ss-section-box" style="border-color: rgba(239, 68, 68, 0.35); background: rgba(15, 23, 42, 0.85);">
                    <div class="ss-section-title" style="color: #f87171;">
                        📝 Editable Cybercrime Complaint Draft (For cybercrime.gov.in / Helpline 1930)
                    </div>
                """, unsafe_allow_html=True)

                st.text_area(
                    "Review and edit this complaint draft before submitting:",
                    value=complaint_text,
                    height=180,
                    key="editable_complaint_area"
                )

                st.markdown("""
                    <div style="display: flex; gap: 12px; align-items: center; margin-top: 10px; flex-wrap: wrap;">
                        <a href="https://cybercrime.gov.in" target="_blank" style="display: inline-flex; align-items: center; gap: 6px; background: #ef4444; color: white; padding: 7px 16px; border-radius: 8px; font-weight: 700; text-decoration: none; font-size: 0.85rem; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);">
                            🚨 File at cybercrime.gov.in
                        </a>
                        <span style="color: #94a3b8; font-size: 0.82rem;">Or dial <strong>1930</strong> immediately from your phone to report financial fraud.</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with st.expander("🔍 View Raw Agent Output & Tool Telemetry"):
                st.markdown(answer)

    elif investigate_clicked:
        st.warning("Please paste a message or select a sample scenario first.")


# Only run UI automatically if executed directly by Streamlit runner
if __name__ == "__main__" or os.getenv("STREAMLIT_RUNNING"):
    render_ui()
