\
import streamlit as st
from scamshield.scorer import score_text, score_url, explain_reasons

st.set_page_config(
    page_title="SCAMShield — Prototype",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ SCAMShield — Prototype (texte & URL)")
st.write("Collez un **message** (email/SMS) ou un **lien** pour évaluer le risque.")

tab1, tab2, tab3 = st.tabs(["📨 Message", "🔗 URL", "🧪 Exemples"])

with tab1:
    txt = st.text_area("Message", height=180, placeholder="Collez ici le message à analyser…")
    if st.button("Analyser le message", type="primary"):
        if not txt.strip():
            st.warning("Veuillez coller un message.")
        else:
            score, reasons = score_text(txt)
            st.metric("Score de risque (0-100)", score)
            st.markdown(explain_reasons(score, reasons))

with tab2:
    url = st.text_input("URL")
    if st.button("Analyser l’URL"):
        if not url.strip():
            st.warning("Veuillez saisir une URL.")
        else:
            score, reasons = score_url(url.strip())
            st.metric("Score de risque (0-100)", score)
            st.markdown(explain_reasons(score, reasons))

with tab3:
    st.write("**Exemples rapides**")
    samples = [
        ("LEGIT", "Hi Alex, here is the Zoom link for 3pm. No rush."),
        ("SCAM", "URGENT: Your bank account will be closed in 3 hours. Verify now: http://secure-bànk-support.com/login"),
        ("SCAM", "Code OTP 431992 – Do not share with anyone (reply to confirm)."),
        ("SCAM", "Congratulations! You won 1000€ Amazon gift card. Claim: http://amàzon-prize.win"),
        ("LEGIT", "Invoice attached from our usual vendor (same IBAN). Call me if needed.")
    ]
    for label, s in samples:
        st.caption(f"**{label}** — {s}")
