# -*- coding: utf-8 -*-
import traceback
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from scamshield.scorer import score_text

st.set_page_config(page_title="SCAMShield — Prototype", page_icon="🛡️", layout="centered")

# --- Helpers ---------------------------------------------------------------

def _normalize_score(res) -> Tuple[float, List[str], List[str]]:
    """
    Accepte le retour brut de score_text(...) et renvoie :
      (prob_0_1, red_flags, hints)
    """
    # score_text(text) -> (score, red_flags, hints)
    if isinstance(res, tuple):
        s, red, hints = res
    elif isinstance(res, dict):
        s = float(res.get("score", res.get("proba", 0.0)))
        red = res.get("red_flags") or res.get("reasons") or []
        hints = res.get("hints", [])
    else:
        raise ValueError(f"Format inattendu: {type(res)} -> {res}")

    # Certains scorers renvoient 0–100 au lieu de 0–1
    prob = s / 100.0 if s > 1.0 else float(s)
    return max(0.0, min(1.0, prob)), list(red or []), list(hints or [])


def _render_result(title: str, prob: float, red: List[str], hints: List[str], threshold_pct: int):
    percent = round(prob * 100, 1)
    label = "SCAM" if percent >= threshold_pct else "LEGIT"

    st.subheader(title)
    cols = st.columns([1, 1, 2])
    with cols[0]:
        st.metric("Risque SCAM", f"{percent:.1f}%")
    with cols[1]:
        st.metric("Décision", label)

    if red:
        st.markdown("**🔴 Red flags détectés**")
        for r in red:
            st.write(f"• {r}")

    if hints:
        st.markdown("**🟡 Indices**")
        for h in hints:
            st.write(f"• {h}")


# --- UI --------------------------------------------------------------------

st.title("🛡️ SCAMShield — Prototype (texte & URL)")
st.caption("Collez un message (email/SMS) ou un lien pour évaluer le risque.")

with st.sidebar:
    st.header("Réglages")
    threshold_pct = st.slider("Seuil d’alerte (%)", 10, 90, 50, 5)
    st.caption("≥ seuil → classé SCAM")

tabs = st.tabs(["📨 Message", "🔗 URL", "🧪 Exemples"])

# -- Onglet Message
with tabs[0]:
    txt = st.text_area("Message", height=160, placeholder="Ex: Bonjour, pouvez-vous me rappeler à propos d’une facture ?")
    if st.button("Analyser le message", type="primary"):
        if not txt.strip():
            st.warning("Merci de coller un message avant d’analyser.")
        else:
            try:
                raw = score_text(txt)
                prob, red, hints = _normalize_score(raw)
                _render_result("Résultat (Message)", prob, red, hints, threshold_pct)
            except Exception as e:
                st.error("Erreur pendant l’analyse du message.")
                with st.expander("Détails de l’erreur"):
                    st.code("".join(traceback.format_exc()), language="python")

# -- Onglet URL (analyse basique en tant que texte)
with tabs[1]:
    url = st.text_input("URL", placeholder="https://exemple.com/...")
    if st.button("Analyser l’URL"):
        if not url.strip():
            st.warning("Merci de saisir une URL avant d’analyser.")
        else:
            try:
                # Si tu as un score_url(...) ailleurs, remplace par cet appel.
                raw = score_text(url)
                prob, red, hints = _normalize_score(raw)
                _render_result("Résultat (URL)", prob, red, hints, threshold_pct)
            except Exception as e:
                st.error("Erreur pendant l’analyse de l’URL.")
                with st.expander("Détails de l’erreur"):
                    st.code("".join(traceback.format_exc()), language="python")

# -- Onglet Exemples
with tabs[2]:
    st.write("Clique sur un exemple pour le tester :")
    ex1 = "Bonjour, pouvez-vous me rappeler à propos d’une facture ?"
    ex2 = "Claim your prize now!!! Click here to receive your reward."
    ex3 = "0899 12 34 56 — contact urgent"

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Exemple: facture (FR)"):
            raw = score_text(ex1)
            prob, red, hints = _normalize_score(raw)
            _render_result("Exemple — facture", prob, red, hints, threshold_pct)
    with c2:
        if st.button("Exemple: prize (EN)"):
            raw = score_text(ex2)
            prob, red, hints = _normalize_score(raw)
            _render_result("Exemple — prize", prob, red, hints, threshold_pct)
    with c3:
        if st.button("Exemple: numéro surtaxé"):
            raw = score_text(ex3)
            prob, red, hints = _normalize_score(raw)
            _render_result("Exemple — numéro", prob, red, hints, threshold_pct)
