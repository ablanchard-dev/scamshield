# -*- coding: utf-8 -*-
import html

import streamlit as st

from scamshield.scorer import score_text, data_is_complete

st.set_page_config(page_title="SCAMShield", layout="centered")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@600&display=swap');
:root { --amber:#F59E0B; --green:#22C55E; --red:#EF4444; --bg:#0F172A;
  --fg:#F8FAFC; --dim:#94A3B8; --border:#334155; --muted:#1E293B; }
.stApp { background: var(--bg); }
html, body, [class*="css"], .stMarkdown { font-family:'IBM Plex Sans', system-ui, sans-serif; color: var(--fg); }
.block-container { max-width: 720px; padding-top: 2.4rem; }
h1,h2,h3,p,label { color: var(--fg) !important; }
.stTextArea textarea, .stTextInput input { background: var(--muted) !important; color: var(--fg) !important;
  border:1px solid var(--border) !important; border-radius:12px !important; }
.stTextArea textarea:focus { border-color: var(--amber) !important; box-shadow:0 0 0 3px rgba(245,158,11,.18) !important; }
.stButton>button { background: var(--amber); color:#0F172A; font-weight:700; border:0;
  border-radius:12px; padding:.5rem 1.1rem; transition: filter .15s ease; }
.stButton>button:hover { filter:brightness(1.06); color:#0F172A; border:0; }
.ss-brand{display:flex;align-items:center;gap:12px;margin-bottom:6px;}
.ss-mark{width:40px;height:40px;border-radius:11px;background:linear-gradient(180deg,#1E293B,#0B1220);
  border:1px solid var(--border);display:grid;place-items:center;}
.ss-title{font-size:26px;font-weight:700;letter-spacing:-.02em;margin:0;}
.ss-sub{color:var(--dim);font-size:13px;margin:0;}
.ss-card{background:var(--muted);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-top:8px;}
.ss-scorerow{display:flex;align-items:baseline;gap:12px;}
.ss-score{font-family:'IBM Plex Mono',monospace;font-size:46px;font-weight:600;letter-spacing:-.03em;
  line-height:1;font-variant-numeric:tabular-nums;}
.ss-score small{font-size:18px;color:var(--dim);}
.ss-badge{margin-left:auto;align-self:center;padding:5px 12px;border-radius:999px;font-size:13px;font-weight:700;letter-spacing:.04em;}
.ss-safe{background:rgba(34,197,94,.15);color:#4ADE80;border:1px solid rgba(34,197,94,.4);}
.ss-doubt{background:rgba(245,158,11,.15);color:var(--amber);border:1px solid rgba(245,158,11,.4);}
.ss-risky{background:rgba(239,68,68,.15);color:#F87171;border:1px solid rgba(239,68,68,.4);}
.ss-meter{position:relative;height:9px;border-radius:999px;margin:14px 0 5px;
  background:linear-gradient(90deg,var(--green) 0 25%,var(--amber) 25% 60%,var(--red) 60% 100%);opacity:.85;}
.ss-needle{position:absolute;top:-3px;width:3px;height:15px;border-radius:2px;background:var(--fg);box-shadow:0 0 0 2px var(--bg);}
.ss-ticks{display:flex;justify-content:space-between;color:var(--dim);font-size:11px;}
.ss-reason{display:flex;align-items:center;gap:10px;padding:8px 0;border-top:1px solid var(--border);font-size:14px;}
.ss-dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--amber);}
.ss-foot{color:var(--dim);font-size:12px;margin-top:14px;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

SHIELD = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" '
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
          '<path d="M12 2l8 3v6c0 5-3.4 8.5-8 11-4.6-2.5-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/></svg>')

st.markdown(
    f'<div class="ss-brand"><div class="ss-mark">{SHIELD}</div><div>'
    f'<p class="ss-title">SCAMShield</p>'
    f"<p class=\"ss-sub\">Détecteur d'arnaque &amp; phishing — moteur explicable, analyse 100&nbsp;% locale</p>"
    f"</div></div>",
    unsafe_allow_html=True,
)


def verdict(s):
    # Un moteur privé de ses fichiers de règles ne trouve rien parce qu'il ne PEUT
    # rien trouver : il rendait alors 0/100 « SÛR » sur un phishing dont l'expéditeur
    # et le domaine sont sur liste noire (88/100 « RISQUÉ » avec les données).
    # « Je n'ai pas mes règles » ne doit jamais s'afficher comme « c'est sûr ».
    if not data_is_complete():
        return "doubt", "DOUTEUX"
    if s < 25:
        return "safe", "SÛR"
    if s < 60:
        return "doubt", "DOUTEUX"
    return "risky", "RISQUÉ"


def render(score, reasons):
    cls, label = verdict(score)
    rows = "".join(
        f'<div class="ss-reason"><span class="ss-dot"></span><span>{html.escape(r)}</span></div>'
        for r in reasons
    ) or ('<div class="ss-reason" style="border:0;color:#94A3B8">'
          "Aucun indicateur de risque notable détecté.</div>")
    st.markdown(
        f'<div class="ss-card">'
        f'<div class="ss-scorerow"><div class="ss-score">{int(score)}<small>/100</small></div>'
        f'<span class="ss-badge ss-{cls}">{label}</span></div>'
        f'<div class="ss-meter"><span class="ss-needle" style="left:calc({score}% - 1.5px)"></span></div>'
        f'<div class="ss-ticks"><span>Sûr</span><span>Douteux</span><span>Risqué</span></div>'
        f"<div>{rows}</div></div>",
        unsafe_allow_html=True,
    )


EXAMPLES = {
    "Faux colis": "Votre colis est retenu. Réglez 2,99€ sous 24h : http://amazon-prize.win",
    "Faux support": "Message de votre banque : connexion suspecte, vérifiez votre compte http://secure-bank-support.com",
    "Légitime": "Café d'équipe jeudi 10h salle A2, pense au projecteur. Aucune action requise.",
}

txt = st.text_area("Message à vérifier", height=150, placeholder="Collez un SMS ou un e-mail suspect…")
if st.button("Analyser", type="primary"):
    if not txt.strip():
        st.warning("Collez un message avant d'analyser.")
    else:
        score, reasons, _ = score_text(txt)
        render(score, reasons)

st.write("")
st.caption("Ou testez un exemple :")
cols = st.columns(len(EXAMPLES))
for col, (name, sample) in zip(cols, EXAMPLES.items()):
    if col.button(name):
        score, reasons, _ = score_text(sample)
        render(score, reasons)

st.markdown(
    '<p class="ss-foot">Le moteur liste les raisons de chaque score. '
    "Métriques (voir le README) : moteur explicable ROC-AUC 0.82 · "
    "baseline ML F1 0.96 sur le corpus UCI SMS&nbsp;Spam.</p>",
    unsafe_allow_html=True,
)
