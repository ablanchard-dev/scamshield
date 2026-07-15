"""Eval de la couche LLM : moteur de règles SEUL vs règles + LLM (zone grise).

Mesure honnête sur la batterie monde-réel (22 messages : 11 scams + 11 légitimes).
Publie recall / précision / faux positifs / cas gris ré-arbitrés / latence — et le
chiffre sort tel quel, même s'il est décevant. C'est le but.

100% gratuit : la couche auto-détecte une clé free-tier présente (Groq / Cerebras /
Gemini / Mistral — mêmes clés que lumenia), sinon retombe sur un Ollama local.
    export GROQ_API_KEY=...   # gratuit sur console.groq.com
    python eval_llm.py

Détails / surcharge explicite : voir scamshield/llm.py.
Sans endpoint joignable, la passe LLM dégrade proprement et l'eval le dit.
"""
import time

from scamshield.llm import llm_adjudicate
from scamshield.scorer import score_text
from tests.test_realworld_battery import SCAMS, LEGIT


def band(s):
    return "SUR" if s < 25 else "DOUTEUX" if s < 60 else "RISQUE"


def evaluate(use_llm):
    """Retourne (recall, precision, faux_positifs, gris, latence_ms_par_appel)."""
    tp = fp = grey = n_calls = 0
    t_llm = 0.0
    for corpus, is_scam in ((SCAMS, True), (LEGIT, False)):
        for t in corpus:
            s0, *_ = score_text(t)                 # score règles seul (pour repérer la zone grise)
            in_grey = 25.0 <= s0 < 60.0
            if in_grey and use_llm:
                grey += 1
            t0 = time.perf_counter()
            s, *_ = score_text(t, use_llm=use_llm)
            if use_llm and in_grey:
                t_llm += time.perf_counter() - t0
                n_calls += 1
            flagged = band(s) != "SUR"
            if is_scam and flagged:
                tp += 1
            elif not is_scam and flagged:
                fp += 1
    recall = tp / len(SCAMS)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    lat = (t_llm / n_calls * 1000) if n_calls else 0.0
    return recall, precision, fp, grey, lat


def main():
    available = llm_adjudicate("Bonjour, ceci est un simple test.") is not None
    print(f"Endpoint LLM : {'joignable' if available else 'INJOIGNABLE (passe LLM inactive)'}\n")

    r0, p0, fp0, _, _ = evaluate(use_llm=False)
    r1, p1, fp1, grey, lat = evaluate(use_llm=True)

    print(f"{'':22} {'REGLES':>8} {'REGLES+LLM':>12}")
    print(f"{'recall (scams)':22} {r0:>7.0%} {r1:>11.0%}")
    print(f"{'precision':22} {p0:>7.0%} {p1:>11.0%}")
    print(f"{'faux positifs':22} {fp0:>8} {fp1:>12}")
    print(f"\nCas en zone grise (DOUTEUX), candidats a l'arbitrage LLM : {grey}")
    if available:
        print(f"Latence moyenne / appel LLM : ~{lat:.0f} ms")
        print("Cout : 0 (Ollama local, rien ne sort de la machine)")
    else:
        print("Passe LLM inactive (endpoint injoignable) : REGLES+LLM == REGLES ci-dessus.")


if __name__ == "__main__":
    main()
