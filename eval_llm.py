"""Eval de la couche LLM : moteur de règles SEUL vs règles + LLM (zone grise).

Mesure honnête sur la batterie monde-réel (22 messages : 11 scams + 11 légitimes).
Publie recall / précision / faux positifs / cas gris ré-arbitrés / latence / coût —
et le chiffre sort tel quel, même s'il est décevant. C'est le but.

Usage :
    ANTHROPIC_API_KEY=... python eval_llm.py

Sans clé, la passe LLM dégrade proprement (aucun cas ré-arbitré) et l'eval le dit.
"""
import os
import time

from scamshield.scorer import score_text
from tests.test_realworld_battery import SCAMS, LEGIT

# Prix Haiku 4.5 (USD / 1M tokens), cf. skill claude-api. Estimation ~300 in + ~50 out par appel.
HAIKU_IN, HAIKU_OUT = 1.0, 5.0
EST_IN_TOK, EST_OUT_TOK = 300, 50


def band(s):
    return "SUR" if s < 25 else "DOUTEUX" if s < 60 else "RISQUE"


def evaluate(use_llm):
    """Retourne (recall, precision, faux_positifs, gris, latence_ms_par_appel)."""
    tp = fp = grey = 0
    t_llm = 0.0
    n_calls = 0
    for t in SCAMS:
        s0, *_ = score_text(t)                    # score règles (pour compter la zone grise)
        if 25.0 <= s0 < 60.0 and use_llm:
            grey += 1
        t0 = time.perf_counter()
        s, *_ = score_text(t, use_llm=use_llm)
        if use_llm and 25.0 <= s0 < 60.0:
            t_llm += time.perf_counter() - t0
            n_calls += 1
        if band(s) != "SUR":
            tp += 1
    for t in LEGIT:
        s0, *_ = score_text(t)
        if 25.0 <= s0 < 60.0 and use_llm:
            grey += 1
        t0 = time.perf_counter()
        s, *_ = score_text(t, use_llm=use_llm)
        if use_llm and 25.0 <= s0 < 60.0:
            t_llm += time.perf_counter() - t0
            n_calls += 1
        if band(s) != "SUR":
            fp += 1
    recall = tp / len(SCAMS)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    lat = (t_llm / n_calls * 1000) if n_calls else 0.0
    return recall, precision, fp, grey, lat


def main():
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    print(f"Cle API detectee : {'oui' if has_key else 'NON (passe LLM inactive)'}\n")

    r0, p0, fp0, _, _ = evaluate(use_llm=False)
    r1, p1, fp1, grey, lat = evaluate(use_llm=True)

    print(f"{'':22} {'REGLES':>8} {'REGLES+LLM':>12}")
    print(f"{'recall (scams)':22} {r0:>7.0%} {r1:>11.0%}")
    print(f"{'precision':22} {p0:>7.0%} {p1:>11.0%}")
    print(f"{'faux positifs':22} {fp0:>8} {fp1:>12}")
    print(f"\nCas en zone grise (DOUTEUX), candidats a l'arbitrage LLM : {grey}")
    if has_key:
        cost_per_call = (EST_IN_TOK * HAIKU_IN + EST_OUT_TOK * HAIKU_OUT) / 1e6
        print(f"Latence moyenne / appel LLM : ~{lat:.0f} ms")
        print(f"Cout estime : ~{cost_per_call*1000:.2f} USD / 1000 messages en zone grise")
    else:
        print("Passe LLM inactive (pas de cle) : REGLES+LLM == REGLES ci-dessus.")


if __name__ == "__main__":
    main()
