# -*- coding: utf-8 -*-
import importlib

def load_scorer():
    mod = importlib.import_module("scamshield.scorer")
    score_text = getattr(mod, "score_text")
    score_url = getattr(mod, "score_url", None)
    explain_reasons = getattr(mod, "explain_reasons", None)
    return score_text, score_url, explain_reasons

def normalize_score_tuple(res):
    if not isinstance(res, tuple) or len(res) != 3:
        raise AssertionError(f"Retour inattendu: {type(res)} {res}")
    s, reasons, notes = res
    prob = float(s) / 100.0 if float(s) > 1.0 else float(s)
    prob = max(0.0, min(1.0, prob))
    return prob, list(reasons or []), list(notes or [])
