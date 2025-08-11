# -*- coding: utf-8 -*-
from .conftest import load_scorer, normalize_score_tuple

def test_score_text_contract_runs():
    score_text, _, _ = load_scorer()
    res = score_text("Bonjour, pouvez-vous me rappeler à propos d’une facture ?")
    prob, reasons, notes = normalize_score_tuple(res)
    assert 0.0 <= prob <= 1.0
    assert isinstance(reasons, list)
    assert isinstance(notes, list)

def test_score_text_handles_suspicious_message():
    score_text, _, _ = load_scorer()
    benign = score_text("Bonjour, facture réglée hier, merci.")
    suspicious = score_text("Claim your prize now!!! Click here: http://bit.ly/freegift")
    p_b, _, _ = normalize_score_tuple(benign)
    p_s, _, _ = normalize_score_tuple(suspicious)
    assert p_s >= p_b
