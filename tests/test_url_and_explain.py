# -*- coding: utf-8 -*-
import pytest
from .conftest import load_scorer, normalize_score_tuple

def test_score_url_if_available():
    _, score_url, _ = load_scorer()
    if score_url is None:
        pytest.skip("score_url non disponible")
    res = score_url("http://bit.ly/claim-now")
    prob, reasons, notes = normalize_score_tuple(res)
    assert 0.0 <= prob <= 1.0
    assert isinstance(reasons, list)

def test_explain_reasons_if_available():
    _, _, explain_reasons = load_scorer()
    if explain_reasons is None:
        pytest.skip("explain_reasons non disponible")
    md = explain_reasons(87, ["URL raccourcie", "Urgence/pression"], ["Possible phishing"])
    assert isinstance(md, str) and md.strip()
