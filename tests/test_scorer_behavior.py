# -*- coding: utf-8 -*-
from .conftest import load_scorer, normalize_score_tuple

def test_surtaxed_number_flag():
    score_text, _, _ = load_scorer()
    res = score_text("Contactez-moi URGENT au 0899 12 34 56 !")
    prob, reasons, notes = normalize_score_tuple(res)
    assert 0.0 <= prob <= 1.0
    assert len(reasons) + len(notes) >= 1

def test_media_flags_do_not_crash():
    score_text, _, _ = load_scorer()
    media = {"audio": True, "video": True, "voiceprint_mismatch": True}
    res = score_text("Appel vidéo suspect avec voix robotisée", media=media)
    prob, reasons, notes = normalize_score_tuple(res)
    assert 0.0 <= prob <= 1.0
