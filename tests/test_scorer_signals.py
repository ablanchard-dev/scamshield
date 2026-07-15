# -*- coding: utf-8 -*-
"""Tests comportementaux du scorer : chaque signal de risque doit peser.

On compare surtout des messages identiques AVEC vs SANS un signal donné, pour
rester robuste aux poids exacts (qui peuvent évoluer).
"""
from .conftest import load_scorer, normalize_score_tuple


def _p(res):
    return normalize_score_tuple(res)[0]


def test_suspicious_scores_higher_than_benign():
    score_text, _, _ = load_scorer()
    benign = _p(score_text("Bonjour, merci pour ton retour, a demain au bureau."))
    scam = _p(score_text(
        "URGENT ! Votre compte sera suspendu. Cliquez vite http://bit.ly/secure "
        "et confirmez vos identifiants bancaires."))
    assert scam > benign


def test_zero_width_obfuscation_flagged():
    score_text, _, _ = load_scorer()
    # base neutre : le caractère invisible est le SEUL signal qui change
    # (sur un mot-clé, l'obfuscation casserait le match au lieu d'ajouter du risque)
    p_clean, _, _ = normalize_score_tuple(score_text("bonjour tout le monde ca va"))
    p_obf, r_obf, _ = normalize_score_tuple(score_text("bonjour​ tout le monde ca va"))
    assert p_obf >= p_clean
    assert any("invisible" in x.lower() or "obfusc" in x.lower() for x in r_obf)


def test_url_shortener_adds_risk():
    score_text, _, _ = load_scorer()
    plain = _p(score_text("Voici le lien : https://www.example.org/page"))
    short = _p(score_text("Voici le lien : http://bit.ly/abcd"))
    assert short >= plain


def test_deepfake_media_increases_score():
    score_text, _, _ = load_scorer()
    text = "Appel de votre banque, confirmez votre code."
    base = _p(score_text(text))
    with_media = _p(score_text(text, media={"voiceprint_mismatch": True}))
    assert with_media > base


def test_btc_address_raises_signal():
    score_text, _, _ = load_scorer()
    base = _p(score_text("Merci de regler la facture."))
    btc = _p(score_text(
        "Envoyez le paiement a cette adresse 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
    assert btc >= base


def test_urgency_adds_risk():
    score_text, _, _ = load_scorer()
    neutral = _p(score_text("Pouvez-vous me rappeler quand vous avez un moment ?"))
    urgent = _p(score_text(
        "URGENT repondez immediatement sous peine de suspension de votre compte"))
    assert urgent >= neutral


def test_determinism():
    score_text, _, _ = load_scorer()
    msg = "URGENT cliquez http://bit.ly/x et donnez votre mot de passe"
    assert score_text(msg) == score_text(msg)


def test_empty_text_is_handled():
    score_text, _, _ = load_scorer()
    p, reasons, notes = normalize_score_tuple(score_text(""))
    assert 0.0 <= p <= 1.0
    assert isinstance(reasons, list)
    assert isinstance(notes, list)


def test_suspicious_message_has_reasons():
    score_text, _, _ = load_scorer()
    _, reasons, notes = normalize_score_tuple(score_text(
        "URGENT ! Cliquez http://bit.ly/x et donnez votre mot de passe"))
    assert len(reasons) + len(notes) >= 1


def test_prob_always_in_range():
    score_text, _, _ = load_scorer()
    for msg in ("", "coucou", "URGENT http://bit.ly/x mot de passe IBAN FR7630006000011234567890189"):
        p, _, _ = normalize_score_tuple(score_text(msg))
        assert 0.0 <= p <= 1.0


def test_score_url_contract():
    score_text, score_url, _ = load_scorer()
    if score_url is None:
        import pytest
        pytest.skip("score_url non exposé")
    p, reasons, notes = normalize_score_tuple(score_url("http://bit.ly/abcd"))
    assert 0.0 <= p <= 1.0
    assert isinstance(reasons, list)


def test_explain_reasons_non_empty_markdown():
    _, _, explain = load_scorer()
    if explain is None:
        import pytest
        pytest.skip("explain_reasons non exposé")
    md = explain(80.0, ["Lien raccourci suspect", "Demande d'identifiants"], ["note"])
    assert isinstance(md, str) and md.strip()


def test_long_benign_text_no_crash():
    score_text, _, _ = load_scorer()
    txt = "Bonjour, " + "tout va bien aujourd'hui. " * 50
    p, _, _ = normalize_score_tuple(score_text(txt))
    assert 0.0 <= p <= 1.0


def _grey_zone_scam():
    # Un scam qui tombe dans la bande DOUTEUX (25-60) avec les règles seules :
    # c'est le cas que le LLM est censé arbitrer.
    from scamshield.scorer import score_text
    t = ("URGENT maman j'ai casse mon telephone, voici mon nouveau numero. "
         "Peux-tu m'envoyer 250EUR par PCS, je te rembourse ce soir.")
    s, _, _ = score_text(t)
    assert 25.0 <= s < 60.0, f"pre-requis test : attendu zone grise, obtenu {s}"
    return t


def test_llm_off_by_default_is_graceful():
    # LLM indisponible (endpoint injoignable -> None) : use_llm=True ne doit ni
    # crasher ni changer le verdict. Le moteur de règles reste maître (dégradation
    # propre = frontière de confiance). On force None (pas d'appel réseau en test).
    import scamshield.llm as llm
    from scamshield.scorer import score_text
    t = _grey_zone_scam()
    rules_only, _, _ = score_text(t)
    with_forced_none, r, _ = _monkey(llm, lambda *_a, **_k: None, lambda: score_text(t, use_llm=True))
    assert with_forced_none == rules_only
    assert not any("LLM:" in x for x in r)


def test_llm_adjudicates_grey_zone_when_available():
    # Quand le LLM répond "scam" avec confiance, un cas gris est promu RISQUÉ
    # et la raison LLM est exposée (l'explicabilité continue).
    import scamshield.llm as llm
    from scamshield.scorer import score_text
    t = _grey_zone_scam()
    fake = {"verdict": "scam", "confidence": 0.9, "reason": "arnaque au proche + PCS"}
    s, reasons, _ = _monkey(llm, lambda *_a, **_k: fake, lambda: score_text(t, use_llm=True))
    assert s >= 60.0
    assert any("LLM: scam" in x for x in reasons)


def _monkey(module, replacement, call):
    # Remplace llm_adjudicate le temps de l'appel (import interne au scorer).
    orig = module.llm_adjudicate
    module.llm_adjudicate = replacement
    try:
        return call()
    finally:
        module.llm_adjudicate = orig


def test_dangerous_attachment_flagged():
    # Regression : un nom de fichier normal (facture.exe) doit lever le signal
    # piece-jointe. Un backslash parasite dans le regex le rendait mort (matchait
    # seulement "xxx\.exe"), le signal ne se declenchait jamais.
    score_text, _, _ = load_scorer()
    p_no, _, _ = normalize_score_tuple(score_text("Bonjour, voici le document en piece jointe."))
    p_att, r_att, _ = normalize_score_tuple(
        score_text("Bonjour, ouvrez la piece jointe facture.exe pour valider."))
    assert p_att > p_no
    assert any("jointe" in x.lower() for x in r_att)
