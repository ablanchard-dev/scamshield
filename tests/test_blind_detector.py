"""Un detecteur prive de ses regles ne doit jamais dire "SUR".

Mesure du 15/08 : un phishing dont l'expediteur ET le domaine sont sur liste noire
sortait a 88/100 "RISQUE" avec les donnees, et a 0/100 "SUR" avec ZERO raison quand
les fichiers de regles etaient absents. Le detecteur affirmait la securite pendant
qu'il etait aveugle -- exactement l'inverse de son metier.
"""
import importlib
import tempfile

import pytest

import scamshield.scorer as scorer
from app.main import verdict

SCAM = ("From: Service Facturation <billing@amaz0n-help.com>\n"
        "Objet : Votre recu de commande\n\n"
        "Bonjour, veuillez trouver le recu de votre derniere commande ici : "
        "https://amaz0n-help.com/recu/48211. Merci de votre confiance.\n")


@pytest.fixture
def aveugle(monkeypatch):
    """Simule un deploiement ou les fichiers de regles n'ont pas ete embarques."""
    vide = tempfile.mkdtemp()
    monkeypatch.setattr(scorer, "DATA_DIR", vide)
    monkeypatch.setattr(scorer, "MISSING_DATA", [], raising=False)
    for nom, fichier in [("TRUSTED_SENDERS", "trusted_senders.txt"),
                         ("MALICIOUS_SENDERS", "malicious_senders.txt"),
                         ("BLOCKED_DOMAINS", "blocked_domains.txt"),
                         ("DENYLIST_PHRASES", "denylist_phrases.txt"),
                         ("SUSPICIOUS_TLDS", "suspicious_tlds.txt")]:
        monkeypatch.setattr(scorer, nom, scorer._load_list(fichier))
    return scorer


def test_les_donnees_completes_ne_declenchent_aucune_alerte():
    # Garde-fou du garde-fou : en fonctionnement normal, rien ne doit changer.
    assert scorer.data_is_complete() is True
    score, raisons, _ = scorer.score_text(SCAM)
    assert score >= 60, "ce message est un phishing avere"
    assert not any("ANALYSE INCOMPLETE" in r.upper() for r in raisons)
    assert verdict(score)[1] == "RISQUÉ"


def test_regles_manquantes_signalees_au_chargement(aveugle):
    assert aveugle.MISSING_DATA, "un fichier absent doit laisser une trace"
    assert aveugle.data_is_complete() is False


def test_le_score_dit_lui_meme_qu_il_est_incomplet(aveugle):
    _, raisons, _ = aveugle.score_text(SCAM)
    assert raisons, "un score aveugle ne doit pas sortir sans une seule raison"
    assert "ANALYSE INCOMPLÈTE" in raisons[0], \
        "l'avertissement doit etre la PREMIERE raison, pas noyee en fin de liste"


def test_le_verdict_ne_peut_plus_dire_SUR_a_l_aveugle(aveugle):
    score, _, _ = aveugle.score_text(SCAM)
    # Le score chute (les listes ne peuvent plus matcher), c'est attendu...
    assert score < 25, "sans les listes, ce message ne declenche plus rien"
    # ...mais le VERDICT ne doit pas se laisser tromper.
    cls, label = verdict(score)
    assert label != "SÛR", "une arnaque reelle affichee SURE parce que le moteur est aveugle"
    assert cls == "doubt"


def test_un_json_illisible_compte_aussi_comme_une_cecite(tmp_path, monkeypatch):
    # Fichier present mais corrompu : le `except: return {}` d'origine l'avalait.
    mauvais = tmp_path / "url_reputation.json"
    mauvais.write_text("{ ceci n'est pas du json", encoding="utf-8")
    monkeypatch.setattr(scorer, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(scorer, "MISSING_DATA", [], raising=False)
    scorer._load_json("url_reputation.json")
    assert scorer.MISSING_DATA == ["url_reputation.json"]
