"""Chaque signal doit etre defendu par un test QUI LUI EST PROPRE.

Mutation du 15/08, un poids a la fois : **18 des 28 poids de `WEIGHTS` pouvaient etre
mis a 0.0 sans qu'un seul test tombe**. Aucun n'etait mort — ils se MASQUAIENT les uns
les autres : les messages des tests declenchent plusieurs regles a la fois, donc en
annuler une laissait les autres porter le score au-dessus du seuil.

Le remede n'est pas d'ajouter des cas realistes (ils cumulent les signaux), c'est de
donner a chaque regle une entree qui ne declenche QU'ELLE. Ces tests-la tombent quand
leur poids passe a 0 — verifie par mutation.

⚠️ PIEGE EVITE DE JUSTESSE : la premiere version de ces tests comparait le score a
`WEIGHTS[poids]`. Quand la mutation met le poids a 0.0, la valeur ATTENDUE devient 0
elle aussi — le test passe, et ne prouve rien. Une assertion qui lit la valeur qu'elle
verifie est auto-referentielle. On assert donc que le score est STRICTEMENT POSITIF.

Poids couverts ici : les deux plus lourds (`malicious_sender` et `url_reputation`,
25.0 chacun) et les signaux distinctifs du produit (deepfake x3, punycode, crypto).
Les autres restent listes dans la memoire projet.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield import scorer  # noqa: E402
from scamshield.scorer import score_text  # noqa: E402


def test_un_expediteur_sur_liste_noire_pese_a_lui_seul():
    """Le poids le plus lourd (25.0). Aucun autre signal dans ce message.

    ⚠️ `MALICIOUS_SENDERS` vient d'une union d'ENSEMBLES : son ordre CHANGE d'une
    execution a l'autre (verifie : 3 lancements, 3 premiers elements differents).
    Prendre `[0]` rendait ce test instable — la moitie des expediteurs ont un domaine
    lui aussi bloque, ce qui ajoute un second signal. On trie, et on choisit un
    expediteur dont le domaine n'est PAS liste, pour n'activer que cette regle."""
    isolables = sorted(s for s in scorer.MALICIOUS_SENDERS
                       if s.split("@")[-1] not in scorer.BLOCKED_DOMAINS)
    assert isolables, "aucun expediteur n'est isolable : la regle devient indefendable"
    score, raisons, _ = score_text(f"From: {isolables[0]}\n\nBonjour, voici le document.")

    assert score > 0, "un expediteur sur liste noire ne pese plus rien"
    assert len(raisons) == 1, f"le message declenche autre chose : {raisons}"


def test_la_reputation_d_url_pese_meme_sans_liste_noire(monkeypatch):
    """⚠️ Les 6 domaines a reputation livres sont TOUS aussi dans la liste noire :
    ce signal ne peut jamais se declencher seul avec les donnees du depot. On injecte
    donc un domaine propre — sinon `blocked_domain` (22.0) masque `url_reputation`
    (25.0) en permanence et la regle reste indefendable."""
    monkeypatch.setitem(scorer.URL_REPUTATION, "exemple-neutre.fr", 1.0)
    score, raisons, _ = score_text("Le document est ici : https://exemple-neutre.fr/doc")

    assert any("putation" in r for r in raisons), f"reputation non prise en compte : {raisons}"
    assert score > 0, "la reputation d'URL ne pese plus rien"


@pytest.mark.parametrize("flag,poids", [
    ("audio", "deepfake_audio"),
    ("video", "deepfake_video"),
    ("voiceprint_mismatch", "voiceprint_mismatch"),
])
def test_chaque_signal_media_pese_seul(flag, poids):
    """Les 3 signaux deepfake : aucun n'etait defendu, et ce sont des arguments
    produit. Message volontairement anodin pour n'activer qu'eux."""
    score, raisons, _ = score_text("Bonjour, rappelle-moi.", media={flag: True})

    assert score > 0, f"le signal media {poids} ne pese plus rien"
    assert len(raisons) == 1, f"{flag} declenche autre chose : {raisons}"


def test_un_domaine_punycode_pese_seul():
    """Attaque homographe : `xn--pypal-4ve.com` imite `paypal`. TLD non suspect,
    domaine non liste — seule la regle punycode peut mordre."""
    score, raisons, _ = score_text("Lien : https://xn--pypal-4ve.com/login")

    assert score > 0, "un domaine punycode ne pese plus rien"
    assert len(raisons) == 1 and "punycode" in raisons[0].lower()


def test_une_adresse_crypto_pese_seule():
    score, raisons, _ = score_text("Envoie sur 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa merci.")

    assert score > 0, "une adresse crypto ne pese plus rien"
    assert len(raisons) == 1


def test_un_message_anodin_ne_declenche_rien():
    """Le temoin : sans lui, les tests ci-dessus pourraient etre verts a cause d'un
    score de base non nul."""
    score, raisons, _ = score_text("Bonjour, rappelle-moi.")

    assert score == 0.0
    assert raisons == []
