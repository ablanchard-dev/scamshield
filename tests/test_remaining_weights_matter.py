"""Les 10 poids qui restaient indefendus apres `test_each_weight_matters.py`.

Meme mesure, meme methode : mutation d'un poids a la fois. Ces dix-la pouvaient
encore passer a 0.0 sans qu'un test tombe. Trois d'entre eux demandent une
assertion d'une autre forme, et c'est la que le piege se trouve :

- **Poids NEGATIFS** (`trusted_sender` -10, `allow_phrase` -4). Un score ne peut
  pas descendre sous zero, donc « le score est positif » ne prouve rien. On
  compare deux messages : le meme, avec et sans le signal rassurant. Le second
  doit etre STRICTEMENT plus bas. Mis a 0, les deux scores s'egalisent.
  ⚠️ Le message temoin doit deja depasser la valeur du bonus, sinon le plancher
  a zero avale la difference et le test devient aveugle.

- **Synergie** (`synergy_money_time`). Elle ne peut par construction jamais se
  declencher seule : il lui faut la pression ET l'argent, donc trois autres
  regles mordent en meme temps. On mesure ce qu'elle est : le tout doit valoir
  STRICTEMENT PLUS que la somme des parties. Mise a 0, tout = parties.

Rappel du piege de la premiere serie : ne jamais comparer le score a
`WEIGHTS[...]` — la mutation deplacerait aussi la valeur attendue.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield import scorer  # noqa: E402
from scamshield.scorer import score_text  # noqa: E402


def _score(txt: str) -> float:
    return score_text(txt)[0]


# --- signaux positifs isolables tels quels -----------------------------------

def test_un_raccourcisseur_pese_seul():
    """⚠️ `bit.ly` est a la fois raccourcisseur, domaine bloque ET mal note : il
    declenche trois regles et n'isole rien. On prend un raccourcisseur qui n'est
    que cela — sinon ce poids reste indefendable avec les donnees livrees."""
    isolables = [d for d in sorted(scorer.SHORTENERS)
                 if d not in scorer.BLOCKED_DOMAINS
                 and scorer._url_reputation_boost(d) == 0]
    assert isolables, "tous les raccourcisseurs sont masques par une autre regle"
    score, raisons, _ = score_text(f"Voir https://{isolables[0]}/3xYz")

    assert score > 0, "un raccourcisseur d'URL ne pese plus rien"
    assert len(raisons) == 1, f"le message declenche autre chose : {raisons}"


def test_un_iban_pese_seul():
    score, raisons, _ = score_text("Coordonnees : FR7630006000011234567890189")

    assert score > 0, "un IBAN ne pese plus rien"
    assert len(raisons) == 1 and "IBAN" in raisons[0]


def test_une_piece_jointe_executable_pese_seule():
    """Nom de fichier volontairement neutre : « facture.exe » declencherait aussi
    la demande financiere et masquerait ce poids."""
    score, raisons, _ = score_text("Ci-joint document.exe pour information.")

    assert score > 0, "une piece jointe executable ne pese plus rien"
    assert len(raisons) == 1


def test_un_reply_to_divergent_pese_seul():
    score, raisons, _ = score_text(
        "From: contact@societe-exemple.fr\n"
        "Reply-To: autre@ailleurs-exemple.fr\n\nBonjour."
    )

    assert score > 0, "un Reply-To divergent ne pese plus rien"
    assert len(raisons) == 1 and "Reply-To" in raisons[0]


def test_un_domaine_a_scripts_mixtes_pese_seul():
    # « paypal » avec un « у » cyrillique : l'oeil ne voit rien, le code doit voir.
    score, raisons, _ = score_text("Lien : https://paуpal-exemple.com/x")

    assert score > 0, "un domaine a scripts mixtes ne pese plus rien"
    assert len(raisons) == 1


def test_une_demande_de_qr_code_pese_seule():
    score, raisons, _ = score_text("Merci de scanner le QR code ci-joint.")

    assert score > 0, "une demande de scan QR ne pese plus rien"
    assert len(raisons) == 1


def test_une_marque_usurpee_dans_le_nom_d_affichage_pese_seule():
    """Le nom d'affichage annonce une marque, le domaine dit autre chose."""
    score, raisons, _ = score_text(
        'From: "Service Amazon" <contact@societe-exemple.fr>\n\nBonjour.'
    )

    assert score > 0, "un nom d'affichage usurpant une marque ne pese plus rien"
    assert len(raisons) == 1

    # temoin : la meme marque sur son vrai domaine ne doit rien declencher
    assert _score('From: "Service Amazon" <contact@amazon.fr>\n\nBonjour.') == 0.0


# --- poids negatifs : on compare, on ne mesure pas ----------------------------

def test_un_expediteur_fiable_fait_BAISSER_le_score():
    """⚠️ Un score ne descend pas sous zero. Si le message temoin vaut moins que
    le bonus, le plancher avale la difference et le test ne prouve plus rien :
    on prend donc un message franchement charge."""
    charge = "Bonjour, cliquez ici pour valider. C'est urgent, repondez immediatement."
    sans = _score(charge)
    assert sans > abs(scorer.WEIGHTS["trusted_sender"]), (
        "message temoin trop faible : le plancher a zero rendrait ce test aveugle"
    )
    avec = _score(f"From: contact@edf.fr\n\n{charge}")

    assert avec < sans, "un expediteur fiable ne fait plus baisser le score"


def test_une_phrase_rassurante_fait_BAISSER_le_score():
    deny = scorer.DENYLIST_PHRASES[0]
    allow = scorer.ALLOWLIST_PHRASES[1]
    sans = _score(f"Bonjour, {deny}.")
    avec = _score(f"Bonjour, {deny}. {allow}.")

    assert avec < sans, "un indice rassurant ne fait plus baisser le score"


# --- synergie : le tout doit valoir plus que la somme des parties -------------

def test_la_synergie_pression_argent_vaut_plus_que_ses_parties():
    """Cette regle ne peut jamais se declencher seule — il lui faut la pression ET
    l'argent. On epingle donc ce qu'elle EST : un supplement. Mise a 0, le tout
    retombe exactement sur la somme des parties et ce test tombe."""
    pression = _score("C'est urgent, repondez immediatement.")
    argent = _score("Merci de virer 250 euros.")
    ensemble, raisons, _ = score_text("C'est urgent, virez 250 euros immediatement.")

    assert "Pression + argent" in raisons, f"synergie non declenchee : {raisons}"
    assert ensemble > pression + argent, (
        "la synergie pression+argent n'ajoute plus rien : "
        f"{ensemble} = {pression} + {argent}"
    )


def test_des_caracteres_invisibles_pesent_seuls():
    """Le zero-width space sert a casser la detection de phrases : il doit peser
    par lui-meme, sinon l'obfuscation devient gratuite. Texte anodin pour ne pas
    reveiller la denylist."""
    score, raisons, _ = score_text("Bon​jour, rappelle-moi.")

    assert score > 0, "les caracteres invisibles ne pesent plus rien"
    assert len(raisons) == 1 and "invisibles" in raisons[0]
