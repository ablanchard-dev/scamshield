"""Ce que les seuils AFFICHES donnent vraiment, sur le jeu de donnees publie.

Le README annonce « Best F1 0.824 » — mesure au seuil qui maximise F1 (7 sur ce
corpus). Le produit, lui, affiche ses verdicts a 25 (SUR/DOUTEUX) et 60 (RISQUE).
Les deux affirmations sont vraies separement, et personne ne reliait le chiffre
publie au comportement livre : au seuil affiche le rappel tombe a ~0,35, et le
palier RISQUE n'est JAMAIS atteint sur ce benchmark.

Ces tests defendent le chiffre publie ET le point de fonctionnement livre, pour
qu'aucun des deux ne derive en silence.
"""
import csv
import functools

from scamshield.scorer import score_text

DISPLAY_DOUBT = 25   # app/main.py::verdict et extension/scorer.js
DISPLAY_RISKY = 60


@functools.lru_cache(maxsize=1)
def _scores():
    xs, ys = [], []
    with open("data/dataset.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            t = row["text"].replace("\n", " ").strip()
            if not t:
                continue
            s, _, _ = score_text(t)
            xs.append(s)
            ys.append(int(row["label"]))
    return tuple(xs), tuple(ys)


def _pr(seuil):
    xs, ys = _scores()
    tp = sum(1 for s, l in zip(xs, ys) if s >= seuil and l == 1)
    fp = sum(1 for s, l in zip(xs, ys) if s >= seuil and l == 0)
    fn = sum(1 for s, l in zip(xs, ys) if s < seuil and l == 1)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r


def _f1(seuil):
    p, r = _pr(seuil)
    return 2 * p * r / (p + r) if p + r else 0.0


def test_le_best_F1_publie_est_reproductible():
    """Le README annonce 0.824 : un chiffre publie doit etre defendu par un test."""
    best = max(_f1(s) for s in range(0, 101))
    assert best >= 0.80, f"Best F1 mesure {best:.3f} < 0.80 : le README annonce 0.824"


def test_les_seuils_affiches_ne_font_aucun_faux_positif():
    """La promesse « favors precision » du README, au seuil REELLEMENT affiche."""
    p, _ = _pr(DISPLAY_DOUBT)
    assert p == 1.0, f"precision {p:.2f} au seuil {DISPLAY_DOUBT} : la promesse du README tombe"


def test_le_rappel_au_seuil_affiche_est_connu_et_ne_doit_pas_baisser():
    """Le chiffre que le README ne donnait pas : ~0,35 de rappel a l'affichage.

    Il est bas par CHOIX (precision d'abord). Ce test empeche qu'il baisse encore
    sans que personne ne le voie."""
    _, r = _pr(DISPLAY_DOUBT)
    assert r >= 0.30, f"rappel {r:.2f} au seuil affiche : degradation silencieuse"


def test_le_palier_RISQUE_est_atteignable_ou_le_test_le_dit():
    """Sur ce benchmark, AUCUN message n'atteint 60 : le palier haut est mort.

    Ce test acte la mesure. Le jour ou le seuil ou la ponderation change, il
    faudra le mettre a jour SCIEMMENT — c'est exactement le but."""
    xs, ys = _scores()
    atteints = sum(1 for s, l in zip(xs, ys) if s >= DISPLAY_RISKY and l == 1)
    assert atteints == 0, (
        f"{atteints} arnaque(s) atteignent maintenant RISQUE — mettre a jour ce test "
        "et le README, la calibration a change")
