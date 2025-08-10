# -*- coding: utf-8 -*-
"""
Usage rapide (exemples) :
  - Proba de la classe 1 (ex. SCAM) sans inversion :
      python predict_csv.py --model models\scamshield_calibrated.joblib ^
        --in data\norm_scam1.csv --text-col text ^
        --out data\norm_scam1_scored.csv --threshold 0.6 --pos 1

  - Proba de la classe 0 mais inversée (équivalent "proba classe 1") :
      python predict_csv.py --model models\scamshield_calibrated.joblib ^
        --in data\norm_scam1.csv --text-col text ^
        --out data\norm_scam1_scored.csv --threshold 0.6 --pos 0 --invert
"""
import argparse
import numpy as np
import pandas as pd
from joblib import load


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="Chemin du .joblib")
    ap.add_argument("--in", dest="inp", required=True, help="CSV d'entrée")
    ap.add_argument("--text-col", default="text", help="Nom de la colonne texte")
    ap.add_argument("--out", required=True, help="CSV de sortie")
    ap.add_argument("--threshold", type=float, default=0.5, help="Seuil de décision (0..1)")
    ap.add_argument(
        "--pos", type=int, choices=[0, 1], default=1,
        help="Classe dont on veut la probabilité (0 ou 1). Par défaut: 1."
    )
    ap.add_argument(
        "--invert", action="store_true",
        help="Si défini, remplace proba par (1 - proba) après calcul."
    )
    args = ap.parse_args()

    # validations simples
    if not (0.0 <= args.threshold <= 1.0):
        raise SystemExit("--threshold doit être entre 0 et 1")

    df = pd.read_csv(args.inp)
    if args.text_col not in df.columns:
        raise SystemExit(f"colonne texte '{args.text_col}' absente. Colonnes: {list(df.columns)}")

    # Texte propre : NaN -> "", tout en str
    X = df[args.text_col].fillna("").astype(str)

    clf = load(args.model)
    if not hasattr(clf, "predict_proba"):
        raise SystemExit("Le modèle chargé n'a pas de predict_proba")

    probs = clf.predict_proba(X)

    # Récup classes (si dispo)
    classes = getattr(clf, "classes_", None)
    if classes is None:
        # fallback raisonnable
        classes = np.arange(probs.shape[1]) if probs.ndim == 2 else np.array([1])

    # Choix de la colonne proba selon --pos
    if probs.ndim == 1:
        # certains estimateurs renvoient (n_samples,) déjà pour la classe positive
        p = probs
        used_idx = None
    else:
        if args.pos in classes:
            used_idx = int(np.where(classes == args.pos)[0][0])
        else:
            # fallback si classes inattendues
            used_idx = 1 if (args.pos == 1 and probs.shape[1] > 1) else 0
        p = probs[:, used_idx]

    # inversion optionnelle
    if args.invert:
        p = 1.0 - p

    # clamp de sûreté (rarement utile mais safe)
    p = np.clip(p, 0.0, 1.0)

    df["proba"] = p
    df["pred"] = (p >= args.threshold).astype(int)

    df.to_csv(args.out, index=False)
    print(f"OK -> {args.out} | rows: {len(df)} | threshold: {args.threshold}")
    if "label" in df.columns:
        try:
            means = df.groupby("label", dropna=False)["proba"].mean().to_dict()
        except Exception:
            means = "n/a"
        print("Mean proba by label:", means)
        try:
            y = df["label"].astype(int).to_numpy()
            uniq, cnt = np.unique(y, return_counts=True)
            print("Label counts:", dict(zip(uniq.tolist(), cnt.tolist())))
        except Exception:
            pass

    classes_list = classes.tolist() if hasattr(classes, "tolist") else list(classes)
    print(f"Model classes_: {classes_list} | used column index: {used_idx} | pos: {args.pos} | invert: {args.invert}")


if __name__ == "__main__":
    main()
