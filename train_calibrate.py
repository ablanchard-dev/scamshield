import argparse, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, brier_score_loss
from joblib import dump

def main(a):
    df = pd.read_csv(a.data)
    X = df[a.text_col].astype(str).values
    y_raw = df[a.label_col]

    # Map labels -> 0/1
    if y_raw.dtype.kind in "if":
        y = (y_raw.astype(float) > 0.5).astype(int).values
    else:
        classes, y_idx = np.unique(y_raw, return_inverse=True)
        # si 'scam' existe, on la met en classe positive
        if 'scam' in classes:
            pos = np.where(classes=='scam')[0][0]
            y = (y_idx == pos).astype(int)
        else:
            y = (y_idx == y_idx.max()).astype(int)  # dernière classe = positive

    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    X_val, X_te,  y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42)

    base = Pipeline([
        ("tfidf", TfidfVectorizer(min_df=a.min_df, ngram_range=(1, a.max_ngram))),
        ("clf",   LogisticRegression(max_iter=2000, solver="liblinear"))
    ])
    base.fit(X_tr, y_tr)  # modèle "préfité"

    cal = CalibratedClassifierCV(estimator=base, method=a.method, cv="prefit")
    cal.fit(X_val, y_val)  # calibration SANS fuite

    p = cal.predict_proba(X_te)[:, 1]
    print("AUC :", round(roc_auc_score(y_te, p), 4))
    print("Brier:", round(brier_score_loss(y_te, p), 4))

    dump(cal, a.out)
    print("✅ Modèle calibré sauvegardé ->", a.out)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV avec colonnes texte/label")
    ap.add_argument("--text-col", required=True)
    ap.add_argument("--label-col", required=True)
    ap.add_argument("--out", default="models/scamshield_calibrated.joblib")
    ap.add_argument("--method", choices=["sigmoid","isotonic"], default="sigmoid")
    ap.add_argument("--min-df", type=int, default=2)
    ap.add_argument("--max-ngram", type=int, default=2)
    args = ap.parse_args()
    main(args)
