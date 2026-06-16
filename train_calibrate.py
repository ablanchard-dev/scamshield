
import argparse, os, json, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import roc_auc_score, brier_score_loss, log_loss, precision_recall_fscore_support
from joblib import dump

def expected_calibration_error(y_true, p, n_bins=15):
    # Standard ECE: bin by confidence in the *predicted* class, then compare
    # average confidence to average accuracy per bin. (The previous version
    # compared raw P(class=1) to accuracy, which blows up on imbalanced data.)
    y_true = np.asarray(y_true, dtype=int)
    p = np.asarray(p, dtype=float)
    pred = (p >= 0.5).astype(int)
    conf = np.where(pred == 1, p, 1.0 - p)
    correct = (pred == y_true).astype(float)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(conf, bins) - 1, 0, n_bins - 1)
    ece = 0.0
    for b in range(n_bins):
        mask = idx == b
        if not np.any(mask):
            continue
        ece += mask.mean() * abs(correct[mask].mean() - conf[mask].mean())
    return float(ece)

def read_table(path, encoding=None):
    # sep=None + engine='python' permet d'inférer ',' vs ';'
    return pd.read_csv(path, sep=None, engine="python", encoding=encoding)

def map_labels(y_series, pos_label=None):
    y_raw = y_series.copy()
    if y_raw.dtype.kind in "if":
        return (y_raw.astype(float) > 0.5).astype(int).values, {"pos_label": "numeric>0.5"}
    classes, y_idx = np.unique(y_raw, return_inverse=True)
    # si on a un nom de classe positive connu
    if pos_label is not None and pos_label in classes:
        pos = np.where(classes == pos_label)[0][0]
        return (y_idx == pos).astype(int), {"classes": list(map(str, classes)), "pos_label": pos_label}
    # heuristique : si 'scam' existe on la prend
    if "scam" in classes:
        pos = np.where(classes == "scam")[0][0]
        return (y_idx == pos).astype(int), {"classes": list(map(str, classes)), "pos_label": "scam"}
    # sinon on met la dernière classe en positive (documente dans meta)
    return (y_idx == y_idx.max()).astype(int), {"classes": list(map(str, classes)), "pos_label": str(classes[-1])}

def build_vectorizer(analyzer, min_df, max_ngram, char_min=3, char_max=5, max_features=None):
    if analyzer == "word":
        return TfidfVectorizer(min_df=min_df, ngram_range=(1, max_ngram),
                               max_features=max_features, lowercase=True)
    if analyzer == "char":
        return TfidfVectorizer(analyzer="char", ngram_range=(char_min, char_max),
                               max_features=max_features, lowercase=True)
    # both = union char + word
    return FeatureUnion([
        ("word", TfidfVectorizer(min_df=min_df, ngram_range=(1, max_ngram),
                                 max_features=max_features, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(char_min, char_max),
                                 max_features=max_features, lowercase=True)),
    ])

def main(a):
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)

    df = read_table(a.data, encoding=a.encoding)
    if a.text_col not in df.columns or a.label_col not in df.columns:
        raise ValueError(f"Colonnes introuvables. Dispo={list(df.columns)}")

    X = df[a.text_col].astype(str).values
    y, meta_label = map_labels(df[a.label_col], pos_label=a.pos_label)

    X_tr, X_tmp, y_tr, y_tmp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42)
    X_val, X_te,  y_val, y_te = train_test_split(
        X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42)

    vec = build_vectorizer(a.analyzer, a.min_df, a.max_ngram,
                           char_min=a.char_min, char_max=a.char_max,
                           max_features=a.max_features)

    base = Pipeline([
        ("vec", vec),
        ("clf", LogisticRegression(
            max_iter=2000,
            solver="liblinear",
            class_weight=(None if a.class_weight == "none" else "balanced")
        ))
    ])
    base.fit(X_tr, y_tr)

    cal = CalibratedClassifierCV(FrozenEstimator(base), method=a.method)
    cal.fit(X_val, y_val)

    p = cal.predict_proba(X_te)[:, 1]
    auc = roc_auc_score(y_te, p)
    brier = brier_score_loss(y_te, p)
    ece = expected_calibration_error(y_te, p, n_bins=15)
    ll = log_loss(y_te, np.vstack([1-p, p]).T)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_te, (p >= 0.5).astype(int), average="binary", zero_division=0)

    print(f"AUC    : {auc:.4f}")
    print(f"F1     : {f1:.4f}  (precision {prec:.4f}, recall {rec:.4f})")
    print(f"Brier  : {brier:.4f}")
    print(f"ECE    : {ece:.4f}")
    print(f"LogLoss: {ll:.4f}")

    dump(cal, a.out)
    meta = {
        "data": a.data,
        "text_col": a.text_col,
        "label_col": a.label_col,
        "method": a.method,
        "analyzer": a.analyzer,
        "min_df": a.min_df,
        "max_ngram": a.max_ngram,
        "char_min": a.char_min,
        "char_max": a.char_max,
        "max_features": a.max_features,
        "class_weight": a.class_weight,
        "label_mapping": meta_label,
        "metrics": {"auc": auc, "f1": f1, "precision": prec, "recall": rec,
                    "brier": brier, "ece": ece, "logloss": ll}
    }
    with open(os.path.splitext(a.out)[0] + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print("[OK] Calibrated model saved ->", a.out)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="chemin CSV/TSV")
    ap.add_argument("--text-col", required=True)
    ap.add_argument("--label-col", required=True)
    ap.add_argument("--out", default="models/scamshield_calibrated.joblib")

    ap.add_argument("--method", choices=["sigmoid","isotonic"], default="sigmoid")
    ap.add_argument("--analyzer", choices=["word","char","both"], default="both")
    ap.add_argument("--min-df", type=int, default=2)
    ap.add_argument("--max-ngram", type=int, default=2)
    ap.add_argument("--char-min", type=int, default=3)
    ap.add_argument("--char-max", type=int, default=5)
    ap.add_argument("--max-features", type=int, default=None)

    ap.add_argument("--class-weight", choices=["none","balanced"], default="balanced")
    ap.add_argument("--pos-label", default=None, help="nom explicite de la classe positive (ex: scam)")
    ap.add_argument("--encoding", default=None, help="ex: utf-8, latin-1 si besoin")
    args = ap.parse_args()
    main(args)
