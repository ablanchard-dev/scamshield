import argparse, numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_fscore_support, confusion_matrix

p = argparse.ArgumentParser()
p.add_argument("--scored", required=True)
p.add_argument("--label-col", default="label")
p.add_argument("--proba-col", default="proba")
p.add_argument("--thresholds", nargs="+", type=float, default=[0.5])
args = p.parse_args()

df = pd.read_csv(args.scored)
y = df[args.label_col].astype(int).values
p_hat = df[args.proba_col].values

print("Rows:", len(df))
print("Label counts:", dict(zip(*np.unique(y, return_counts=True))))
print("Mean proba by label:", df.groupby(args.label_col)[args.proba_col].mean().to_dict())

try:
    auc = roc_auc_score(y, p_hat)
    ap  = average_precision_score(y, p_hat)
    print(f"ROC-AUC: {auc:.4f} | PR-AUC: {ap:.4f}")
except Exception as e:
    print("AUC/AP skipped:", e)

for t in args.thresholds:
    y_pred = (p_hat >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, y_pred, labels=[0,1]).ravel()
    prec, rec, f1, _ = precision_recall_fscore_support(y, y_pred, average="binary", zero_division=0)
    print(f"\n--- Threshold {t:.2f} ---")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={prec:.3f} Recall={rec:.3f} F1={f1:.3f}")
