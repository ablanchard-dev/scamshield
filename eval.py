"""Evaluate the explainable rule-based scorer on the French benchmark.

The rule engine (scamshield/scorer.py) is the product layer; this measures how
well its 0-100 score separates scam from legit on data/dataset.csv, and prints
precision/recall/F1 across a few thresholds so the trade-off is explicit.

Run:  python eval.py            # uses data/dataset.csv
"""

import argparse
import csv

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score

from scamshield.scorer import score_text


def load(path):
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    texts = [r["text"] for r in rows]
    labels = [int(float(r["label"])) for r in rows]
    return texts, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--thresholds", nargs="+", type=float, default=[5, 10, 15, 20, 25])
    args = ap.parse_args()

    texts, y = load(args.data)
    scores = [score_text(t)[0] for t in texts]
    p = [s / 100.0 for s in scores]  # pseudo-probability for ranking metrics

    auc = roc_auc_score(y, p)
    print(f"Rule scorer on {args.data}  ({len(y)} messages, scam={sum(y)})")
    print(f"ROC-AUC (score as ranking): {auc:.4f}\n")
    print(f"{'thr':>5} {'precision':>10} {'recall':>8} {'F1':>6}   TP  FP  TN  FN")
    for t in args.thresholds:
        pred = [1 if s >= t else 0 for s in scores]
        prec, rec, f1, _ = precision_recall_fscore_support(
            y, pred, average="binary", zero_division=0
        )
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        print(f"{t:>5.0f} {prec:>10.3f} {rec:>8.3f} {f1:>6.3f}  {tp:>3} {fp:>3} {tn:>3} {fn:>3}")


if __name__ == "__main__":
    main()
