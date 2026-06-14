"""Download the public SMS Spam Collection for the ML baseline.

Real, labeled SMS messages (Almeida, Gómez Hidalgo & Yamakami, 2011 — UCI SMS
Spam Collection). Using a real corpus instead of synthetic data is what makes
the reported metrics trustworthy.

Writes data/sms_spam.csv with columns: text,label  (1 = spam, 0 = ham/legit).
"""

import csv
import os
import urllib.request

URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
OUT = os.path.join(os.path.dirname(__file__), "data", "sms_spam.csv")


def main():
    with urllib.request.urlopen(URL, timeout=30) as resp:
        raw = resp.read().decode("utf-8")

    rows = []
    for line in raw.splitlines():
        if "\t" not in line:
            continue
        label, text = line.split("\t", 1)
        rows.append((text.strip(), 1 if label.strip().lower() == "spam" else 0))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)

    spam = sum(y for _, y in rows)
    print(f"Wrote {len(rows)} rows to {OUT} (spam={spam}, ham={len(rows) - spam})")


if __name__ == "__main__":
    main()
