#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seed_data.py — Seeder évolué pour SCAMShield
- Merge/reset sans doublons
- Sort/normalisation
- Exporte TXT (legacy), JSON et CSV
- Stats rapides
"""

from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path

# ---------- Données par défaut (tu peux allonger) ----------
DEFAULT_DATA = {
    "sample_texts": [
        "Votre compte bancaire a été suspendu. Cliquez ici pour le réactiver.",
        "Félicitations ! Vous avez gagné un iPhone 15, répondez vite pour le recevoir.",
        "Message de votre banque : connexion suspecte détectée.",
        "Rappel : votre facture EDF est impayée, réglez immédiatement.",
        "Votre colis est retenu. Payez 2,99€ pour la livraison.",
        "Mise à jour de sécurité obligatoire, connectez-vous à votre espace.",
        "Alerte : connexion depuis un nouvel appareil. Validez votre identité.",
        "Votre TVA n’a pas été réglée, pénalité immédiate si inaction.",
    ],
    "trusted_senders": [
        "support@paypal.com",
        "service-client@amazon.fr",
        "contact@edf.fr",
        "noreply@impots.gouv.fr",
        "help@airfrance.fr",
    ],
    "malicious_senders": [
        "secure-paypal@fraud.com",
        "support-client@amaz0n.net",
        "edf-facture@dangerousmail.ru",
        "update@impots-g0uv.fr",
        "delivery@fakecolis.cn",
        "appleid@support-apple-security.com",
        "sfr@facturation-suspendue.net",
    ],
    "blocked_domains": [
        "fraud.com",
        "phishing-mail.ru",
        "fakecolis.cn",
        "paypal-verif.net",
        "secure-amazon-login.org",
        "impots-g0uv.fr",
        "amaz0n.net",
    ],
    "denylist_phrases": [
        "cliquez ici pour valider",
        "votre compte sera suspendu",
        "paiement non reçu",
        "mise à jour urgente",
        "vérifiez votre identité",
        "pénalité immédiate",
        "virement instantané requis",
    ],
    "allowlist_phrases": [
        "merci de votre confiance",
        "votre commande a été expédiée",
        "facture disponible dans votre espace client",
        "cet email est purement informatif",
    ],
    "phone_scam_patterns": [
        "+33 9 70 00 00 00",
        "+33 7 56 12 34 56",
        "0899 12 34 56",
        "0810 00 00 00",
        "+44 20 7946 0958",
    ],
    "suspicious_attachments": [".exe", ".scr", ".bat", ".vbs", ".js", ".cmd", ".lnk", ".hta", ".ps1"],
    "suspicious_tlds": [".ru", ".cn", ".tk", ".ml", ".ga", ".top", ".xyz", ".icu"],
}

# ---------- Helpers ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def normalize_line(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())

def valid_email(s: str) -> bool:
    return bool(EMAIL_RE.match(s))

def load_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [normalize_line(x) for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if normalize_line(x)]

def save_txt(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def unique_sorted(seq: list[str]) -> list[str]:
    return sorted(set(normalize_line(x) for x in seq if normalize_line(x)))

# ---------- Core ----------
def seed_data(base_dir: Path, mode: str = "merge", verbose: bool = True) -> dict:
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # mapping nom logique -> nom de fichier .txt legacy
    file_map = {
        "sample_texts": "sample_texts.txt",
        "trusted_senders": "trusted_senders.txt",
        "malicious_senders": "malicious_senders.txt",
        "blocked_domains": "blocked_domains.txt",
        "denylist_phrases": "denylist_phrases.txt",
        "allowlist_phrases": "allowlist_phrases.txt",
        "phone_scam_patterns": "phone_scam_patterns.txt",
        "suspicious_attachments": "suspicious_attachments.txt",
        "suspicious_tlds": "suspicious_tlds.txt",
    }

    result: dict[str, list[str]] = {}
    for key, fname in file_map.items():
        target = data_dir / fname
        default_vals = DEFAULT_DATA.get(key, [])

        if mode == "reset":
            merged = unique_sorted(default_vals)
        else:
            existing = load_lines(target)
            merged = unique_sorted(existing + default_vals)

        # Petites règles de qualité
        if key.endswith("senders"):
            # garder seulement les emails valides
            merged = [x for x in merged if valid_email(x)]
        if key == "blocked_domains":
            merged = [x.lower() for x in merged]
        if key == "suspicious_tlds":
            # normaliser avec un point de tête
            merged = [x.lower() if x.startswith(".") else f".{x.lower()}" for x in merged]

        save_txt(target, merged)
        result[key] = merged
        if verbose:
            print(f"[OK] {fname:28} → {len(merged):4d} entrées")

    # Exporte JSON consolidé
    json_path = data_dir / "seed_bundle.json"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if verbose:
        print(f"[OK] seed_bundle.json             → {sum(len(v) for v in result.values()):4d} items totaux")

    # Exporte CSV “flat” (clé;valeur)
    csv_path = data_dir / "seed_bundle.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["list_key", "value"])
        for k, vals in result.items():
            for v in vals:
                w.writerow([k, v])
    if verbose:
        print(f"[OK] seed_bundle.csv              → lignes: {sum(len(v) for v in result.values())}")

    # Stats utiles
    stats = {
        "emails_total": len(result.get("trusted_senders", [])) + len(result.get("malicious_senders", [])),
        "domains_blocked": len(set(result.get("blocked_domains", []))),
        "tlds_suspicious": len(set(result.get("suspicious_tlds", []))),
        "phrases_deny": len(result.get("denylist_phrases", [])),
        "phrases_allow": len(result.get("allowlist_phrases", [])),
        "attachments": len(result.get("suspicious_attachments", [])),
    }
    if verbose:
        print("\nRésumé :")
        for k, v in stats.items():
            print(f" - {k.replace('_', ' ').title():22}: {v}")

    return result

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Seeder évolué pour SCAMShield")
    parser.add_argument(
        "--dir", type=str, default=".", help="Chemin du dossier projet (par défaut: .)"
    )
    parser.add_argument(
        "--mode", choices=["merge", "reset"], default="merge",
        help="merge = fusionne avec l'existant / reset = réécrit avec les défauts"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Moins de logs"
    )
    args = parser.parse_args()

    base_dir = Path(args.dir).resolve()
    seed_data(base_dir, mode=args.mode, verbose=not args.quiet)

if __name__ == "__main__":
    main()
