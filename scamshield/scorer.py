# scamshield/scorer.py # — V1.4

import re, json, os
from typing import Tuple, List, Dict, Optional
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

def _load_list(relpath: str) -> List[str]:
    p = os.path.join(DATA_DIR, relpath)
    if not os.path.exists(p):
        return []
    with open(p, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

def _load_json(relpath: str) -> Dict[str, float]:
    p = os.path.join(DATA_DIR, relpath)
    if not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

TRUSTED_SENDERS   = _load_list("trusted_senders.txt")
MALICIOUS_SENDERS = list({* _load_list("malicious_senders.txt"),
                          * _load_list("known_phishing_senders.txt")})
BLOCKED_DOMAINS   = list({* _load_list("blocked_domains.txt"),
                          * _load_list("bad_domains.txt")})

DENYLIST_PHRASES     = _load_list("denylist_phrases.txt")
ALLOWLIST_PHRASES    = _load_list("allowlist_phrases.txt")
SUSPICIOUS_ATTACH    = _load_list("suspicious_attachments.txt")
SUSPICIOUS_TLDS      = _load_list("suspicious_tlds.txt")
PHONE_PATTERNS       = _load_list("phone_scam_patterns.txt")
URL_REPUTATION       = _load_json("url_reputation.json")

WEIGHTS = {
    "malicious_sender"     : 25.0,
    "trusted_sender"       : -10.0,
    "blocked_domain"       : 22.0,
    "suspicious_tld"       : 8.0,
    "deny_phrase"          : 5.0,
    "allow_phrase"         : -4.0,
    "shortener"            : 8.0,
    "urgency"              : 6.0,
    "time_pressure"        : 6.0,
    "credential_request"   : 10.0,
    "financial_request"    : 12.0,
    "iban_detected"        : 10.0,
    "crypto_address"       : 12.0,
    "attachment_risky"     : 8.0,
    "phone_scam"           : 8.0,
    "url_reputation"       : 25.0,  # *max* if reputation=1.0
}

URL_REGEX = re.compile(r"(https?://[^\s)]+)", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+", re.IGNORECASE)
# IBAN générique + focus FR (simple)
IBAN_REGEX = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b")
FR_IBAN_HINT = re.compile(r"\bFR\d{2}\s?\d{5}\s?\d{5}\s?[A-Z0-9]{11}\s?\d{2}\b", re.IGNORECASE)
# Bitcoin (classique)
BTC_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

SHORTENERS = {"bit.ly","tiny.cc","t.co","short.ly","goo.gl","is.gd","cutt.ly","ow.ly"}

def _extract_sender(text: str) -> Optional[str]:
    # Cherche une ligne “De: xxx” sinon 1er email dans le texte
    for line in text.splitlines():
        if line.lower().startswith(("de: ", "from: ")):
            m = EMAIL_REGEX.search(line)
            if m: return m.group(0).lower()
    m = EMAIL_REGEX.search(text)
    return m.group(0).lower() if m else None

def _domain_of(email_or_url: str) -> Optional[str]:
    if "@" in email_or_url:
        return email_or_url.split("@")[-1].lower()
    try:
        host = urlparse(email_or_url).netloc.lower()
        return host.split(":")[0]
    except Exception:
        return None

def _extract_urls(text: str) -> List[str]:
    return [m.group(1) for m in URL_REGEX.finditer(text)]

def _extract_attachments(text: str) -> List[str]:
    # naïf : trouve des mots avec extension connue
    found = []
    for ext in SUSPICIOUS_ATTACH:
        pattern = re.compile(rf"\b[\w\-]+\{re.escape(ext)}\b", re.IGNORECASE)
        found += pattern.findall(text)
    return list(set(found))

def _count_occurrences(text: str, phrases: List[str]) -> int:
    t = text.lower()
    return sum(1 for p in phrases if p in t)

def _has_urgency(text: str) -> bool:
    t = text.lower()
    keys = ["urgent", "immédiat", "immediat", "48h", "24h", "sans délai", "dernier avertissement", "compte suspendu"]
    return any(k in t for k in keys)

def _has_time_pressure(text: str) -> bool:
    t = text.lower()
    keys = ["aujourd'hui", "avant minuit", "dans l'heure", "sous 24h", "immédiatement"]
    return any(k in t for k in keys)

def _asks_credentials(text: str) -> bool:
    t = text.lower()
    keys = ["mot de passe", "password", "code sms", "code de vérification", "identité", "pièce d'identité"]
    return any(k in t for k in keys)

def _asks_money(text: str) -> bool:
    t = text.lower()
    keys = ["paiement", "virement", "remboursement", "facture", "iban", "crypto", "bitcoin", "ethereum"]
    return any(k in t for k in keys)

def _phone_scam(text: str) -> bool:
    t = text.lower()
    if any(p in t for p in PHONE_PATTERNS):
        return True
    # Numéro FR simple
    return bool(re.search(r"\b0[1-9](?:[\s\.-]?\d{2}){4}\b", t))

def _is_suspicious_tld(domain: str) -> bool:
    # check extension .co .xyz etc.
    if not domain or "." not in domain:
        return False
    tld = "." + domain.split(".")[-1]
    return tld in SUSPICIOUS_TLDS

def _url_reputation_boost(domain: str) -> float:
    # renvoie un facteur [0..1], qu’on multiplie par WEIGHTS["url_reputation"]
    rep = URL_REPUTATION.get(domain, 0.0)
    return max(0.0, min(1.0, float(rep)))

def score_text(text: str) -> Tuple[float, List[str]]:
    """
    Analyse le contenu (texte/email). Retourne (score, raisons[])
    Score ~ [0..100+] (plus haut = plus risqué)
    """
    score = 0.0
    reasons: List[str] = []
    t = text or ""
    tl = t.lower()

    # 1) Expéditeur
    sender = _extract_sender(t)
    if sender:
        sender_l = sender.lower()
        if sender_l in MALICIOUS_SENDERS:
            score += WEIGHTS["malicious_sender"]
            reasons.append(f"Expéditeur listé comme malveillant : {sender}")
        if sender_l in TRUSTED_SENDERS:
            score += WEIGHTS["trusted_sender"]
            reasons.append(f"Expéditeur listé comme fiable : {sender}")

        dom = _domain_of(sender_l)
        if dom:
            if dom in BLOCKED_DOMAINS:
                score += WEIGHTS["blocked_domain"]
                reasons.append(f"Domaine expéditeur bloqué : {dom}")
            if _is_suspicious_tld(dom):
                score += WEIGHTS["suspicious_tld"]
                reasons.append(f"TLD suspicieux : .{dom.split('.')[-1]}")

    # 2) URLs
    urls = _extract_urls(t)
    for u in urls:
        dom = _domain_of(u)
        if not dom: 
            continue
        if dom in BLOCKED_DOMAINS:
            score += WEIGHTS["blocked_domain"]
            reasons.append(f"Lien vers domaine bloqué : {dom}")
        host_parts = dom.split(".")
        base = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else dom
        if base in SHORTENERS or dom in SHORTENERS:
            score += WEIGHTS["shortener"]
            reasons.append(f"Raccourcisseur d’URL détecté : {dom}")
        if _is_suspicious_tld(dom):
            score += WEIGHTS["suspicious_tld"]
            reasons.append(f"TLD suspicieux sur lien : .{dom.split('.')[-1]}")
        # réputation
        rep = _url_reputation_boost(base)
        if rep > 0:
            add = rep * WEIGHTS["url_reputation"]
            score += add
            reasons.append(f"Réputation URL mauvaise ({base}) : +{int(add)}")

    # 3) Phrases à risque / rassurantes
    deny_hits  = _count_occurrences(t, DENYLIST_PHRASES)
    allow_hits = _count_occurrences(t, ALLOWLIST_PHRASES)
    if deny_hits > 0:
        add = deny_hits * WEIGHTS["deny_phrase"]
        score += add
        reasons.append(f"Expressions risquées détectées x{deny_hits} : +{int(add)}")
    if allow_hits > 0:
        add = allow_hits * WEIGHTS["allow_phrase"]
        score += add
        reasons.append(f"Indices rassurants x{allow_hits} : {int(add)}")

    # 4) Heuristiques sociales/risques
    if _has_urgency(t): 
        score += WEIGHTS["urgency"]; reasons.append("Langage d’urgence")
    if _has_time_pressure(t): 
        score += WEIGHTS["time_pressure"]; reasons.append("Pression temporelle")
    if _asks_credentials(t):
        score += WEIGHTS["credential_request"]; reasons.append("Demande d’identifiants")
    if _asks_money(t):
        score += WEIGHTS["financial_request"]; reasons.append("Demande financière")

    # 5) IBAN & crypto
    if FR_IBAN_HINT.search(t) or IBAN_REGEX.search(t):
        score += WEIGHTS["iban_detected"]; reasons.append("IBAN détecté")
    if BTC_REGEX.search(t):
        score += WEIGHTS["crypto_address"]; reasons.append("Adresse crypto détectée")

    # 6) Pièces jointes à risque (détection naïve)
    atts = _extract_attachments(t)
    if atts:
        add = WEIGHTS["attachment_risky"]
        score += add
        reasons.append(f"Pièce jointe potentiellement dangereuse : {', '.join(atts)} (+{int(add)})")

    # 7) Phone scam
    if _phone_scam(t):
        score += WEIGHTS["phone_scam"]; reasons.append("Indication d’arnaque téléphonique")

    # Clamp minimal 0
    score = max(0.0, score)
    # Normalisation douce (cap à 100, mais peut dépasser si gros cumul)
    score_normalized = min(score, 100.0)
    return score_normalized, reasons

def score_url(url: str) -> Tuple[float, List[str]]:
    """Heuristique rapide si on ne donne qu’une URL (collée dans l’UI)."""
    score = 0.0
    reasons: List[str] = []
    dom = _domain_of(url)
    if dom:
        base = ".".join(dom.split(".")[-2:]) if "." in dom else dom
        if dom in BLOCKED_DOMAINS or base in BLOCKED_DOMAINS:
            score += WEIGHTS["blocked_domain"]; reasons.append(f"Domaine bloqué : {dom}")
        if base in SHORTENERS or dom in SHORTENERS:
            score += WEIGHTS["shortener"]; reasons.append(f"Raccourcisseur d’URL : {dom}")
        if _is_suspicious_tld(dom):
            score += WEIGHTS["suspicious_tld"]; reasons.append(f"TLD suspicieux : .{dom.split('.')[-1]}")
        rep = _url_reputation_boost(base)
        if rep > 0:
            add = rep * WEIGHTS["url_reputation"]
            score += add
            reasons.append(f"Réputation URL mauvaise ({base}) : +{int(add)}")
    return min(score, 100.0), reasons

def explain_reasons(score: float, reasons: List[str]) -> str:
    badge = "🟢 SÛR" if score < 25 else "🟠 DOUTEUX" if score < 60 else "🔴 RISQUÉ"
    parts = [f"**Score** : **{int(score)}/100** — {badge}"]
    if reasons:
        parts.append("**Raisons principales :**")
        for r in reasons:
            parts.append(f"- {r}")
    else:
        parts.append("_Pas d’indicateurs de risque notables détectés._")
    parts.append("\n**Conseil** : ne cliquez jamais sur un lien douteux et ne partagez pas vos identifiants par email/SMS.")
    return "\n".join(parts)  

if __name__ == "__main__":
    import argparse, sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description="SCAMShield scorer CLI")
    parser.add_argument("--demo", action="store_true", help="Afficher un aperçu des listes et quitter")
    parser.add_argument("--text", type=str, help="Texte/email brut à évaluer")
    parser.add_argument("--url", type=str, help="URL seule à évaluer")
    args = parser.parse_args()

    if args.demo:
        print("[SCAMSHIELD] Demo mode ON")
        base = Path(__file__).resolve().parents[1] / "data"
        def head(p, n=5):
            return [l.strip() for l in (base/p).read_text(encoding="utf-8").splitlines()[:n] if l.strip()]
        print(" - blocked_domains.txt (5):", head("blocked_domains.txt"))
        print(" - bad_domains.txt (5):", head("bad_domains.txt") if (base/"bad_domains.txt").exists() else "(absent)")
        print(" - malicious_senders.txt (5):", head("malicious_senders.txt"))
        print(" - known_phishing_senders.txt (5):", head("known_phishing_senders.txt") if (base/"known_phishing_senders.txt").exists() else "(absent)")
        print(" - suspicious_attachments.txt (5):", head("suspicious_attachments.txt"))
        sys.exit(0)

    if args.url:
        s, reasons = score_url(args.url)
        print(explain_reasons(s, reasons))
        sys.exit(0)

    if args.text:
        s, reasons = score_text(args.text)
        print(explain_reasons(s, reasons))
        sys.exit(0)

    parser.print_help()

