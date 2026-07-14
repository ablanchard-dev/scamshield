"""Explainable rule-based scam/phishing scorer.

Sums weighted, transparent signals (risky/reassuring phrasings, domains, senders,
urgency, credential/financial requests, IBAN/crypto, punycode, QR codes, optional
media flags) and returns a 0-100 score with the list of reasons behind it.
"""

import re, json, os, unicodedata
from typing import Tuple, List, Dict, Optional, Any
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
KNOWN_BRANDS         = _load_list("brands.txt") or [
    # fallback minimal si data/brands.txt absent
    "microsoft","apple","paypal","amazon","google","facebook","instagram","netflix",
    "orange","sfr","free","la poste","chronopost","dhl","ups","urssaf","impots",
    "ameli","caf","edf","engie","banque","credit","societe generale","lcl","axa"
]

WEIGHTS = {
    "malicious_sender"      : 25.0,
    "trusted_sender"        : -10.0,
    "blocked_domain"        : 22.0,
    "suspicious_tld"        : 8.0,
    "deny_phrase"           : 5.0,
    "allow_phrase"          : -4.0,
    "shortener"             : 8.0,
    "urgency"               : 6.0,
    "time_pressure"         : 6.0,
    "credential_request"    : 10.0,
    "financial_request"     : 12.0,
    "iban_detected"         : 10.0,
    "crypto_address"        : 12.0,
    "attachment_risky"      : 8.0,
    "phone_scam"            : 8.0,
    "url_reputation"        : 25.0,  # *max* if reputation=1.0
    # Nouveaux signaux
    "reply_to_mismatch"     : 10.0,
    "punycode_domain"       : 9.0,
    "mixed_script_domain"   : 6.0,
    "qr_request"            : 6.0,
    "amount_present"        : 5.0,
    "zero_width"            : 4.0,
    # Synergies (bonus de risque si combos)
    "synergy_urgent_cred"   : 6.0,
    "synergy_money_time"    : 6.0,
    "brand_mismatch"        : 10.0,
    # Deepfake (nouveaux)
    "deepfake_audio"        : 20.0,
    "deepfake_video"        : 20.0,
    "voiceprint_mismatch"   : 22.0,
}

URL_REGEX   = re.compile(r"(https?://[^\s)<>]+)", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+", re.IGNORECASE)
# IBAN générique + focus FR
IBAN_REGEX   = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b")
FR_IBAN_HINT = re.compile(r"\bFR\d{2}\s?\d{5}\s?\d{5}\s?[A-Z0-9]{11}\s?\d{2}\b", re.IGNORECASE)
# Bitcoin
BTC_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
# Montants en devise
AMOUNT_REGEX = re.compile(
    r"(?:€|\$|£)\s?\d{2,6}(?:[.,]\d{2})?|\d{2,6}(?:[.,]\d{2})?\s?(?:eur|€|usd|dollars?|gbp|livres?)",
    re.IGNORECASE
)
# QR code
QR_REGEX = re.compile(r"\bqr\s?code\b|\bscanner\b.*\bqr\b|\bflasher\b.*\bqr\b", re.IGNORECASE)
# Zero-width / obfuscation
ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\u2060]")

SHORTENERS = {"bit.ly","tiny.cc","t.co","short.ly","goo.gl","is.gd","cutt.ly","ow.ly"}

def _extract_sender(text: str) -> Optional[str]:
    # Cherche une ligne “De: xxx” sinon 1er email dans le texte
    for line in text.splitlines():
        if line.lower().startswith(("de: ", "from: ")):
            m = EMAIL_REGEX.search(line)
            if m: return m.group(0).lower()
    m = EMAIL_REGEX.search(text)
    return m.group(0).lower() if m else None

def _extract_header(text: str, header_name: str) -> Optional[str]:
    prefix = header_name.lower() + ":"
    for line in text.splitlines():
        if line.lower().startswith(prefix):
            return line.strip()
    return None

def _display_name_from_from_line(from_line: str) -> Optional[str]:
    if not from_line: return None
    # Ex: From: "PayPal Support" <no-reply@x.com>
    line = from_line.split(":",1)[-1].strip()
    if "<" in line:
        disp = line.split("<",1)[0].strip().strip('"').strip("'")
    else:
        disp = line.strip()
    return disp.lower() if disp else None

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
    keys = ["mot de passe", "password", "code sms", "code de vérification", "identité", "pièce d'identité",
            "identifiant", "se connecter", "vérifier votre compte", "connexion sécurisée"]
    return any(k in t for k in keys)

def _asks_money(text: str) -> bool:
    t = text.lower()
    keys = ["paiement", "virement", "remboursement", "facture", "iban", "crypto", "bitcoin", "ethereum",
            "frais", "taxe", "amende", "droit", "règlement", "régler"]
    return any(k in t for k in keys)

def _phone_scam(text: str) -> bool:
    t = text.lower()
    if any(p in t for p in PHONE_PATTERNS):
        return True
    # Numéro FR simple + formats internationaux
    if re.search(r"\b0[1-9](?:[\s\.-]?\d{2}){4}\b", t):
        return True
    if re.search(r"\+\d{1,3}[\s\.-]?\d{4,14}\b", t):
        return True
    return False

def _is_suspicious_tld(domain: str) -> bool:
    # check extension .co .xyz etc.
    if not domain or "." not in domain:
        return False
    tld = "." + domain.split(".")[-1]
    return tld in SUSPICIOUS_TLDS

def _has_mixed_scripts(s: str) -> bool:
    if not s: return False
    has_lat = bool(re.search(r"[A-Za-z]", s))
    has_cyr = bool(re.search(r"[\u0400-\u04FF]", s))
    has_grk = bool(re.search(r"[\u0370-\u03FF]", s))
    return has_lat and (has_cyr or has_grk)

def _url_reputation_boost(domain: str) -> float:
    # renvoie un facteur [0..1], qu’on multiplie par WEIGHTS["url_reputation"]
    rep = URL_REPUTATION.get(domain, 0.0)
    return max(0.0, min(1.0, float(rep)))

def _has_qr_request(text: str) -> bool:
    return bool(QR_REGEX.search(text))

def _has_amount(text: str) -> bool:
    return bool(AMOUNT_REGEX.search(text))

def _has_zero_width(text: str) -> bool:
    return bool(ZERO_WIDTH_PATTERN.search(text))

def _brand_from_display(display_name: Optional[str]) -> Optional[str]:
    if not display_name: return None
    dl = display_name.lower()
    for b in KNOWN_BRANDS:
        if b in dl:
            return b
    return None

def _quick_notes(text: str, urls: List[str], reasons: List[str], score: float) -> List[str]:
    """Notes rapides (diagnostics courts) à exposer dans l’UI/CLI."""
    tl = text.lower()
    notes = []

    # Thèmes courants
    if any("identifiants" in r or "Demande d’identifiants" in r for r in reasons) and urls:
        notes.append("Phishing identifiants")
    if any(k in tl for k in ["colis", "livraison", "chronopost", "dhl", "la poste", "suivi colis"]) and (_has_urgency(text) or _has_time_pressure(text)):
        notes.append("Faux colis / livraison")
    admin_keys = ["impôt","impots","amendes","urssaf","ameli","caf","dgfip","trésor public","tresor public"]
    if any(k in tl for k in admin_keys) and (_asks_money(text) or _asks_credentials(text)):
        notes.append("Fausse administration")
    support_keys = ["support technique","service client","compte suspendu","sécurité du compte","verifier votre compte","réinitialiser le mot de passe"]
    if any(k in tl for k in support_keys):
        notes.append("Faux support / compte")
    romance_keys = ["amour","romance","western union","argent pour billet","urgence familiale","je t'aime","héritage bloqué"]
    if any(k in tl for k in romance_keys) and _asks_money(text):
        notes.append("Arnaque sentimentale")
    if _phone_scam(text):
        notes.append("Vishing / arnaque téléphonique")
    if IBAN_REGEX.search(text) or FR_IBAN_HINT.search(text):
        notes.append("Demande de virement (IBAN)")
    if BTC_REGEX.search(text):
        notes.append("Demande crypto")
    if _has_qr_request(text):
        notes.append("QR code piégé")
    # Deepfake (à partir des raisons)
    if any("Deepfake audio" in r for r in reasons):
        notes.append("Deepfake audio suspect")
    if any("Deepfake vidéo" in r for r in reasons):
        notes.append("Deepfake vidéo suspecte")
    if any("Empreinte vocale incohérente" in r for r in reasons):
        notes.append("Empreinte vocale incohérente")
    # URLs raccourcies
    if urls:
        for u in urls:
            dom = _domain_of(u) or ""
            base = ".".join(dom.split(".")[-2:]) if "." in dom else dom
            if base in SHORTENERS or dom in SHORTENERS:
                notes.append("Lien raccourci")
                break

    # Consolidation (unique + ordre stable)
    seen = set()
    deduped = []
    for n in notes:
        if n not in seen:
            seen.add(n)
            deduped.append(n)
    return deduped

def score_text(text: str, media: Optional[Dict[str, Any]] = None) -> Tuple[float, List[str], List[str]]:
    """
    Analyse le contenu (texte/email). Retourne (score_normalized, raisons[], notesRapides[])
    Score ~ [0..100+] (plus haut = plus risqué)
    `media` (optionnel) peut contenir des flags/valeurs pour:
      - media["audio"]               -> deepfake audio détecté (bool / 0..1)
      - media["video"]               -> deepfake vidéo détecté (bool / 0..1)
      - media["voiceprint_mismatch"] -> empreinte vocale incohérente (bool / 0..1)
    """
    score = 0.0
    reasons: List[str] = []
    t = text or ""
    tl = t.lower()

    # 0) Obfuscation (caractères invisibles)
    if _has_zero_width(t):
        score += WEIGHTS["zero_width"]
        reasons.append("Caractères invisibles (obfuscation)")

    # 1) Expéditeur + en-têtes basiques
    sender = _extract_sender(t)
    from_line = _extract_header(t, "From")
    reply_to = _extract_header(t, "Reply-To")

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
            # Punycode / IDN
            if any(lbl.startswith("xn--") for lbl in dom.split(".")):
                score += WEIGHTS["punycode_domain"]
                reasons.append(f"Domaine IDN/punycode : {dom}")
            elif _has_mixed_scripts(dom):
                score += WEIGHTS["mixed_script_domain"]
                reasons.append(f"Domaine à scripts mixtes (risque homographe) : {dom}")

            # Brand mismatch display name vs domaine
            disp = _display_name_from_from_line(from_line or "")
            brand = _brand_from_display(disp)
            if brand and brand not in dom:
                score += WEIGHTS["brand_mismatch"]
                reasons.append(f"Nom d’affichage marque « {brand} » ≠ domaine expéditeur ({dom})")

    # Reply-To mismatch (domaines différents)
    if reply_to and sender:
        m1 = EMAIL_REGEX.search(reply_to)
        if m1:
            rt_addr = m1.group(0).lower()
            d1 = _domain_of(rt_addr)
            d0 = _domain_of(sender)
            if d1 and d0 and d1 != d0:
                score += WEIGHTS["reply_to_mismatch"]
                reasons.append(f"Reply-To différent du domaine expéditeur ({d0} → {d1})")

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
        # IDN / mixed scripts sur liens
        if any(lbl.startswith("xn--") for lbl in dom.split(".")):
            score += WEIGHTS["punycode_domain"]
            reasons.append(f"Domaine IDN/punycode dans lien : {dom}")
        elif _has_mixed_scripts(dom):
            score += WEIGHTS["mixed_script_domain"]
            reasons.append(f"Domaine à scripts mixtes dans lien : {dom}")

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
    had_urgency = _has_urgency(t)
    had_time    = _has_time_pressure(t)
    asks_cred   = _asks_credentials(t)
    asks_money  = _asks_money(t)

    if had_urgency:
        score += WEIGHTS["urgency"]; reasons.append("Langage d’urgence")
    if had_time:
        score += WEIGHTS["time_pressure"]; reasons.append("Pression temporelle")
    if asks_cred:
        score += WEIGHTS["credential_request"]; reasons.append("Demande d’identifiants")
    if asks_money:
        score += WEIGHTS["financial_request"]; reasons.append("Demande financière")

    # Synergies
    if had_urgency and asks_cred:
        score += WEIGHTS["synergy_urgent_cred"]; reasons.append("Urgence + identifiants")
    if (had_urgency or had_time) and (asks_money or IBAN_REGEX.search(t) or BTC_REGEX.search(t) or _has_amount(t)):
        score += WEIGHTS["synergy_money_time"]; reasons.append("Pression + argent")

    # 5) IBAN & crypto & montants
    if FR_IBAN_HINT.search(t) or IBAN_REGEX.search(t):
        score += WEIGHTS["iban_detected"]; reasons.append("IBAN détecté")
    if BTC_REGEX.search(t):
        score += WEIGHTS["crypto_address"]; reasons.append("Adresse crypto détectée")
    if _has_amount(t):
        score += WEIGHTS["amount_present"]; reasons.append("Montant d’argent détecté")

    # 6) Pièces jointes à risque (détection naïve)
    atts = _extract_attachments(t)
    if atts:
        add = WEIGHTS["attachment_risky"]
        score += add
        reasons.append(f"Pièce jointe potentiellement dangereuse : {', '.join(atts)} (+{int(add)})")

    # 7) Phone scam
    if _phone_scam(t):
        score += WEIGHTS["phone_scam"]; reasons.append("Indication d’arnaque téléphonique")

    # 8) QR code
    if _has_qr_request(t):
        score += WEIGHTS["qr_request"]; reasons.append("Demande de scan QR code")

    # 9) Deepfake / média
    if media:
        def _flag(v: Any) -> bool:
            if isinstance(v, (bool, int)):
                return bool(v)
            try:
                return float(v) >= 0.5
            except Exception:
                return bool(v)

        audio_flag = _flag(media.get("audio")) if "audio" in media else False
        video_flag = _flag(media.get("video")) if "video" in media else False
        voice_mis  = _flag(media.get("voiceprint_mismatch")) if "voiceprint_mismatch" in media else False

        if audio_flag:
            score += WEIGHTS["deepfake_audio"]
            reasons.append("Deepfake audio suspect (signal média)")
        if video_flag:
            score += WEIGHTS["deepfake_video"]
            reasons.append("Deepfake vidéo suspecte (signal média)")
        if voice_mis:
            score += WEIGHTS["voiceprint_mismatch"]
            reasons.append("Empreinte vocale incohérente (voiceprint mismatch)")

    # Clamp minimal 0
    score = max(0.0, score)
    # Normalisation douce (cap à 100, mais peut dépasser si gros cumul)
    score_normalized = min(score, 100.0)

    # Notes rapides
    notes = _quick_notes(t, urls, reasons, score_normalized)
    return score_normalized, reasons, notes

def score_url(url: str) -> Tuple[float, List[str], List[str]]:
    """Heuristique rapide si on ne donne qu’une URL (collée dans l’UI). Retourne (score, raisons, notesRapides)."""
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
        # IDN/mixed scripts
        if any(lbl.startswith("xn--") for lbl in dom.split(".")):
            score += WEIGHTS["punycode_domain"]; reasons.append(f"Domaine IDN/punycode : {dom}")
        elif _has_mixed_scripts(dom):
            score += WEIGHTS["mixed_script_domain"]; reasons.append(f"Domaine à scripts mixtes : {dom}")

    score = min(score, 100.0)
    notes = _quick_notes(url, [url], reasons, score)
    return score, reasons, notes

def explain_reasons(score: float, reasons: List[str], notes: Optional[List[str]] = None) -> str:
    badge = "🟢 SÛR" if score < 25 else "🟠 DOUTEUX" if score < 60 else "🔴 RISQUÉ"
    parts = [f"**Score** : **{int(score)}/100** — {badge}"]
    if notes:
        parts.append("**Notes rapides :** " + " · ".join(notes))
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

    # La sortie contient des badges emoji (SUR/DOUTEUX/RISQUE). La console Windows par defaut
    # (cp1252) ne peut pas les encoder et leve UnicodeEncodeError. On force UTF-8 en sortie pour
    # que la CLI tourne partout sans PYTHONIOENCODING.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="SCAMShield scorer CLI")
    parser.add_argument("--demo", action="store_true", help="Afficher un aperçu des listes et quitter")
    parser.add_argument("--text", type=str, help="Texte/email brut à évaluer")
    parser.add_argument("--url", type=str, help="URL seule à évaluer")
    parser.add_argument("--media-json", type=str, help="Fichier JSON avec signaux média (audio/video/voiceprint_mismatch)")
    args = parser.parse_args()

    if args.demo:
        print("[SCAMSHIELD] Demo mode ON")
        base = Path(__file__).resolve().parents[1] / "data"
        def head(p, n=5):
            fp = base / p
            if not fp.exists(): return ["(absent)"]
            return [l.strip() for l in fp.read_text(encoding="utf-8").splitlines()[:n] if l.strip()]
        print(" - blocked_domains.txt (5):", head("blocked_domains.txt"))
        print(" - bad_domains.txt (5):", head("bad_domains.txt"))
        print(" - malicious_senders.txt (5):", head("malicious_senders.txt"))
        print(" - known_phishing_senders.txt (5):", head("known_phishing_senders.txt"))
        print(" - suspicious_attachments.txt (5):", head("suspicious_attachments.txt"))
        print(" - suspicious_tlds.txt (5):", head("suspicious_tlds.txt"))
        print(" - brands.txt (5):", head("brands.txt"))
        sys.exit(0)

    if args.url:
        s, reasons, notes = score_url(args.url)
        print(explain_reasons(s, reasons, notes))
        sys.exit(0)

    if args.text:
        media = None
        if args.media_json:
            try:
                with open(args.media_json, "r", encoding="utf-8") as mf:
                    media = json.load(mf)
            except Exception as e:
                print(f"[SCAMSHIELD] Impossible de charger --media-json ({e}). Poursuite sans média.", file=sys.stderr)
        s, reasons, notes = score_text(args.text, media=media)
        print(explain_reasons(s, reasons, notes))
        sys.exit(0)

    parser.print_help()

