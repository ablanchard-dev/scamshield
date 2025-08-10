\
import re
import idna
from urllib.parse import urlparse
import tldextract

# Basic homoglyph map for common phishing tricks (subset; extend over time)
HOMOGLYPHS = {
    "à":"a","á":"a","â":"a","ä":"a","ã":"a","å":"a","ā":"a","ɑ":"a","а":"a",
    "è":"e","é":"e","ê":"e","ë":"e","ē":"e","е":"e",
    "ì":"i","í":"i","î":"i","ï":"i","ī":"i","ı":"i",
    "ò":"o","ó":"o","ô":"o","ö":"o","õ":"o","ō":"o","ο":"o","о":"o",
    "ù":"u","ú":"u","û":"u","ü":"u","ū":"u",
    "ÿ":"y","ý":"y",
    "ç":"c","ć":"c","č":"c",
    "ß":"ss",
    "ł":"l",
    "¡":"i","|":"l","Ｉ":"i","ⅼ":"l",
    "㎝":"cm",
}

SUSPICIOUS_TLDS = {
    "zip","mov","tk","gq","cf","ml","xyz","top","win","click","link","work",
    "monster","fit","review","country","kim","men","date","ru","su"
}

BRAND_ROOTS = [
    "apple","icloud","amazon","amzn","microsoft","outlook","office","google","gmail","youtube",
    "facebook","meta","instagram","whatsapp","paypal","stripe","revolut","wise","binance",
    "coinbase","santander","hsbc","barclays","credit-agricole","societe-generale","banquepopulaire",
    "bnp","lcl","orange","sfr","free","la-poste","impots","ameli","cpam"
]

def normalize_homoglyphs(s: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in s.lower())

def domain_of(url: str) -> str:
    try:
        if not re.match(r"^\w+://", url):
            url = "http://" + url
        u = urlparse(url)
        host = u.netloc.split("@")[-1].split(":")[0]
        host = idna.decode(idna.encode(host))
        return host
    except Exception:
        return ""

def root_parts(host: str):
    if not host:
        return ("","")
    ext = tldextract.extract(host)
    return ext.domain, ext.suffix

def levenshtein(a: str, b: str) -> int:
    # Lightweight Levenshtein (no external dep)
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    # b is shorter
    previous = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            ins = previous[j] + 1
            dele = current[-1] + 1
            sub = previous[j-1] + (ca != cb)
            current.append(min(ins, dele, sub))
        previous = current
    return previous[-1]

def is_lookalike(host: str) -> tuple[bool, str]:
    if not host:
        return (False, "")
    h_norm = normalize_homoglyphs(host)
    d, sfx = root_parts(host)
    if not d:
        return (False, "")
    for brand in BRAND_ROOTS:
        # distance on normalized root
        dist = levenshtein(normalize_homoglyphs(d), brand)
        if brand in d or dist == 0:
            # exact brand use, check for suspicious sfx or extra labels
            return (True, f"Nom de marque détecté dans le domaine: {d}")
        if dist == 1 and d != brand:
            return (True, f"Domaine similaire à une marque connue: {d} ~ {brand}")
    return (False, "")

def tld_suspicious(host: str) -> bool:
    _, sfx = root_parts(host)
    return sfx.split(".")[-1] in SUSPICIOUS_TLDS

def has_ip_host(url: str) -> bool:
    try:
        host = domain_of(url)
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    except Exception:
        return False

def url_features(url: str) -> dict:
    host = domain_of(url)
    d, sfx = root_parts(host)
    look, look_reason = is_lookalike(host)
    suspicious = tld_suspicious(host)
    iphost = has_ip_host(url)
    path_len = len(urlparse(url).path)
    q_len = len(urlparse(url).query)
    return {
        "host": host,
        "root": d,
        "suffix": sfx,
        "lookalike": look,
        "lookalike_reason": look_reason,
        "suspicious_tld": suspicious,
        "ip_host": iphost,
        "path_len": path_len,
        "query_len": q_len,
    }
