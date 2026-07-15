"""Adjudication LLM optionnelle pour les cas gris de scamshield — 100% gratuite.

Le moteur de regles reste LE produit (transparent, explicable, local). Quand son
score tombe dans la bande ambigue DOUTEUX (25-60), on peut demander a un petit LLM
de trancher — avec degradation TOTALE : endpoint injoignable, JSON casse -> None,
et le score de regles reste maitre.

Fidele a l'ADN de scamshield (privacy-first, tout en local) : par defaut on tape un
**Ollama local** (http://localhost:11434, aucune cle, aucun cout, rien ne sort de la
machine). Comme c'est un endpoint **OpenAI-compatible**, la meme fonction marche aussi
avec un free tier cloud (Groq, OpenRouter...) en surchargeant 3 variables d'env :

    SCAMSHIELD_LLM_BASE   (defaut http://localhost:11434/v1)
    SCAMSHIELD_LLM_MODEL  (defaut llama3.1)
    SCAMSHIELD_LLM_KEY    (optionnel ; Ollama local n'en a pas besoin)

Off par defaut cote scorer (use_llm=False) : la CI et les tests ne demandent rien.
Zero dependance (urllib stdlib).
"""
import json
import os
import urllib.request

BASE = os.environ.get("SCAMSHIELD_LLM_BASE", "http://localhost:11434/v1")
MODEL = os.environ.get("SCAMSHIELD_LLM_MODEL", "llama3.1")
KEY = os.environ.get("SCAMSHIELD_LLM_KEY", "")

_PROMPT = (
    "Tu es un filtre anti-arnaque pour SMS/emails en francais. On te donne UN message.\n"
    "Juge s'il s'agit d'une arnaque (phishing, faux colis, faux support, arnaque au proche, "
    "sextorsion, faux investissement, fausse administration...) en te basant sur l'INGENIERIE "
    "SOCIALE (urgence, appat, usurpation, demande d'argent ou d'identifiants), pas sur la seule "
    "presence d'un lien.\n"
    'Reponds UNIQUEMENT par un objet JSON strict, sans texte autour : '
    '{"verdict": "scam" ou "legit", "confidence": nombre 0 a 1, "reason": "courte raison FR"}.\n\n'
    "Message :\n"
)


def llm_adjudicate(text, model=None, timeout=20):
    """Renvoie {'verdict','confidence','reason'} ou None.

    None des qu'il y a le moindre doute (endpoint injoignable, erreur, JSON invalide,
    verdict hors schema) : le produit retombe TOUJOURS sur les regles, jamais
    d'exception qui remonte. Frontiere de confiance, on ne la simplifie pas.
    """
    payload = {
        "model": model or MODEL,
        "messages": [{"role": "user", "content": _PROMPT + (text or "")}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    if KEY:
        headers["Authorization"] = f"Bearer {KEY}"
    try:
        req = urllib.request.Request(
            BASE.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        raw = body["choices"][0]["message"]["content"]
        data = json.loads(raw)
        verdict = data.get("verdict")
        if verdict not in ("scam", "legit"):
            return None
        conf = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
        return {"verdict": verdict, "confidence": conf, "reason": str(data.get("reason", ""))[:200]}
    except Exception:
        # ponytail: appel sync simple, pas de retry/cache/async ; ajouter si volume reel.
        return None
