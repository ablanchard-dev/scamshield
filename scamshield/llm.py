"""Adjudication LLM optionnelle pour les cas gris de scamshield — gratuite.

Le moteur de regles reste LE produit (transparent, explicable, local). Quand son
score tombe dans la bande ambigue DOUTEUX (25-60), un petit LLM tranche — avec
degradation TOTALE : pas de cle / endpoint injoignable / JSON casse -> None, et le
score de regles reste maitre.

Aucune API payante. On reutilise les **free tiers OpenAI-compatibles** que le
portfolio utilise deja (memes cles que lumenia) : la fonction DETECTE automatiquement
la premiere cle presente dans l'environnement (Groq, Cerebras, Gemini, Mistral).
A defaut de toute cle, elle tombe sur un Ollama local (si un serveur ecoute).

Surcharge explicite possible : SCAMSHIELD_LLM_BASE / SCAMSHIELD_LLM_MODEL /
SCAMSHIELD_LLM_KEY. Off par defaut cote scorer (use_llm=False). Zero dependance (urllib).
"""
import json
import os
import time
import urllib.error
import urllib.request

# Free tiers OpenAI-compatibles, par ordre de preference (limite/vitesse). Modeles
# petits/rapides : la tache est une classification binaire courte.
_PROVIDERS = [
    ("GROQ_API_KEY",     "https://api.groq.com/openai/v1",                          "llama-3.1-8b-instant"),
    ("CEREBRAS_API_KEY", "https://api.cerebras.ai/v1",                              "gpt-oss-120b"),
    ("GEMINI_API_KEY",   "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.5-flash-lite"),
    ("MISTRAL_API_KEY",  "https://api.mistral.ai/v1",                               "mistral-small-latest"),
    ("XAI_API_KEY",      "https://api.x.ai/v1",                                     "grok-3-mini"),  # credits requis (pas gratuit)
]


def _resolve():
    """(base, model, key) : surcharge explicite > 1re cle free-tier presente > Ollama local."""
    base = os.environ.get("SCAMSHIELD_LLM_BASE")
    if base:
        return base, os.environ.get("SCAMSHIELD_LLM_MODEL", ""), os.environ.get("SCAMSHIELD_LLM_KEY", "")
    for env, prov_base, prov_model in _PROVIDERS:
        key = os.environ.get(env)
        if key:
            return prov_base, os.environ.get("SCAMSHIELD_LLM_MODEL", prov_model), key
    # Dernier recours : Ollama local (aucune cle). Injoignable -> None plus bas.
    return "http://localhost:11434/v1", os.environ.get("SCAMSHIELD_LLM_MODEL", "llama3.1"), ""


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


def llm_adjudicate(text, timeout=20):
    """Renvoie {'verdict','confidence','reason'} ou None.

    None des qu'il y a le moindre doute : le produit retombe TOUJOURS sur les regles,
    jamais d'exception qui remonte. Frontiere de confiance, on ne la simplifie pas.
    """
    base, model, key = _resolve()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": _PROMPT + (text or "")}],
        "temperature": 0,
        "max_tokens": 200,        # cap la sortie : la reponse JSON est courte -> moins de tokens/min consommes
        "response_format": {"type": "json_object"},
        "stream": False,
    }
    headers = {
        "Content-Type": "application/json",
        # UA navigateur : certains fournisseurs (Cerebras via Cloudflare) rejettent
        # le UA par defaut d'urllib avec un 403 code 1010.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/125 Safari/537.36",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data_bytes = json.dumps(payload).encode("utf-8")
    url = base.rstrip("/") + "/chat/completions"

    # Retry sur 429 (rate limit) : respecte Retry-After sinon backoff, plafonne le total.
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            raw = body["choices"][0]["message"]["content"]
            data = json.loads(raw)
            verdict = data.get("verdict")
            if verdict not in ("scam", "legit"):
                return None
            conf = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
            return {"verdict": verdict, "confidence": conf, "reason": str(data.get("reason", ""))[:200]}
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                wait = e.headers.get("Retry-After")
                time.sleep(min(float(wait), 30) if wait and wait.replace(".", "").isdigit() else (attempt + 1) * 12)
                continue
            return None
        except Exception:
            return None
    return None
