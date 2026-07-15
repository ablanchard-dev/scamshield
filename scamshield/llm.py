"""Adjudication LLM optionnelle pour les cas gris de scamshield.

Le moteur de regles reste LE produit (transparent, explicable, local). Quand son
score tombe dans la bande ambigue DOUTEUX (25-60), on peut demander a un petit LLM
de trancher — avec une sortie structuree et une degradation TOTALE : pas de cle,
pas de reseau, ou JSON casse -> None, et le score de regles reste maitre.

Off par defaut cote scorer (use_llm=False) : la CI et les tests ne demandent
aucune cle. Ce module n'importe `anthropic` que si on l'appelle vraiment.
"""
import json
import os

# Modele le moins cher, tache = classification binaire courte. Id exact (skill claude-api),
# ne PAS suffixer de date.
MODEL = "claude-haiku-4-5"

_PROMPT = (
    "Tu es un filtre anti-arnaque pour SMS/emails en francais. On te donne UN message.\n"
    "Juge s'il s'agit d'une arnaque (phishing, faux colis, faux support, arnaque au proche, "
    "sextorsion, faux investissement, fausse administration...) en te basant sur l'INGENIERIE "
    "SOCIALE (urgence, appat, usurpation d'identite, demande d'argent ou d'identifiants), pas "
    "sur la seule presence d'un lien.\n"
    "Reponds UNIQUEMENT via le schema JSON impose : verdict scam|legit, confidence 0..1, "
    "reason (courte, en francais).\n\nMessage :\n"
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["scam", "legit"]},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reason"],
    "additionalProperties": False,
}


def llm_adjudicate(text, model=MODEL):
    """Renvoie {'verdict','confidence','reason'} ou None.

    None des qu'il y a le moindre doute (pas de cle, erreur reseau/API, JSON
    invalide, verdict hors schema) : le produit retombe TOUJOURS sur les regles,
    jamais d'exception qui remonte. C'est une frontiere de confiance, on ne la
    simplifie pas.
    """
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return None
    try:
        import anthropic
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=256,
            output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
            messages=[{"role": "user", "content": _PROMPT + (text or "")}],
        )
        raw = next((b.text for b in resp.content if b.type == "text"), None)
        if not raw:
            return None
        data = json.loads(raw)
        verdict = data.get("verdict")
        if verdict not in ("scam", "legit"):
            return None
        conf = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
        return {"verdict": verdict, "confidence": conf, "reason": str(data.get("reason", ""))[:200]}
    except Exception:
        # ponytail: appel sync simple, pas de retry/cache/async ; ajouter si volume reel.
        return None
