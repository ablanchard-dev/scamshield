# SCAMShield

> Détection d'arnaques et de phishing dans du texte (SMS, e-mails, messages) : moteur
> de scoring explicable, démo Streamlit, pipeline d'entraînement/évaluation et extension Chrome.

![CI](https://github.com/ablanchard-dev/scamshield/actions/workflows/ci.yml/badge.svg?branch=main)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

SCAMShield analyse un texte et renvoie une probabilité d'arnaque accompagnée des
signaux qui l'ont déclenchée (pas une boîte noire). Pensé pour être explicable,
testé et déployable.

## Fonctionnalités

- Scoring explicable : chaque verdict liste ses red flags (urgence, appât du gain, demande de paiement/identifiants…) et ses indices (domaine, URL, expéditeur).
- Signaux data-driven : réputation de domaines/URLs, TLDs suspects, expéditeurs de phishing connus, listes denylist/allowlist de tournures.
- Pipeline `train -> predict -> metrics` : scripts CSV pour entraîner, prédire et mesurer la performance.
- Démo Streamlit : coller un message, voir le score et les raisons en direct.
- Extension Chrome : scoring directement dans le navigateur.
- Tests + CI : suite `tests/` (comportement + contrat) lancée par GitHub Actions.

## Démarrage rapide

```bash
git clone https://github.com/ablanchard-dev/scamshield.git
cd scamshield

python -m venv .venv
# Linux/macOS : source .venv/bin/activate
# Windows     : .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Lancer la démo Streamlit
streamlit run app/main.py
```

Scorer un fichier CSV en ligne de commande :

```bash
python predict_csv.py            # prédictions
python metrics_csv.py            # métriques (precision / recall / etc.)
```

## Comment ça marche

Le moteur (`scamshield/scorer.py`) combine plusieurs signaux pondérés :

| Signal | Source |
|---|---|
| Tournures à risque | `data/denylist_phrases.txt` / `allowlist_phrases.txt` |
| Domaines & URLs | `data/url_reputation.json`, `bad_domains.txt`, `suspicious_tlds.txt` |
| Expéditeurs | `data/known_phishing_senders.txt`, `malicious_senders.txt`, `trusted_senders.txt` |
| Pièces jointes | `data/dangerous_attachment_hashes.txt`, `suspicious_attachments.txt` |

Le résultat est une probabilité de 0 à 1 + la liste des raisons, ce qui rend chaque décision auditable.

## Structure

```
scamshield/        # moteur de scoring (scorer, url_utils) + données de référence
app/main.py        # interface Streamlit
extension/         # extension Chrome (manifest + popup)
data/              # listes de signaux + jeux de données CSV
tests/             # tests comportement + contrat
predict_csv.py / metrics_csv.py / seed_data.py
.github/workflows/ # CI (lint + tests) et release
```

## Tests

```bash
pytest
```

La CI GitHub Actions exécute les tests à chaque push (badge ci-dessus).

## Licence

MIT.
