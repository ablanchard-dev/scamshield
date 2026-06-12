# SCAMShield – mini pipeline (train → predict → metrics) + app Streamlit
![CI](https://github.com/ablanchard-dev/scamshield/actions/workflows/ci.yml/badge.svg?branch=main)

Prototype SCAMShield texte : entraînement, prédiction, métriques + interface Streamlit.

## 1) Prérequis
- **Windows + PowerShell**
- **Python 3.12+**
- Git (pour la CI GitHub)

## 2) Installation rapide
```powershell
# Cloner (si besoin)
# git clone https://github.com/<votre-user>/scamshield.git
cd scamshield

# Créer/activer l'environnement
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Dépendances
pip install -r requirements.txt
