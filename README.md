# ScamShield – mini pipeline (train → predict → metrics)

(# ScamShield – mini pipeline (train → predict → metrics)

## 1) Prérequis
- Python 3.12+
- Windows PowerShell
- Ce repo contient 3 scripts :
  - `train_calibrate.py` : entraîne et calibre le modèle
  - `predict_csv.py`     : score un CSV (sort une colonne `proba` + `pred`)
  - `metrics_csv.py`     : calcule AUC / PR-AUC + métriques par seuil

## 2) Installation rapide
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
)
