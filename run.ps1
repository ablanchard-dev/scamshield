. .\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = (Get-Location).Path
streamlit run app\main.py
