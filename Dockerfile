FROM python:3.12-slim

WORKDIR /app

# Le moteur (scamshield/scorer.py, scamshield/llm.py) n'utilise que la stdlib.
# Les paquets de requirements.txt (pandas, scikit-learn, scipy...) ne servent qu'au
# pipeline data -> train -> eval, pas au produit : on ne les installe pas ici.
# Seule la demo web a besoin d'une dependance.
RUN pip install --no-cache-dir "streamlit>=1.36,<2.0"

# data/ est obligatoire : scorer.py y lit ses listes (DATA_DIR = <racine>/data) et
# _load_list renvoie [] en silence si un fichier manque -> l'image builderait, tournerait,
# et classerait tout SUR. Le job docker de la CI verifie le verdict pour attraper ca.
COPY scamshield/ ./scamshield/
COPY data/ ./data/
COPY app/ ./app/

EXPOSE 8501

# Par defaut : la demo web. Pour la CLI :
#   docker run --rm scamshield python -m scamshield.scorer --text "..."
CMD ["streamlit", "run", "app/main.py", "--server.address=0.0.0.0", "--server.headless=true"]
