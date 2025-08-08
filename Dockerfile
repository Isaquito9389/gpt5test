# Utilise une image Python légère
FROM python:3.11-slim

# Met à jour et installe nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Crée un dossier app
WORKDIR /app

# Copie les fichiers requirements et code
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Définit la variable de clé API (à changer en prod)
ENV SCAN_API_KEY=change-me
ENV PORT=5000

# Commande de démarrage
CMD ["python", "app.py"]
