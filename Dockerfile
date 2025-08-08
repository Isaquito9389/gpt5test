# Utilise une image Python légère
FROM python:3.11-slim

# Met à jour et installe les dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Crée un utilisateur non-root
RUN useradd -m appuser && \
    chown -R appuser:appuser /app

# Change à l'utilisateur non-root
USER appuser

# Crée le dossier de travail
WORKDIR /app

# Copie les fichiers requirements et code
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copie le reste du code
COPY . .

# Définit les variables d'environnement
ENV SCAN_API_KEY=change-me
ENV PORT=5000

# Commande de démarrage
CMD ["python", "app.py"]
