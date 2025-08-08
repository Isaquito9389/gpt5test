# Port Scanner API

Une API REST pour scanner les ports ouverts d'un hôte en utilisant nmap.

## Déploiement sur Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Isaquito9389/gpt5test)

## Configuration

Variables d'environnement :
- `SCAN_API_KEY` : Clé API pour authentification (générée automatiquement sur Render)
- `RATE_LIMIT_PER_MIN` : Limite de requêtes par minute (défaut: 10)
- `NMAP_TIMEOUT` : Timeout pour nmap en secondes (défaut: 25)

## Installation locale

1. Clonez le dépôt :
```bash
git clone https://github.com/Isaquito9389/gpt5test.git
```

2. Créez un fichier `.env` :
```bash
touch .env
```

3. Ajoutez vos variables d'environnement dans `.env` :
```
SCAN_API_KEY=votre_clé_api
RATE_LIMIT_PER_MIN=10
NMAP_TIMEOUT=25
```

4. Installez les dépendances :
```bash
pip install -r requirements.txt
```

5. Lancez l'application :
```bash
python app.py
```

## Déploiement sur Render

1. Créez un compte sur [Render](https://render.com)
2. Cliquez sur le bouton "Deploy to Render" ci-dessus
3. Configurez les variables d'environnement :
   - `SCAN_API_KEY` : Laissez "Generate value"
   - `RATE_LIMIT_PER_MIN` : Optionnel (défaut: 10)
   - `NMAP_TIMEOUT` : Optionnel (défaut: 25)

## Utilisation

### Interface Web
Accédez directement à votre application déployée pour utiliser l'interface graphique.

### API REST
```bash
curl -X POST https://votre-app.onrender.com/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: votre-cle-api" \
  -d '{"host": "example.com", "ports": "1-1024"}'
```

### Configuration post-déploiement
1. Récupérez votre clé API depuis les variables d'environnement Render
2. Modifiez la variable `API_KEY` dans `static/index.html` ligne 45

## Réponse

```json
{
  "host": "example.com",
  "open_ports": [
    {"port": 80, "protocol": "tcp", "service": "http"},
    {"port": 443, "protocol": "tcp", "service": "https"}
  ],
  "scanned_ports": "1-1024",
  "nmap_exit_code": 0
}
```