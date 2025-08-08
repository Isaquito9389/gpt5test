# Port Scanner API

Une API REST pour scanner les ports ouverts d'un hôte en utilisant nmap.

## Déploiement sur Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Isaquito9389/port-scanner-api)

## Configuration

Variables d'environnement :
- `SCAN_API_KEY` : Clé API pour authentification (générée automatiquement sur Render)
- `RATE_LIMIT_PER_MIN` : Limite de requêtes par minute (défaut: 10)
- `NMAP_TIMEOUT` : Timeout pour nmap en secondes (défaut: 25)

## Utilisation

```bash
curl -X POST https://votre-app.onrender.com/scan \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: votre-cle-api" \
  -d '{"host": "example.com", "ports": "1-1024"}'
```

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