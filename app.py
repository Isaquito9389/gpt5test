import os
import re
import time
import ipaddress
import logging
import subprocess
import xml.etree.ElementTree as ET
from threading import Lock
from flask import Flask, request, jsonify, abort
from flask import send_from_directory
# Configuration
API_KEY = os.environ.get("SCAN_API_KEY", "change-me")  # changez via env var en production
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "10"))  # requêtes/min par clé
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "25"))  # secondes
ALLOWED_PORT_RANGE_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")  # optionnel: validation ports

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# in-memory rate limiting: api_key -> [timestamps_of_requests]
_rate_lock = Lock()
_rate_store = {}

def check_rate_limit(key):
    now = time.time()
    window_start = now - 60
    with _rate_lock:
        timestamps = _rate_store.get(key, [])
        # keep only timestamps in the last minute
        timestamps = [t for t in timestamps if t >= window_start]
        if len(timestamps) >= RATE_LIMIT_PER_MIN:
            _rate_store[key] = timestamps
            return False
        timestamps.append(now)
        _rate_store[key] = timestamps
    return True

def validate_host(host):
    # Accept IPv4, IPv6 or hostname (basic)
    try:
        # if it's an IP this will validate
        ipaddress.ip_address(host)
        return True
    except Exception:
        # hostname basic sanity check (no spaces, reasonable chars)
        if len(host) > 255:
            return False
        if host.endswith("."):
            host = host[:-1]
        allowed = re.compile(r"^(?=.{1,255}$)[0-9A-Za-z](?:[0-9A-Za-z\-]{0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z\-]{0,61}[0-9A-Za-z])?)*$")
        return bool(allowed.match(host))

def parse_nmap_xml(xml_bytes):
    # returns list of dicts: {"port": int, "protocol": "tcp", "service": "ssh"}
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []
    ports = []
    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for p in ports_elem.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = p.get("portid")
            proto = p.get("protocol")
            svc = p.find("service")
            svcname = svc.get("name") if svc is not None and svc.get("name") else None
            try:
                portnum = int(portid)
            except Exception:
                continue
            ports.append({"port": portnum, "protocol": proto, "service": svcname})
    return ports

@app.route("/scan", methods=["POST"])
def scan():
    # API key
    key = request.headers.get("X-API-KEY") or request.headers.get("Authorization")
    if not key:
        return jsonify({"error": "API key required in X-API-KEY header"}), 401
    # support "Bearer <key>" in Authorization
    if key.startswith("Bearer "):
        key = key.split(" ", 1)[1].strip()
    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403

    # rate limit
    if not check_rate_limit(key):
        return jsonify({"error": "Rate limit exceeded"}), 429

    # parse JSON body
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 400
    data = request.get_json()
    host = data.get("ip") or data.get("host")
    ports_spec = data.get("ports", "1-1024")  # default ports range to scan

    if not host:
        return jsonify({"error": "Missing 'ip' (or 'host') in JSON body"}), 400

    if not validate_host(host):
        return jsonify({"error": "Invalid host/ip format"}), 400

    # optional validation of ports format (simple)
    if ports_spec and not ALLOWED_PORT_RANGE_RE.match(str(ports_spec)):
        return jsonify({"error": "Invalid ports format. Example: '1-1024' or '22,80,443'"}), 400

    # Build nmap command
    cmd = ["nmap", "-Pn", "-p", str(ports_spec), "--open", "-oX", "-", host]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "nmap timed out"}), 504
    except FileNotFoundError:
        return jsonify({"error": "nmap not installed on server"}), 503
    except Exception as e:
        app.logger.exception("Error running nmap")
        return jsonify({"error": "Internal error running nmap", "detail": str(e)}), 500

    if proc.returncode not in (0, 1):  # nmap returns 0 (no hosts down), 1 (hosts down) etc
        # still try to parse output, but inform user
        app.logger.warning("nmap returned non-zero exit code: %s", proc.returncode)

    xml_out = proc.stdout
    if not xml_out:
        # sometimes nmap outputs to stderr
        xml_out = proc.stderr or b""

    open_ports = parse_nmap_xml(xml_out)

    response = {
        "host": host,
        "open_ports": open_ports,
        "scanned_ports": str(ports_spec),
        "nmap_exit_code": proc.returncode
    }
    return jsonify(response), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.route("/")
def home():
    api_key = os.environ.get("SCAN_API_KEY", "")
    return f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Port Scanner Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
    h1 {{ text-align: center; }}
    .card {{ background: white; padding: 20px; border-radius: 8px; max-width: 500px; margin: auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1);}}
    label {{ display: block; margin-top: 15px; }}
    input, button {{ width: 100%; padding: 10px; margin-top: 5px; }}
    button {{ background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}
    button:hover {{ background: #0056b3; }}
    pre {{ background: #272822; color: #f8f8f2; padding: 10px; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
    <h1>Port Scanner</h1>
    <div class="card">
        <label for="host">Adresse IP ou nom d'hôte :</label>
        <input type="text" id="host" placeholder="Ex: 192.168.1.1 ou example.com">
        <label for="ports">Ports (optionnel) :</label>
        <input type="text" id="ports" placeholder="Ex: 80,443 ou 1-1024">
        <button onclick="scan()">Scanner</button>
        <div id="result"></div>
    </div>
    <script src="config.js"></script>
    <script>
        // Injecter la clé API depuis le backend
        window.API_CONFIG.API_KEY = "{api_key}";
        async function scan() {{
            const host = document.getElementById('host').value.trim();
            const ports = document.getElementById('ports').value.trim();
            if (!host) {{
                alert('Veuillez entrer une adresse IP ou un nom d\'hôte');
                return;
            }}
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<p>Scanning...</p>';
            try {{
                const response = await fetch(window.API_CONFIG.API_URL, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-API-Key': window.API_CONFIG.API_KEY
                    }},
                    body: JSON.stringify({{
                        host,
                        ports: ports || null
                    }})
                }});
                if (!response.ok) {{
                    throw new Error('Erreur lors du scan');
                }}
                const data = await response.json();
                resultDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            }} catch (error) {{
                resultDiv.innerHTML = `<p style="color: red;">Erreur: ${error.message}</p>`;
            }}
        }}
    </script>
</body>
</html>
    """

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "service": "Port Scanner API"}), 200

@app.errorhandler(500)
def server_err(e):
    return jsonify({"error": "Internal server error"}), 500
if __name__ == "__main__":
    # production: use gunicorn/uvicorn, not flask builtin server
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
