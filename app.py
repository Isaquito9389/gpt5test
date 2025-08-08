import os
import re
import time
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import socket
import urllib.request
import urllib.parse
from threading import Lock
from flask import Flask, request, jsonify, render_template_string
from flask import send_from_directory
# Configuration
API_KEY = os.environ.get("SCAN_API_KEY", "change-me")  # changez via env var en production
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "10"))  # requêtes/min par clé
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "25"))  # secondes
ALLOWED_PORT_RANGE_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")  # optionnel: validation ports

app = Flask(__name__)

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

def normalize_host(host):
    """Normalise un nom d'hôte en retirant les protocoles et www optionnels"""
    if not host:
        return None
    
    # Retirer les protocoles
    host = re.sub(r'^https?://', '', host.lower().strip())
    # Retirer les chemins
    host = host.split('/')[0]
    # Retirer les ports s'ils sont spécifiés
    host = host.split(':')[0]
    
    return host

def resolve_host_with_redirects(host):
    """Résout un nom d'hôte en suivant les redirections et retourne l'IP finale"""
    try:
        # D'abord, essayer de résoudre directement si c'est déjà une IP
        try:
            ipaddress.ip_address(host)
            return host, host  # C'est déjà une IP
        except:
            pass
        
        # Normaliser le host
        normalized = normalize_host(host)
        if not normalized:
            return None, None
            
        # Essayer différentes variantes du domaine
        variants = [normalized]
        
        # Si pas de www, ajouter www
        if not normalized.startswith('www.'):
            variants.append(f'www.{normalized}')
        # Si www présent, essayer sans
        elif normalized.startswith('www.'):
            variants.append(normalized[4:])
        
        final_host = None
        final_ip = None
        
        # Tester chaque variante
        for variant in variants:
            try:
                # Essayer de suivre les redirections HTTP
                for protocol in ['https', 'http']:
                    try:
                        url = f'{protocol}://{variant}'
                        req = urllib.request.Request(url, method='HEAD')
                        req.add_header('User-Agent', 'Port-Scanner/1.0')
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            # Récupérer l'URL finale après redirections
                            final_url = response.url
                            final_host = urllib.parse.urlparse(final_url).netloc
                            break
                    except:
                        continue
                
                # Si on a trouvé un host final, résoudre son IP
                if final_host:
                    try:
                        final_ip = socket.gethostbyname(final_host)
                        return final_host, final_ip
                    except:
                        continue
                        
                # Sinon essayer de résoudre directement la variante
                try:
                    resolved_ip = socket.gethostbyname(variant)
                    return variant, resolved_ip
                except:
                    continue
                    
            except:
                continue
        
        # Si aucune variante ne fonctionne, essayer une résolution DNS simple
        try:
            ip = socket.gethostbyname(normalized)
            return normalized, ip
        except:
            return None, None
            
    except Exception:
        return None, None

def validate_host(host):
    """Valide et résout un nom d'hôte"""
    if not host:
        return False
    
    # Essayer de résoudre avec redirections
    resolved_host, resolved_ip = resolve_host_with_redirects(host)
    return resolved_host is not None and resolved_ip is not None

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

    # Résoudre l'hôte avec gestion des redirections
    resolved_host, target_ip = resolve_host_with_redirects(host)
    
    if not resolved_host or not target_ip:
        return jsonify({"error": f"Unable to resolve host: {host}"}), 400

    # optional validation of ports format (simple)
    if ports_spec and ports_spec.strip() and not ALLOWED_PORT_RANGE_RE.match(str(ports_spec).strip()):
        return jsonify({"error": "Invalid ports format. Example: '1-1024' or '22,80,443'"}), 400
    
    # Si ports_spec est vide ou None, utiliser la valeur par défaut
    if not ports_spec or not ports_spec.strip():
        ports_spec = "1-1024"

    # Build nmap command - utiliser l'IP résolue pour le scan
    cmd = ["nmap", "-Pn", "-p", str(ports_spec), "--open", "-oX", "-", target_ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "nmap timed out"}), 504
    except FileNotFoundError:
        return jsonify({"error": "nmap not installed on server"}), 503
    except Exception as e:
        return jsonify({"error": "Internal error running nmap"}), 500

    if proc.returncode not in (0, 1):  # nmap returns 0 (no hosts down), 1 (hosts down) etc
        pass  # still try to parse output

    xml_out = proc.stdout
    if not xml_out:
        # sometimes nmap outputs to stderr
        xml_out = proc.stderr or b""

    open_ports = parse_nmap_xml(xml_out)

    response = {
        "original_host": host,
        "resolved_host": resolved_host,
        "target_ip": target_ip,
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
    return send_from_directory("static", "index.html")

@app.route("/static/config.js")
def config_js():
    api_key = os.environ.get("SCAN_API_KEY", "change-me")
    config_content = f"""// Configuration dynamique pour l'API
window.API_CONFIG = {{
    API_KEY: "{api_key}",
    API_URL: window.location.origin + "/scan"
}};"""
    return config_content, 200, {'Content-Type': 'application/javascript'}

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "service": "Port Scanner API"}), 200

@app.route("/debug", methods=["GET"])
def debug_info():
    return jsonify({
        "api_key_configured": bool(os.environ.get("SCAN_API_KEY")),
        "api_key_length": len(os.environ.get("SCAN_API_KEY", "")),
        "rate_limit": RATE_LIMIT_PER_MIN,
        "timeout": NMAP_TIMEOUT
    }), 200

@app.route("/resolve", methods=["POST"])
def test_resolve():
    """Test de résolution DNS avec redirections"""
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 400
    
    data = request.get_json()
    host = data.get("host")
    
    if not host:
        return jsonify({"error": "Missing 'host' in JSON body"}), 400
    
    resolved_host, target_ip = resolve_host_with_redirects(host)
    
    return jsonify({
        "original_host": host,
        "resolved_host": resolved_host,
        "target_ip": target_ip,
        "success": resolved_host is not None
    }), 200

@app.errorhandler(500)
def server_err(e):
    return jsonify({"error": "Internal server error"}), 500
if __name__ == "__main__":
    # production: use gunicorn/uvicorn, not flask builtin server
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
