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

def get_real_ip_behind_cdn(domain):
    """Techniques pour trouver la vraie IP derrière Cloudflare/CDN"""
    real_ips = []
    
    try:
        # 1. Recherche de sous-domaines non protégés
        subdomains = ['mail', 'ftp', 'cpanel', 'webmail', 'direct', 'origin', 'admin', 'dev', 'staging']
        for sub in subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                ip = socket.gethostbyname(subdomain)
                # Vérifier si ce n'est pas une IP Cloudflare
                if not is_cloudflare_ip(ip):
                    real_ips.append({"method": f"subdomain_{sub}", "ip": ip, "host": subdomain})
            except:
                continue
        
        # 2. Recherche DNS historique (simulation)
        try:
            # Technique: essayer des enregistrements MX
            import subprocess
            result = subprocess.run(['nslookup', '-type=MX', domain], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Parser les résultats MX pour trouver des IPs
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'mail exchanger' in line.lower():
                        parts = line.split()
                        if len(parts) > 3:
                            mx_host = parts[-1].rstrip('.')
                            try:
                                mx_ip = socket.gethostbyname(mx_host)
                                if not is_cloudflare_ip(mx_ip):
                                    real_ips.append({"method": "mx_record", "ip": mx_ip, "host": mx_host})
                            except:
                                continue
        except:
            pass
            
        # 3. Technique de scan de plages IP connues
        # (Simulation - en production, utiliser des bases de données spécialisées)
        
    except Exception:
        pass
    
    return real_ips

def is_cloudflare_ip(ip):
    """Vérifie si une IP appartient à Cloudflare"""
    cloudflare_ranges = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
        '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
        '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
    ]
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in cloudflare_ranges:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except:
        pass
    return False

def build_nmap_command(target_ip, ports_spec, scan_level):
    """Construit la commande nmap selon le niveau de scan"""
    base_cmd = ["nmap"]
    
    if scan_level == "basic":
        # Scan basique rapide
        cmd = base_cmd + ["-Pn", "-p", str(ports_spec), "--open", "-oX", "-", target_ip]
    
    elif scan_level == "advanced":
        # Scan avancé avec détection de services
        cmd = base_cmd + [
            "-Pn", "-sS", "-sV", "-O", 
            "-p", str(ports_spec), 
            "--open", "--version-intensity", "5",
            "-oX", "-", target_ip
        ]
    
    elif scan_level == "expert":
        # Scan expert avec évasion et scripts
        cmd = base_cmd + [
            "-Pn", "-sS", "-sV", "-sC", "-O",
            "-p", str(ports_spec),
            "--open", "--version-intensity", "9",
            "--script", "default,discovery,vuln",
            "-T4", "--min-rate", "1000",
            "--max-retries", "3",
            "-f",  # Fragment packets
            "--source-port", "53",  # Use DNS port as source
            "--data-length", "25",  # Add random data
            "-oX", "-", target_ip
        ]
    
    elif scan_level == "stealth":
        # Scan furtif pour éviter la détection
        cmd = base_cmd + [
            "-Pn", "-sS", "-sV",
            "-p", str(ports_spec),
            "--open", "-T2",  # Timing très lent
            "--scan-delay", "2s",
            "--max-rate", "10",
            "-f", "-f",  # Double fragmentation
            "--mtu", "16",
            "--source-port", "53",
            "--spoof-mac", "0",
            "-oX", "-", target_ip
        ]
    
    else:
        # Par défaut: basic
        cmd = base_cmd + ["-Pn", "-p", str(ports_spec), "--open", "-oX", "-", target_ip]
    
    return cmd

def parse_nmap_xml(xml_bytes):
    """Parse XML nmap avec informations détaillées"""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return [], {}
    
    ports = []
    host_info = {}
    
    for host in root.findall("host"):
        # Informations sur l'hôte
        status = host.find("status")
        if status is not None:
            host_info["status"] = status.get("state")
        
        # OS Detection
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host_info["os"] = {
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                }
        
        # Ports
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
            
        for p in ports_elem.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
                
            portid = p.get("portid")
            proto = p.get("protocol")
            
            # Service detection
            svc = p.find("service")
            service_info = {}
            if svc is not None:
                service_info = {
                    "name": svc.get("name"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "extrainfo": svc.get("extrainfo")
                }
            
            # Scripts results
            scripts = []
            for script in p.findall("script"):
                scripts.append({
                    "id": script.get("id"),
                    "output": script.get("output")
                })
            
            try:
                portnum = int(portid)
            except Exception:
                continue
                
            port_data = {
                "port": portnum,
                "protocol": proto,
                "service": service_info,
                "scripts": scripts
            }
            ports.append(port_data)
    
    return ports, host_info

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
    
    # Niveau de scan
    scan_level = data.get("scan_level", "basic")
    
    # Recherche de la vraie IP derrière CDN pour les scans avancés
    real_ips = []
    if scan_level in ["expert", "stealth"]:
        real_ips = get_real_ip_behind_cdn(resolved_host)
    
    # Build nmap command selon le niveau
    cmd = build_nmap_command(target_ip, ports_spec, scan_level)

    # Ajuster le timeout selon le niveau de scan
    timeout = NMAP_TIMEOUT
    if scan_level == "expert":
        timeout = NMAP_TIMEOUT * 3  # 3x plus long pour expert
    elif scan_level == "stealth":
        timeout = NMAP_TIMEOUT * 4  # 4x plus long pour stealth
    elif scan_level == "advanced":
        timeout = NMAP_TIMEOUT * 2  # 2x plus long pour advanced

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"nmap timed out after {timeout}s (scan level: {scan_level})"}), 504
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

    open_ports, host_info = parse_nmap_xml(xml_out)

    response = {
        "original_host": host,
        "resolved_host": resolved_host,
        "target_ip": target_ip,
        "scan_level": scan_level,
        "open_ports": open_ports,
        "host_info": host_info,
        "real_ips_found": real_ips,
        "scanned_ports": str(ports_spec),
        "nmap_exit_code": proc.returncode,
        "is_behind_cdn": is_cloudflare_ip(target_ip)
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
