#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import logging
import subprocess
import requests
import os
from datetime import datetime

# Inicialización de la aplicación Flask
app = Flask(__name__)

# Configuración del webhook de Microsoft Teams y archivo de log
WEBHOOK_URL = "https://defaultdde2fb8fd8e0445eb851e69c198c1e.59.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/27/workflows/5d4c08e3e08246ed96cd27a6b44e3836/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=s9A3lzmyqUhZHjq9Y9x6d_Rjrn4qxurFIEBEEeFZpgY"
LOG_FILE = "../central_security_alerts.log"
alertas_recientes = []

# Ruta base para encontrar los scripts en la carpeta blue_team/ (un nivel arriba)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Configuración del logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

def bloquear_ip(ip):
    """Bloquea la IP a nivel de firewall para la respuesta automática."""
    try:
        check = subprocess.run(f"sudo iptables -C INPUT -s {ip} -j DROP", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode != 0:
            subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            return f"IP {ip} bloqueada"
    except Exception as e:
        return f"Error: {e}"
    return "Ya estaba bloqueada"

def obtener_geolocalizacion(ip):
    """Consulta la ubicación geográfica de la IP usando una API pública y ligera."""
    if not ip or ip in ["127.0.0.1", "::1", "localhost", "10.0.0.99"]:
        return "Local / Red Interna"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                pais = data.get("country", "Desconocido")
                ciudad = data.get("city", "")
                return f"{pais}, {ciudad}" if ciudad else pais
    except Exception:
        pass
    return "Desconocido"

def enviar_webhook_teams(fuente, nivel, mensaje, accion, ip_atacante=None):
    """Envía una Tarjeta Adaptable (Adaptive Card) válida al flujo de Power Automate en Teams."""
    if not WEBHOOK_URL:
        return
    
    # Colores y emojis según el nivel de alerta
    color_titulo = "attention" if nivel == "CRITICAL" else ("warning" if nivel == "WARNING" else "accent")
    icono = "🚨" if nivel == "CRITICAL" else ("⚠️" if nivel == "WARNING" else "ℹ️")
    
    # Obtener geolocalización limpia usando la IP real
    ubicacion = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"
    
    # Estructura JSON obligatoria para Tarjetas Adaptables de Teams
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.2",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{icono} Alerta de Seguridad: {nivel}",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": color_titulo
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Sensor:", "value": fuente},
                                {"title": "Detalle:", "value": mensaje},
                                {"title": "IP Atacante:", "value": ip_atacante if ip_atacante else "N/A"},
                                {"title": "Geolocalización:", "value": ubicacion},
                                {"title": "Firewall:", "value": accion},
                                {"title": "Hora:", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                            ]
                        }
                    ]
                }
            }
        ]
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=3)
        if response.status_code not in [200, 202]:
            logging.error(f"Teams respondió con código inesperado: {response.status_code}")
    except Exception as e:
        logging.error(f"Error enviando alerta a Teams: {e}")
        
# Rutas de la API
@app.route('/api/alert', methods=['POST'])
def recibir_alerta():
    """Recibe alertas en formato JSON desde Atom, el sniffer o el monitor SSH."""
    datos = request.get_json()
    if not datos:
        return jsonify({"error": "Payload inválido"}), 400

    # Extrae los campos del JSON y registra la alerta
    fuente = datos.get("source", "Desconocido")
    nivel = datos.get("level", "INFO")
    mensaje = datos.get("message", "Sin detalles")
    ip_atacante = datos.get("ip_to_block", None)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Obtener geolocalización para el registro del dashboard también
    ubicacion_atacante = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"

    # Bloquea la IP si se proporciona y registra la acción
    accion_tomada = bloquear_ip(ip_atacante) if ip_atacante else "Ninguna"
    if ip_atacante:
        mensaje_log = f"{mensaje} | IP: {ip_atacante} ({ubicacion_atacante}) | Acción: {accion_tomada}"
    else:
        mensaje_log = mensaje

    log_msg = f"{fuente} | {mensaje_log}"
    if nivel == "CRITICAL": 
        logging.critical(log_msg)
    elif nivel == "WARNING": 
        logging.warning(log_msg)
    else: 
        logging.info(log_msg)

    alertas_recientes.insert(0, {
        "tiempo": timestamp, "fuente": fuente, "nivel": nivel, 
        "mensaje": mensaje, "accion": accion_tomada, "ubicacion": ubicacion_atacante
    })
    
    if len(alertas_recientes) > 50:
        alertas_recientes.pop()

    # Disparar la notificación a Microsoft Teams si es una alerta importante
    if nivel in ["WARNING", "CRITICAL"]:
        enviar_webhook_teams(fuente, nivel, mensaje, accion_tomada, ip_atacante)

    return jsonify({"status": "ok"}), 200

@app.route('/api/run/<herramienta>', methods=['POST'])
def ejecutar_herramienta(herramienta):
    """Dispara las herramientas de defensa desde los botones del dashboard."""
    try:
        if herramienta == 'firewall':
            script_path = os.path.join(BASE_DIR, 'firewall_hardening.sh')
            subprocess.Popen(['sudo', 'bash', script_path])
            mensaje = "Hardening de firewall UFW ejecutado."
            
        elif herramienta == 'audit':
            launcher_path = os.path.join(BASE_DIR, 'atom_launcher.py')
            subprocess.Popen(['python3', launcher_path])
            mensaje = "Auditoría del sistema iniciada con el framework Atom."
            
        elif herramienta == 'sniffer':
            script_path = os.path.join(BASE_DIR, 'sniffer_defense.py')
            subprocess.Popen(['sudo', 'python', script_path])
            mensaje = "Sniffer de red (IDS) activado en segundo plano."
            
        else:
            return jsonify({"error": "Herramienta no reconocida"}), 400

        requests.post('http://127.0.0.1:5000/api/alert', json={
            "source": "Web Dashboard",
            "level": "INFO",
            "message": mensaje
        })
        
        return jsonify({"status": "ok", "message": mensaje}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def dashboard():
    return render_template('index.html', alertas=alertas_recientes)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)