#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, Response
import hmac
import ipaddress
import logging
import subprocess
import requests
import os
from datetime import datetime

# Inicialización de la aplicación Flask
app = Flask(__name__)

# Configuración sensible mediante variables de entorno.
# NO guardar credenciales ni webhooks directamente en el repositorio.
WEBHOOK_URL = os.getenv("NEXUS_TEAMS_WEBHOOK", "")
ADMIN_USER = os.getenv("NEXUS_ADMIN_USER", "")
ADMIN_PASSWORD = os.getenv("NEXUS_ADMIN_PASSWORD", "")

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "central_security_alerts.log")
alertas_recientes = []

# Ruta base para encontrar los scripts en la carpeta blue_team/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def requiere_autenticacion():
    """Protege acciones administrativas con HTTP Basic Auth."""
    if not ADMIN_USER or not ADMIN_PASSWORD:
        return jsonify({
            "error": "Autenticación administrativa no configurada en el servidor."
        }), 503

    auth = request.authorization
    if not auth:
        return Response(
            "Autenticación requerida",
            401,
            {"WWW-Authenticate": 'Basic realm="NexusSIEM Blue Team"'},
        )

    usuario_ok = hmac.compare_digest(auth.username or "", ADMIN_USER)
    password_ok = hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)

    if not (usuario_ok and password_ok):
        return Response(
            "Credenciales inválidas",
            401,
            {"WWW-Authenticate": 'Basic realm="NexusSIEM Blue Team"'},
        )

    return None


def ip_valida(ip):
    """Valida una IP antes de usarla en una regla de firewall."""
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


def bloquear_ip(ip):
    """Bloquea una IP a nivel de firewall sin usar shell=True."""
    direccion = ip_valida(ip)
    if direccion is None:
        return "IP inválida; no se aplicó bloqueo."

    try:
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", str(direccion), "-j", "DROP"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )

        if check.returncode != 0:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", str(direccion), "-j", "DROP"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=5,
            )
            return f"IP {direccion} bloqueada"

    except subprocess.TimeoutExpired:
        return "Error: operación de firewall agotó el tiempo de espera."
    except subprocess.CalledProcessError as e:
        return f"Error aplicando regla de firewall: {e}"

    return "Ya estaba bloqueada"


def obtener_geolocalizacion(ip):
    """Consulta la ubicación geográfica de la IP usando una API pública y ligera."""
    direccion = ip_valida(ip)

    if direccion is None or direccion.is_loopback or direccion.is_private:
        return "Local / Red Interna"

    try:
        response = requests.get(
            f"http://ip-api.com/json/{direccion}?fields=status,country,city",
            timeout=2,
        )
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
    """Envía una Adaptive Card a Power Automate/Teams si el webhook está configurado."""
    if not WEBHOOK_URL:
        logging.warning("NEXUS_TEAMS_WEBHOOK no está configurado; alerta no enviada a Teams.")
        return

    color_titulo = (
        "attention" if nivel == "CRITICAL"
        else ("warning" if nivel == "WARNING" else "accent")
    )
    icono = "🚨" if nivel == "CRITICAL" else ("⚠️" if nivel == "WARNING" else "ℹ️")

    ubicacion = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
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
                            "color": color_titulo,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Sensor:", "value": fuente},
                                {"title": "Detalle:", "value": mensaje},
                                {"title": "IP Atacante:", "value": ip_atacante if ip_atacante else "N/A"},
                                {"title": "Geolocalización:", "value": ubicacion},
                                {"title": "Firewall:", "value": accion},
                                {"title": "Hora:", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                            ],
                        },
                    ],
                },
            }
        ],
    }

    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=3)
        if response.status_code not in [200, 202]:
            logging.error(f"Teams respondió con código inesperado: {response.status_code}")
    except Exception as e:
        logging.error(f"Error enviando alerta a Teams: {e}")


@app.route("/api/alert", methods=["POST"])
def recibir_alerta():
    """Recibe alertas desde procesos locales de NexusSIEM."""
    # Las alertas locales no necesitan autenticación adicional.
    # Las solicitudes externas deben autenticarse.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        auth_error = requiere_autenticacion()
        if auth_error:
            return auth_error

    datos = request.get_json(silent=True)
    if not datos:
        return jsonify({"error": "Payload inválido"}), 400

    fuente = str(datos.get("source", "Desconocido"))[:100]
    nivel = str(datos.get("level", "INFO"))[:20].upper()
    mensaje = str(datos.get("message", "Sin detalles"))[:1000]
    ip_atacante = datos.get("ip_to_block")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ip_atacante is not None and ip_valida(ip_atacante) is None:
        return jsonify({"error": "ip_to_block no es una dirección IP válida"}), 400

    ubicacion_atacante = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"
    accion_tomada = bloquear_ip(ip_atacante) if ip_atacante else "Ninguna"

    if ip_atacante:
        mensaje_log = (
            f"{mensaje} | IP: {ip_atacante} "
            f"({ubicacion_atacante}) | Acción: {accion_tomada}"
        )
    else:
        mensaje_log = mensaje

    log_msg = f"{fuente} | {mensaje_log}"

    if nivel == "CRITICAL":
        logging.critical(log_msg)
    elif nivel == "WARNING":
        logging.warning(log_msg)
    else:
        logging.info(log_msg)

    alertas_recientes.insert(
        0,
        {
            "tiempo": timestamp,
            "fuente": fuente,
            "nivel": nivel,
            "mensaje": mensaje,
            "accion": accion_tomada,
            "ubicacion": ubicacion_atacante,
        },
    )

    if len(alertas_recientes) > 50:
        alertas_recientes.pop()

    if nivel in ["WARNING", "CRITICAL"]:
        enviar_webhook_teams(
            fuente, nivel, mensaje, accion_tomada, ip_atacante
        )

    return jsonify({"status": "ok"}), 200


@app.route("/api/run/<herramienta>", methods=["POST"])
def ejecutar_herramienta(herramienta):
    """Dispara herramientas administrativas del Blue Team."""
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    try:
        if herramienta == "firewall":
            script_path = os.path.join(BASE_DIR, "firewall_hardening.sh")
            subprocess.Popen(["sudo", "bash", script_path])
            mensaje = "Hardening de firewall UFW ejecutado."

        elif herramienta == "audit":
            launcher_path = os.path.join(BASE_DIR, "atom_launcher.py")
            subprocess.Popen(["python3", launcher_path])
            mensaje = "Auditoría del sistema iniciada con el framework Atom."

        elif herramienta == "sniffer":
            script_path = os.path.join(BASE_DIR, "sniffer_defense.py")
            subprocess.Popen(["sudo", "python", script_path])
            mensaje = "Sniffer de red (IDS) activado en segundo plano."

        else:
            return jsonify({"error": "Herramienta no reconocida"}), 400

        requests.post(
            "http://127.0.0.1:5000/api/alert",
            json={
                "source": "Web Dashboard",
                "level": "INFO",
                "message": mensaje,
            },
            timeout=3,
        )

        return jsonify({"status": "ok", "message": mensaje}), 200

    except Exception as e:
        logging.exception("Error ejecutando herramienta")
        return jsonify({"error": "No se pudo ejecutar la herramienta"}), 500


@app.route("/")
def dashboard():
    return render_template("index.html", alertas=alertas_recientes)


if __name__ == "__main__":
    # Debug desactivado: esta VM está expuesta a la red.
    app.run(host="0.0.0.0", port=5000, debug=False)
