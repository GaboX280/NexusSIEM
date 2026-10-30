#!/usr/bin/env python3
"""NexusSIEM dashboard and alert API."""
from datetime import datetime
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import subprocess

import requests
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

WEBHOOK_URL = os.getenv("NEXUS_TEAMS_WEBHOOK", "")
ADMIN_USER = os.getenv("NEXUS_ADMIN_USER", "")
ADMIN_PASSWORD = os.getenv("NEXUS_ADMIN_PASSWORD", "")
ALERT_TOKEN = os.getenv("NEXUS_ALERT_TOKEN", "")

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "central_security_alerts.log")
alertas_recientes = []
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ATOM_REPORTS_DIR = Path.home() / "Atom-Hardening" / "reports"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def requiere_autenticacion():
    """Protect dashboard and administrative routes with HTTP Basic Auth."""
    if not ADMIN_USER or not ADMIN_PASSWORD:
        return jsonify({"error": "Autenticación administrativa no configurada."}), 503

    auth = request.authorization
    if not auth:
        return Response(
            "Autenticación requerida", 401,
            {"WWW-Authenticate": 'Basic realm="NexusSIEM Blue Team"'},
        )

    usuario_ok = hmac.compare_digest(auth.username or "", ADMIN_USER)
    password_ok = hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)
    if not (usuario_ok and password_ok):
        return Response(
            "Credenciales inválidas", 401,
            {"WWW-Authenticate": 'Basic realm="NexusSIEM Blue Team"'},
        )
    return None


def requiere_token_alertas():
    """Authenticate sensor-to-SIEM events; localhost is not implicitly trusted."""
    if not ALERT_TOKEN:
        return jsonify({"error": "NEXUS_ALERT_TOKEN no está configurado."}), 503

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, ALERT_TOKEN):
        return jsonify({"error": "Token de alertas inválido o ausente."}), 401
    return None


def clasificacion_atom(score):
    """Normalize Atom's score classification for the dashboard."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0
    if score >= 90:
        return "EXCELENTE (90-100)"
    if score >= 75:
        return "BUENO (75-89)"
    if score >= 50:
        return "MODERADO (50-74)"
    return "CRITICO (0-49)"


def cargar_ultimo_reporte_atom():
    """Load the newest valid JSON report produced by Atom."""
    if not ATOM_REPORTS_DIR.is_dir():
        return None

    try:
        reportes = sorted(
            ATOM_REPORTS_DIR.glob("reporte_atom_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        logging.exception("No se pudo listar los reportes de Atom.")
        return None

    for reporte_path in reportes:
        try:
            with reporte_path.open("r", encoding="utf-8") as archivo:
                contenido = json.load(archivo)
            if not isinstance(contenido, dict):
                continue
            reporte = contenido.get("report", {})
            if not isinstance(reporte, dict):
                continue
            summary = reporte.get("summary", {})
            findings = reporte.get("findings", [])
            if not isinstance(summary, dict) or not isinstance(findings, list):
                continue
            summary = dict(summary)
            summary["rating"] = clasificacion_atom(summary.get("score", 0))
            return {
                "filename": reporte_path.name,
                "generated": reporte.get("generated"),
                "summary": summary,
                "findings": findings,
            }
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            logging.exception("No se pudo leer el reporte de Atom: %s", reporte_path)
    return None


def ip_valida(ip):
    """Return a parsed IP address or None."""
    if not isinstance(ip, str) or not ip or len(ip) > 45:
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def ip_bloqueable(ip):
    """Reject invalid/special-purpose addresses before firewall changes."""
    direccion = ip_valida(ip)
    if direccion is None:
        return None
    if (
        direccion.is_loopback
        or direccion.is_unspecified
        or direccion.is_multicast
        or direccion.is_link_local
        or direccion.is_reserved
    ):
        return None
    return direccion


def bloquear_ip(ip):
    """Apply an explicit firewall block without a shell and with a timeout."""
    direccion = ip_bloqueable(ip)
    if direccion is None:
        return "Bloqueo rechazado: IP inválida o especial."

    # Require non-interactive, explicitly configured sudo access when Flask is not root.
    binary = "ip6tables" if direccion.version == 6 else "iptables"
    regla = ["sudo", "-n", binary, "-C", "INPUT", "-s", str(direccion), "-j", "DROP"]
    agregar = ["sudo", "-n", binary, "-A", "INPUT", "-s", str(direccion), "-j", "DROP"]
    try:
        check = subprocess.run(
            regla, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False,
        )
        if check.returncode == 0:
            return f"IP {direccion} ya estaba bloqueada"

        result = subprocess.run(
            agregar, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False,
        )
        if result.returncode != 0:
            logging.error("iptables rechazó el bloqueo de %s: %s", direccion, result.stderr.strip())
            return "Error aplicando regla de firewall; consulte los logs."
        return f"IP {direccion} bloqueada"
    except subprocess.TimeoutExpired:
        logging.exception("Timeout al aplicar regla de firewall para %s", direccion)
        return "Error: operación de firewall agotó el tiempo de espera."
    except OSError:
        logging.exception("No se pudo ejecutar iptables.")
        return "Error: iptables no está disponible o faltan permisos."


def obtener_geolocalizacion(ip):
    """Fetch approximate public-IP location over HTTPS, without blocking alert handling for long."""
    direccion = ip_valida(ip)
    if direccion is None or not direccion.is_global:
        return "Local / No pública"
    try:
        response = requests.get(
            f"https://ipapi.co/{direccion}/json/",
            timeout=2,
        )
        if response.ok:
            data = response.json()
            pais = data.get("country_name", "Desconocido")
            ciudad = data.get("city", "")
            return f"{pais}, {ciudad}" if ciudad else pais
    except (requests.RequestException, ValueError):
        logging.warning("No se pudo consultar geolocalización para %s.", direccion)
    return "Desconocido"


def enviar_webhook_teams(fuente, nivel, mensaje, accion, ip_atacante=None):
    """Send a Teams Adaptive Card when a webhook is configured."""
    if not WEBHOOK_URL:
        logging.info("NEXUS_TEAMS_WEBHOOK no está configurado; alerta no enviada a Teams.")
        return

    color_titulo = "attention" if nivel == "CRITICAL" else ("warning" if nivel == "WARNING" else "accent")
    icono = "🚨" if nivel == "CRITICAL" else ("⚠️" if nivel == "WARNING" else "ℹ️")
    ubicacion = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.2",
                "body": [
                    {"type": "TextBlock", "text": f"{icono} Alerta de Seguridad: {nivel}",
                     "weight": "Bolder", "size": "Medium", "color": color_titulo},
                    {"type": "FactSet", "facts": [
                        {"title": "Sensor:", "value": fuente},
                        {"title": "Detalle:", "value": mensaje},
                        {"title": "IP:", "value": ip_atacante or "N/A"},
                        {"title": "Geolocalización:", "value": ubicacion},
                        {"title": "Firewall:", "value": accion},
                        {"title": "Hora:", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                    ]},
                ],
            },
        }],
    }
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=3)
        if response.status_code not in (200, 202):
            logging.error("Teams respondió con código inesperado: %s", response.status_code)
    except requests.RequestException:
        logging.exception("Error enviando alerta a Teams.")


def registrar_alerta(fuente, nivel, mensaje, ip_atacante=None, accion_tomada="Ninguna", ubicacion=None):
    """Log and retain an already validated event."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ubicacion = ubicacion or (obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A")
    log_msg = f"{fuente} | {mensaje}"
    if ip_atacante:
        log_msg += f" | IP: {ip_atacante} ({ubicacion}) | Acción: {accion_tomada}"

    if nivel == "CRITICAL":
        logging.critical(log_msg)
    elif nivel == "WARNING":
        logging.warning(log_msg)
    else:
        logging.info(log_msg)

    alertas_recientes.insert(0, {
        "tiempo": timestamp, "fuente": fuente, "nivel": nivel,
        "mensaje": mensaje, "accion": accion_tomada, "ubicacion": ubicacion,
    })
    del alertas_recientes[50:]
    if nivel in ("WARNING", "CRITICAL"):
        enviar_webhook_teams(fuente, nivel, mensaje, accion_tomada, ip_atacante)


@app.route("/api/alert", methods=["POST"])
def recibir_alerta():
    """Receive authenticated sensor events; blocking requires explicit critical intent."""
    auth_error = requiere_token_alertas()
    if auth_error:
        return auth_error

    datos = request.get_json(silent=True)
    if not isinstance(datos, dict):
        return jsonify({"error": "El cuerpo debe ser un objeto JSON válido."}), 400

    fuente = datos.get("source", "Desconocido")
    nivel = str(datos.get("level", "INFO")).upper()
    mensaje = datos.get("message", "Sin detalles")
    ip_atacante = datos.get("ip_to_block")

    if not isinstance(fuente, str) or not isinstance(mensaje, str):
        return jsonify({"error": "source y message deben ser texto."}), 400
    if nivel not in ("INFO", "WARNING", "CRITICAL"):
        return jsonify({"error": "level debe ser INFO, WARNING o CRITICAL."}), 400
    fuente = fuente.strip()[:100] or "Desconocido"
    mensaje = mensaje.strip()[:1000] or "Sin detalles"

    if ip_atacante is not None and ip_valida(ip_atacante) is None:
        return jsonify({"error": "ip_to_block no es una dirección IP válida."}), 400

    accion_tomada = "Ninguna"
    # Never block merely because a payload contains ip_to_block. The sender must
    # explicitly request it, and only CRITICAL events are eligible for auto-response.
    if datos.get("block_ip") is True:
        if nivel != "CRITICAL" or not ip_atacante:
            return jsonify({"error": "El bloqueo requiere level=CRITICAL e ip_to_block válida."}), 400
        accion_tomada = bloquear_ip(ip_atacante)

    ubicacion = obtener_geolocalizacion(ip_atacante) if ip_atacante else "N/A"
    registrar_alerta(fuente, nivel, mensaje, ip_atacante, accion_tomada, ubicacion)
    return jsonify({"status": "ok", "action": accion_tomada}), 200


@app.route("/api/state", methods=["GET"])
def estado_dashboard():
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error
    return jsonify({
        "status": "ok", "alerts": alertas_recientes,
        "audit": cargar_ultimo_reporte_atom(),
    }), 200


@app.route("/api/audit/latest", methods=["GET"])
def ultimo_reporte_atom():
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error
    reporte = cargar_ultimo_reporte_atom()
    if reporte is None:
        return jsonify({"status": "not_found", "message": "Todavía no existe un reporte de Atom."}), 404
    return jsonify({"status": "ok", "report": reporte}), 200


@app.route("/api/run/<herramienta>", methods=["POST"])
def ejecutar_herramienta(herramienta):
    """Run allow-listed administrative tools after authentication."""
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    comandos = {
        "firewall": (["sudo", "bash", os.path.join(BASE_DIR, "firewall_hardening.sh")],
                     "Hardening de firewall UFW solicitado."),
        "audit": (["python3", os.path.join(BASE_DIR, "atom_launcher.py")],
                  "Auditoría del sistema iniciada con Atom."),
        "sniffer": (["sudo", "python3", os.path.join(BASE_DIR, "sniffer_defense.py")],
                    "Sniffer de red (IDS) solicitado."),
    }
    if herramienta not in comandos:
        return jsonify({"error": "Herramienta no reconocida."}), 400

    comando, mensaje = comandos[herramienta]
    try:
        subprocess.Popen(
            comando, cwd=BASE_DIR, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        logging.exception("No se pudo iniciar la herramienta %s.", herramienta)
        return jsonify({"error": "No se pudo ejecutar la herramienta."}), 500

    registrar_alerta("Web Dashboard", "INFO", mensaje)
    return jsonify({"status": "ok", "message": mensaje}), 202


@app.route("/")
def dashboard():
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error
    return render_template(
        "index.html", alertas=alertas_recientes,
        reporte_atom=cargar_ultimo_reporte_atom(),
    )


if __name__ == "__main__":
    # Loopback-only by default. For remote use, place behind HTTPS and configure NEXUS_HOST explicitly.
    host = os.getenv("NEXUS_HOST", "127.0.0.1")
    port = int(os.getenv("NEXUS_PORT", "5000"))
    if host not in ("127.0.0.1", "::1", "localhost"):
        logging.warning("NexusSIEM está escuchando en %s; asegure HTTPS mediante un proxy inverso.", host)
    app.run(host=host, port=port, debug=False)
