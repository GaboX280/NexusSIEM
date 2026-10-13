#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, Response
from dotenv import load_dotenv
import hmac
import ipaddress
import logging
import subprocess
import requests
import os
import json
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
BASE_DIR = str(APP_DIR.parent)
PROJECT_ROOT = APP_DIR.parent.parent

# La configuración del proceso (por ejemplo, systemd) tiene prioridad sobre .env.
# El archivo .env es local y nunca debe subirse al repositorio.
load_dotenv(PROJECT_ROOT / ".env", override=False)

# Por seguridad, la aplicación asume producción si el entorno no está definido.
NEXUS_ENV = os.getenv("NEXUS_ENV", "production").strip().lower()
DEMO_MODE = NEXUS_ENV in {"development", "dev", "demo", "test"}
WEBHOOK_URL = os.getenv("NEXUS_TEAMS_WEBHOOK", "")
ADMIN_USER = os.getenv("NEXUS_ADMIN_USER", "")
ADMIN_PASSWORD = os.getenv("NEXUS_ADMIN_PASSWORD", "")
HOST = os.getenv("NEXUS_HOST", "127.0.0.1" if DEMO_MODE else "0.0.0.0")
PORT = int(os.getenv("NEXUS_PORT", "5000"))

app = Flask(__name__)
LOG_FILE = str(APP_DIR.parent / "central_security_alerts.log")
alertas_recientes = []
ATOM_REPORTS_DIR = Path.home() / "Atom-Hardening" / "reports"

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


def clasificacion_atom(score):
    """Normaliza la clasificación de Atom para la vista web."""
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
    """Carga el reporte más reciente o uno sintético en modo de demostración."""
    if DEMO_MODE:
        return {
            "filename": "reporte_atom_demo.json",
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "score": 82,
                "status": {"PASS": 8, "WARNING": 2, "FAIL": 1},
                "total": 11,
                "module": "Atom Demo",
                "rating": clasificacion_atom(82),
            },
            "findings": [
                {
                    "title": "SSH hardening",
                    "category": "Access Control",
                    "status": "PASS",
                    "severity": "LOW",
                    "module": "SSH",
                    "details": "Hallazgo sintético de demostración; no se inspeccionó el sistema.",
                    "recommendation": "En una auditoría real, verificar la configuración SSH efectiva.",
                },
                {
                    "title": "Firewall policy review",
                    "category": "Network Security",
                    "status": "WARNING",
                    "severity": "MEDIUM",
                    "module": "Firewall",
                    "details": "Ejemplo ilustrativo para mostrar el formato de hallazgos.",
                    "recommendation": "Revisar las reglas desde un entorno de laboratorio autorizado.",
                },
                {
                    "title": "Privileged service exposure",
                    "category": "System Hardening",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "module": "Services",
                    "details": "Hallazgo ficticio incluido únicamente para la interfaz de demostración.",
                    "recommendation": "Validar servicios expuestos durante una auditoría real.",
                },
            ],
        }

    if not ATOM_REPORTS_DIR.is_dir():
        return None

    reportes = sorted(
        ATOM_REPORTS_DIR.glob("reporte_atom_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for reporte_path in reportes:
        try:
            with reporte_path.open("r", encoding="utf-8") as archivo:
                contenido = json.load(archivo)

            reporte = contenido.get("report", {})
            summary = reporte.get("summary", {})
            findings = reporte.get("findings", [])

            if not isinstance(summary, dict) or not isinstance(findings, list):
                continue

            summary["rating"] = clasificacion_atom(summary.get("score", 0))

            return {
                "filename": reporte_path.name,
                "generated": reporte.get("generated"),
                "summary": summary,
                "findings": findings,
            }

        except (OSError, json.JSONDecodeError, ValueError):
            logging.exception("No se pudo leer el reporte de Atom: %s", reporte_path)
            continue

    return None


def ip_valida(ip):
    """Valida una IP antes de usarla en una regla de firewall."""
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


def bloquear_ip(ip):
    """Bloquea una IP a nivel de firewall; en modo demo nunca modifica reglas."""
    direccion = ip_valida(ip)
    if direccion is None:
        return "IP inválida; no se aplicó bloqueo."
    if DEMO_MODE:
        return f"SIMULACIÓN: {direccion} no se bloqueó (modo local)."

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
    """Consulta geolocalización solo en producción; demo evita llamadas externas."""
    direccion = ip_valida(ip)

    if DEMO_MODE:
        return "Local / Simulado"
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
    """Envía alertas a Teams solo fuera del modo de demostración."""
    if DEMO_MODE:
        logging.info("Modo demo: alerta no enviada a Teams.")
        return
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


@app.route("/api/state", methods=["GET"])
def estado_dashboard():
    """Entrega el estado del dashboard al operador autenticado."""
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    return jsonify({
        "status": "ok",
        "environment": NEXUS_ENV,
        "demo_mode": DEMO_MODE,
        "alerts": alertas_recientes,
        "audit": cargar_ultimo_reporte_atom(),
    }), 200


@app.route("/api/audit/latest", methods=["GET"])
def ultimo_reporte_atom():
    """Devuelve el último reporte de Atom al operador autenticado."""
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    reporte = cargar_ultimo_reporte_atom()
    if reporte is None:
        return jsonify({
            "status": "not_found",
            "message": "Todavía no existe un reporte de Atom."
        }), 404

    return jsonify({
        "status": "ok",
        "report": reporte,
    }), 200


@app.route("/api/run/<herramienta>", methods=["POST"])
def ejecutar_herramienta(herramienta):
    """Dispara herramientas reales en producción o respuestas sintéticas en demo."""
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    if DEMO_MODE:
        mensajes_demo = {
            "firewall": "SIMULACIÓN: se mostraría el resultado de Firewall Hardening; no se ejecutó sudo ni se modificó el firewall.",
            "audit": "SIMULACIÓN: auditoría Atom de demostración; no se ejecutó ningún escáner del sistema.",
            "sniffer": "SIMULACIÓN: se mostraría la activación del IDS; no se capturó tráfico de red.",
        }
        if herramienta not in mensajes_demo:
            return jsonify({"error": "Herramienta no reconocida"}), 400

        mensaje = mensajes_demo[herramienta]
        alertas_recientes.insert(0, {
            "tiempo": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fuente": "Web Dashboard / Demo",
            "nivel": "INFO",
            "mensaje": mensaje,
            "accion": "Simulado; no se ejecutaron comandos privilegiados",
            "ubicacion": "Local / Simulado",
        })
        del alertas_recientes[50:]
        logging.info("Modo demo: %s", mensaje)
        return jsonify({
            "status": "ok",
            "demo_mode": True,
            "message": mensaje,
        }), 200

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
    auth_error = requiere_autenticacion()
    if auth_error:
        return auth_error

    reporte_atom = cargar_ultimo_reporte_atom()

    return render_template(
        "index.html",
        alertas=alertas_recientes,
        reporte_atom=reporte_atom,
        demo_mode=DEMO_MODE,
        environment_label="LOCAL / DEMO" if DEMO_MODE else "AZURE / LINUX / PRODUCTION",
        node_label="Local / Demo" if DEMO_MODE else "BlueTeam / Azure",
    )


if __name__ == "__main__":
    # Desarrollo queda limitado a localhost; producción conserva el bind de Azure.
    app.run(host=HOST, port=PORT, debug=False)
