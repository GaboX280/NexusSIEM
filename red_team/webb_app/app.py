#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, Response
import hmac
import ipaddress
import logging
import subprocess
import requests
import os
import json
from datetime import datetime
from pathlib import Path

# Inicializacion de la app de Flask
app = Flask(__name__)

# Configuración sensible mediante variables de entorno.
# NO guardar credenciales ni webhooks directamente en el repositorio.
WEBHOOK_URL = os.getenv("RED_TEAMS_WEBHOOK", "")
ADMIN_USER = os.getenv("RED_TEAM_USER", "")
ADMIN_PASSWORD = os.getenv("RED_TEAM_PASSWORD", "")

# Configuración de logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Funcion para proteger rutas con autenticación básica HTTP
def require_authenthication(func):
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
            {"WWW-Authenticate": 'Basic realm="Login Required AT. Red Team"'}
        )

    # Comparación segura de credenciales usando hmac.compare_digest para prevenir ataques de temporización.
    usuario_ok = hmac.compare_digest(auth.username or "", ADMIN_USER)
    password_ok = hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)


    # Si las credenciales no son válidas, se devuelve un error 401 con un encabezado WWW-Authenticate para indicar que se requiere autenticación.
    if not (usuario_ok and password_ok):
        return Response(
            "Credenciales inválidas",
            401,
            {"WWW-Authenticate": 'Basic realm="Login Failed AT. Red Team"'},
        )

    return None
