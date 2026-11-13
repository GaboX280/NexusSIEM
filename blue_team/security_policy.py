#!/usr/bin/env python3
"""Política central de allowlist y bloqueo de direcciones IP para NexusSIEM."""

import ipaddress
import os
import subprocess


# La IP de laboratorio queda siempre permitida. Se pueden añadir otras mediante
# NEXUSSIEM_WHITELIST_IPS, separadas por comas.
DEFAULT_WHITELIST = {"200.105.99.21"}


def _load_whitelist():
    allowed = {ipaddress.ip_address(value) for value in DEFAULT_WHITELIST}
    configured = os.getenv("NEXUSSIEM_WHITELIST_IPS", "")
    for value in configured.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            allowed.add(ipaddress.ip_address(value))
        except ValueError:
            # Una entrada incorrecta no debe detener los sensores.
            continue
    return allowed


def ip_valida(value):
    """Devuelve un objeto IPv4Address/IPv6Address o None."""
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def ip_permitida(value):
    """Indica si una dirección pertenece a la allowlist de NexusSIEM."""
    address = ip_valida(value)
    return address is not None and address in _load_whitelist()


def bloquear_ip(value, motivo="Actividad sospechosa"):
    """Aplica y verifica un DROP, respetando siempre la allowlist."""
    address = ip_valida(value)
    if address is None:
        return "ERROR: dirección IP inválida; no se aplicó bloqueo."

    if ip_permitida(address):
        return (
            f"WHITELISTED: {address} está permitida; "
            "actividad registrada y bloqueo automático omitido."
        )

    firewall = "iptables" if address.version == 4 else "ip6tables"
    base_command = ["sudo", firewall]
    check_command = base_command + [
        "-C", "INPUT", "-s", str(address), "-j", "DROP"
    ]

    try:
        check = subprocess.run(
            check_command,
            capture_output=True,
            text=True,
            timeout=5,
        )

        if check.returncode == 0:
            return f"ALREADY_BLOCKED: {address} ya tenía una regla DROP."

        if check.returncode != 1:
            detail = check.stderr.strip() or f"código {check.returncode}"
            return f"ERROR: no se pudo consultar iptables: {detail}"

        subprocess.run(
            base_command + ["-A", "INPUT", "-s", str(address), "-j", "DROP"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )

        verification = subprocess.run(
            check_command,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if verification.returncode == 0:
            return f"BLOCKED: {address} bloqueada por: {motivo}."

        detail = verification.stderr.strip() or "la regla no apareció en la verificación"
        return f"ERROR: no se pudo confirmar el bloqueo de {address}: {detail}"

    except subprocess.TimeoutExpired:
        return "ERROR: la operación de firewall agotó el tiempo de espera."
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if error.stderr else str(error)
        return f"ERROR: iptables no pudo aplicar el bloqueo: {detail}"
    except OSError as error:
        return f"ERROR: no se pudo ejecutar el firewall: {error}"
