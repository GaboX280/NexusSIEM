#!/usr/bin/env python3
"""SSH failed-login monitor with validated, shell-free firewall response."""
from collections import defaultdict
import ipaddress
import logging
import re
import subprocess
import time

logging.basicConfig(
    filename="ssh_defender.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

LIMITE_FALLOS = 5
VENTANA_TIEMPO = 60
intentos_fallidos = defaultdict(list)
PATRON_IP = re.compile(r"(?:Failed password|Invalid user).*?from\s+([0-9a-fA-F:.]+)")


def ip_bloqueable(ip_atacante):
    """Parse and reject special-purpose addresses before firewall changes."""
    try:
        ip = ipaddress.ip_address(ip_atacante)
    except (ValueError, TypeError):
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return None
    return ip


def bloquear_ip(ip_atacante):
    """Apply a validated firewall rule without shell interpolation."""
    ip = ip_bloqueable(ip_atacante)
    if ip is None:
        logging.warning("Bloqueo SSH rechazado para IP inválida/especial: %r", ip_atacante)
        return False

    check = ["iptables", "-C", "INPUT", "-s", str(ip), "-j", "DROP"]
    add = ["iptables", "-A", "INPUT", "-s", str(ip), "-j", "DROP"]
    try:
        result = subprocess.run(check, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0:
            print("[*] La IP %s ya está bloqueada." % ip)
            return True
        result = subprocess.run(add, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            logging.error("iptables no pudo bloquear %s: %s", ip, result.stderr.strip())
            return False
        mensaje = "[BLOQUEO AUTOMÁTICO] IP bloqueada por fuerza bruta SSH: %s" % ip
        print("\033[91m\n[!] %s\033[0m" % mensaje)
        logging.critical(mensaje)
        return True
    except (OSError, subprocess.TimeoutExpired):
        logging.exception("Error ejecutando iptables para %s.", ip)
        return False


def analizar_linea(linea):
    """Extract IPv4/IPv6 source addresses from failed SSH authentication events."""
    coincidencia = PATRON_IP.search(linea)
    if not coincidencia:
        return
    ip_atacante = coincidencia.group(1).strip("[]")
    try:
        ipaddress.ip_address(ip_atacante)
    except ValueError:
        return

    tiempo_actual = time.monotonic()
    intentos_fallidos[ip_atacante] = [
        t for t in intentos_fallidos[ip_atacante] if tiempo_actual - t < VENTANA_TIEMPO
    ]
    intentos_fallidos[ip_atacante].append(tiempo_actual)
    fallos_recientes = len(intentos_fallidos[ip_atacante])
    print("[*] Intento fallido SSH detectado desde %s (total reciente: %s)" % (ip_atacante, fallos_recientes))

    if fallos_recientes >= LIMITE_FALLOS:
        logging.error("Posible ataque de fuerza bruta SSH desde %s.", ip_atacante)
        bloquear_ip(ip_atacante)
        intentos_fallidos[ip_atacante].clear()


def iniciar_monitoreo():
    print("=" * 60)
    print("  BLUE TEAM: SSH Defender (Prevención de Fuerza Bruta)")
    print("=" * 60)
    print("[*] Escuchando eventos SSH mediante journalctl.")
    print("[*] Presiona Ctrl+C para detener.")
    # Some distributions use sshd rather than ssh as the systemd unit.
    comando = ["journalctl", "-f", "-n", "0", "-u", "ssh", "-u", "sshd"]
    proceso = None
    try:
        proceso = subprocess.Popen(
            comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        if proceso.stdout is None:
            raise RuntimeError("No se pudo abrir la salida de journalctl.")
        for linea in proceso.stdout:
            analizar_linea(linea.strip())
    except (OSError, RuntimeError):
        logging.exception("No se pudo iniciar journalctl.")
        print("[-] No se pudo iniciar journalctl; revise permisos y disponibilidad.")
    except KeyboardInterrupt:
        print("\n[*] Monitoreo SSH detenido.")
    finally:
        if proceso and proceso.poll() is None:
            proceso.terminate()
            try:
                proceso.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proceso.kill()


if __name__ == "__main__":
    iniciar_monitoreo()
