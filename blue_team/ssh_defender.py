#!/usr/bin/env python3
import subprocess
import re
import time
import logging
from collections import defaultdict

from security_policy import bloquear_ip as aplicar_bloqueo, ip_permitida

logging.basicConfig(
    filename="ssh_defender.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

LIMITE_FALLOS = 5
VENTANA_TIEMPO = 60
intentos_fallidos = defaultdict(list)


def bloquear_ip(ip_atacante):
    """Aplica la política central de bloqueo y registra el resultado."""
    resultado = aplicar_bloqueo(ip_atacante, "Fuerza bruta SSH")
    if resultado.startswith("BLOCKED:"):
        logging.critical(resultado)
        print(f"\033[91m[!] {resultado}\033[0m")
    elif resultado.startswith("WHITELISTED:"):
        logging.warning(resultado)
        print(f"[*] {resultado}")
    elif resultado.startswith("ERROR:"):
        logging.error(resultado)
        print(f"[-] {resultado}")
    else:
        logging.warning(resultado)
        print(f"[*] {resultado}")
    return resultado


def analizar_linea(linea):
    """Detecta fallos SSH y cuenta intentos por IP."""
    patron_ip = re.search(
        r"(Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)",
        linea,
    )
    if not patron_ip:
        return

    ip_atacante = patron_ip.group(2)
    tiempo_actual = time.time()
    intentos_fallidos[ip_atacante] = [
        timestamp for timestamp in intentos_fallidos[ip_atacante]
        if tiempo_actual - timestamp < VENTANA_TIEMPO
    ]
    intentos_fallidos[ip_atacante].append(tiempo_actual)
    fallos_recientes = len(intentos_fallidos[ip_atacante])

    estado = "WHITELISTED" if ip_permitida(ip_atacante) else "MONITORED"
    print(
        f"[*] Intento fallido SSH desde {ip_atacante} "
        f"(Total reciente: {fallos_recientes}, Estado: {estado})"
    )

    if fallos_recientes >= LIMITE_FALLOS:
        alerta = f"Ataque de fuerza bruta detectado desde {ip_atacante}."
        logging.error(alerta)
        bloquear_ip(ip_atacante)
        intentos_fallidos[ip_atacante].clear()


def iniciar_monitoreo():
    print("=" * 60)
    print("  BLUE TEAM: SSH Defender (Prevención de Fuerza Bruta)")
    print("=" * 60)
    print(f"[*] Escuchando logs SSH. Umbral: {LIMITE_FALLOS} fallos/{VENTANA_TIEMPO}s.")
    print("[*] La allowlist se mantiene monitorizada, pero no se bloquea.")
    print("[*] Presiona Ctrl+C para detener.\n")

    comando = ["journalctl", "-u", "ssh.service", "-f", "-n", "0"]

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for linea in proceso.stdout:
            analizar_linea(linea.strip())
    except PermissionError:
        print("\n[-] No se pudieron leer los logs. Ejecuta con los permisos adecuados.")
    except KeyboardInterrupt:
        print("\n[*] Monitoreo SSH detenido. Revisa 'ssh_defender.log'.")
    finally:
        if "proceso" in locals() and proceso.poll() is None:
            proceso.terminate()
            proceso.wait(timeout=3)


if __name__ == "__main__":
    iniciar_monitoreo()
