#!/usr/bin/env python3
"""Network IDS with conservative, validated iptables response."""
from collections import defaultdict
import ipaddress
import logging
import subprocess
import time

from scapy.all import ARP, IP, TCP, sniff

logging.basicConfig(
    filename="intrusion_defense.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

puertos_escaneados = defaultdict(set)
conteo_syn_flood = defaultdict(list)
tabla_arp_conocida = {}
UMBRAL_PUERTOS_DISTINTOS = 12
UMBRAL_SYN_RATE = 30
VENTANA_TIEMPO = 5.0


def ip_bloqueable(ip_atacante):
    """Parse and reject special-purpose addresses before firewall changes."""
    try:
        ip = ipaddress.ip_address(ip_atacante)
    except (ValueError, TypeError):
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return None
    return ip


def bloquear_ip(ip_atacante, motivo):
    """Add an iptables DROP rule without invoking a shell."""
    ip = ip_bloqueable(ip_atacante)
    if ip is None:
        logging.warning("Bloqueo rechazado para IP inválida/especial: %r (%s)", ip_atacante, motivo)
        return False

    base = ["iptables", "-C", "INPUT", "-s", str(ip), "-j", "DROP"]
    add = ["iptables", "-A", "INPUT", "-s", str(ip), "-j", "DROP"]
    try:
        check = subprocess.run(base, capture_output=True, text=True, timeout=5, check=False)
        if check.returncode == 0:
            logging.info("La IP %s ya estaba bloqueada.", ip)
            return True
        result = subprocess.run(add, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            logging.error("iptables no pudo bloquear %s: %s", ip, result.stderr.strip())
            return False
        mensaje = "[BLOQUEO AUTOMÁTICO] IP bloqueada por '%s': %s" % (motivo, ip)
        print("\033[91m\n[!] %s\033[0m" % mensaje)
        logging.critical(mensaje)
        return True
    except (OSError, subprocess.TimeoutExpired):
        logging.exception("Error ejecutando iptables para %s.", ip)
        return False


def analizar_trafico_tcp(paquete):
    """Detect SYN scans and high SYN rates in a rolling time window."""
    if not (paquete.haslayer(IP) and paquete.haslayer(TCP)):
        return
    ip_origen = paquete[IP].src
    puerto_destino = paquete[TCP].dport
    flags = paquete[TCP].flags
    tiempo_actual = time.monotonic()

    if flags == "S":
        puertos_escaneados[ip_origen].add(puerto_destino)
        total_puertos = len(puertos_escaneados[ip_origen])
        if total_puertos > UMBRAL_PUERTOS_DISTINTOS:
            alerta = "Escaneo de puertos detectado. IP origen: %s afectó %s puertos." % (ip_origen, total_puertos)
            logging.warning(alerta)
            bloquear_ip(ip_origen, "Escaneo de puertos")
            puertos_escaneados[ip_origen].clear()

        conteo_syn_flood[ip_origen] = [
            t for t in conteo_syn_flood[ip_origen] if tiempo_actual - t < VENTANA_TIEMPO
        ]
        conteo_syn_flood[ip_origen].append(tiempo_actual)
        if len(conteo_syn_flood[ip_origen]) > UMBRAL_SYN_RATE:
            logging.error("Posible SYN flood detectado desde %s.", ip_origen)
            bloquear_ip(ip_origen, "Posible SYN flood")
            conteo_syn_flood[ip_origen].clear()


def analizar_trafico_arp(paquete):
    """Log a possible ARP spoofing event when a known mapping changes."""
    if not paquete.haslayer(ARP) or paquete[ARP].op != 2:
        return
    ip_real = paquete[ARP].psrc
    mac_recibida = paquete[ARP].hwsrc
    if ip_real in tabla_arp_conocida:
        mac_anterior = tabla_arp_conocida[ip_real]
        if mac_anterior != mac_recibida:
            alerta = "Posible ARP spoofing: %s cambió de %s a %s" % (ip_real, mac_anterior, mac_recibida)
            print("\033[93m\n[!] %s\033[0m" % alerta)
            logging.critical(alerta)
            # Update the observed mapping so repeated packets do not flood the log.
            tabla_arp_conocida[ip_real] = mac_recibida
    else:
        tabla_arp_conocida[ip_real] = mac_recibida


def procesar_paquete(paquete):
    analizar_trafico_tcp(paquete)
    analizar_trafico_arp(paquete)


def iniciar_ids():
    print("=" * 60)
    print("  BLUE TEAM: IDS & Active Defense (Scapy + iptables)")
    print("=" * 60)
    print("[*] Monitoreando interfaces de red en busca de anomalías...")
    print("[*] Presiona Ctrl+C para detener.")
    try:
        sniff(prn=procesar_paquete, store=False)
    except PermissionError:
        logging.exception("Permisos insuficientes para capturar tráfico.")
        print("[-] Se requieren permisos adecuados para capturar tráfico.")
    except KeyboardInterrupt:
        print("\n[*] IDS detenido; logs guardados en intrusion_defense.log.")


if __name__ == "__main__":
    iniciar_ids()
