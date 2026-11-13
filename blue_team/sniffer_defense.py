#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, ARP
import logging
from collections import defaultdict
import time

from security_policy import bloquear_ip as aplicar_bloqueo

logging.basicConfig(
    filename="intrusion_defense.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

puertos_escaneados = defaultdict(set)
conteo_syn_flood = defaultdict(list)
tabla_arp_conocida = {}

UMBRAL_PUERTOS_DISTINTOS = 12
UMBRAL_SYN_RATE = 30
VENTANA_TIEMPO = 5.0


def bloquear_ip(ip_atacante, motivo):
    """Usa la política central; las IP permitidas nunca reciben DROP."""
    resultado = aplicar_bloqueo(ip_atacante, motivo)
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


def analizar_trafico_tcp(paquete):
    """Analiza paquetes IP/TCP para detectar escaneos y SYN Flood."""
    if not (paquete.haslayer(IP) and paquete.haslayer(TCP)):
        return

    ip_origen = paquete[IP].src
    puerto_destino = paquete[TCP].dport
    flags = paquete[TCP].flags
    tiempo_actual = time.time()

    if flags == "S":
        puertos_escaneados[ip_origen].add(puerto_destino)
        total_puertos = len(puertos_escaneados[ip_origen])

        if total_puertos > UMBRAL_PUERTOS_DISTINTOS:
            alerta = (
                f"Escaneo de puertos detectado (Nmap). IP origen: "
                f"{ip_origen} afectó {total_puertos} puertos."
            )
            logging.warning(alerta)
            bloquear_ip(ip_origen, "Escaneo de Puertos / Nmap")
            puertos_escaneados[ip_origen].clear()

        conteo_syn_flood[ip_origen] = [
            timestamp for timestamp in conteo_syn_flood[ip_origen]
            if tiempo_actual - timestamp < VENTANA_TIEMPO
        ]
        conteo_syn_flood[ip_origen].append(tiempo_actual)

        if len(conteo_syn_flood[ip_origen]) > UMBRAL_SYN_RATE:
            alerta = f"Ataque DoS (SYN Flood) detectado desde la IP: {ip_origen}"
            logging.error(alerta)
            bloquear_ip(ip_origen, "SYN Flood Attack")
            conteo_syn_flood[ip_origen].clear()


def analizar_trafico_arp(paquete):
    """Detecta cambios inesperados de MAC asociados a una dirección IP."""
    if paquete.haslayer(ARP) and paquete[ARP].op == 2:
        ip_real = paquete[ARP].psrc
        mac_recibida = paquete[ARP].hwsrc

        if ip_real in tabla_arp_conocida:
            if tabla_arp_conocida[ip_real] != mac_recibida:
                alerta = (
                    f"¡ALERTA DE ARP SPOOFING! La IP {ip_real} cambió su MAC "
                    f"de {tabla_arp_conocida[ip_real]} a {mac_recibida}"
                )
                print(f"\033[93m[!] {alerta}\033[0m")
                logging.critical(alerta)
        else:
            tabla_arp_conocida[ip_real] = mac_recibida


def procesar_paquete(paquete):
    analizar_trafico_tcp(paquete)
    analizar_trafico_arp(paquete)


def iniciar_ids():
    print("=" * 60)
    print("  BLUE TEAM: IDS & Active Defense (Scapy + Iptables)")
    print("=" * 60)
    print("[*] Monitoreando interfaces de red en busca de anomalías...")
    print("[*] La allowlist sigue monitorizada, pero no se bloquea.")
    print("[*] Presiona Ctrl+C para detener el sistema de defensa.\n")

    try:
        sniff(prn=procesar_paquete, store=False)
    except PermissionError:
        print("\n[-] Se requieren permisos de superusuario.")
    except KeyboardInterrupt:
        print("\n[*] Sistema IDS detenido. Logs guardados en 'intrusion_defense.log'.")


if __name__ == "__main__":
    iniciar_ids()
