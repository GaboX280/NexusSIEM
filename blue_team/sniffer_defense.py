#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, ARP
import subprocess
import logging
from collections import defaultdict
import time
# Configuración de logging
logging.basicConfig(
    filename="intrusion_defense.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
# Estructuras de control para análisis de comportamiento
puertos_escaneados = defaultdict(set)      # Para escaneos de puertos (Nmap -sS)
conteo_syn_flood = defaultdict(list)       # Para control de tasas de SYN packets
tabla_arp_conocida = {}                    # Para detección de ARP Spoofing
# Umbrales de alerta y bloqueo
UMBRAL_PUERTOS_DISTINTOS = 12  # Si toca más de 12 puertos distintos -> Escaneo Nmap
UMBRAL_SYN_RATE = 30           # Más de 30 paquetes SYN en el intervalo de tiempo
VENTANA_TIEMPO = 5.0           # Segundos para la ventana de tasa SYN
## FUNCIONES DEL PROGRAMA ##
# Sistema de bloqueo automático de IPs maliciosas usando iptables
def bloquear_ip(ip_atacante, motivo):
    """Bloquea automáticamente la IP maliciosa usando iptables de Linux."""
    try:
        # Verificar si la regla ya existe para evitar duplicados
        verificacion = subprocess.run(
            f"sudo iptables -C INPUT -s {ip_atacante} -j DROP", 
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if verificacion.returncode != 0:
            # Ejecutar bloqueo en iptables
            subprocess.run(f"sudo iptables -A INPUT -s {ip_atacante} -j DROP", shell=True, check=True)
            mensaje = f"[BLOQUEO AUTOMÁTICO] IP bloqueada por '{motivo}': {ip_atacante}"
            print(f"\033[91m\n[!] {mensaje}\033[0m")
            logging.critical(mensaje)
        else:
            print(f"[*] La IP {ip_atacante} ya se encontraba previamente bloqueada.")
    except Exception as e:
        print(f"[-] Error crítico al aplicar iptables para {ip_atacante}: {e}")
# Analizador de trafico TCP para detectar escaneo de puertos y SYN Flood
def analizar_trafico_tcp(paquete):
    """Analiza paquetes IP/TCP en busca de patrones ofensivos."""
    if paquete.haslayer(IP) and paquete.haslayer(TCP):
        ip_origen = paquete[IP].src
        puerto_destino = paquete[TCP].dport
        flags = paquete[TCP].flags
        tiempo_actual = time.time()

        # Detección 1: Escaneo de puertos (SYN Scan estilo Nmap -sS)
        if flags == 'S':  # Paquete SYN puro
            puertos_escaneados[ip_origen].add(puerto_destino)
            total_puertos = len(puertos_escaneados[ip_origen])

            if total_puertos > UMBRAL_PUERTOS_DISTINTOS:
                alerta = f"Escaneo de puertos detectado (Nmap). IP origen: {ip_origen} afectó {total_puertos} puertos."
                logging.warning(alerta)
                bloquear_ip(ip_origen, "Escaneo de Puertos / Nmap")
                # Limpiamos el registro de esa IP para evitar bucles constantes
                puertos_escaneados[ip_origen].clear()

            # Detección 2: Protección contra SYN Flood (Denegación de servicio)
            # Limpiamos registros fuera de la ventana de tiempo
            conteo_syn_flood[ip_origen] = [t for t in conteo_syn_flood[ip_origen] if tiempo_actual - t < VENTANA_TIEMPO]
            conteo_syn_flood[ip_origen].append(tiempo_actual)

            if len(conteo_syn_flood[ip_origen]) > UMBRAL_SYN_RATE:
                alerta = f"Ataque DoS (SYN Flood) detectado desde la IP: {ip_origen}"
                logging.error(alerta)
                bloquear_ip(ip_origen, "SYN Flood Attack")
                conteo_syn_flood[ip_origen].clear()
# Analizador de trafico ARP para detectar suplantación de identidad (ARP Spoofing)
def analizar_trafico_arp(paquete):
    """Detecta posibles ataques de ARP Spoofing en la red local."""
    if paquete.haslayer(ARP):
        # ARP Opcode 2 corresponde a una respuesta ARP (ARP Reply)
        if paquete[ARP].op == 2:
            ip_real = paquete[ARP].psrc
            mac_recibida = paquete[ARP].hwsrc

            # Si ya teníamos registrada una MAC para esta IP y cambia abruptamente, hay suplantación
            if ip_real in tabla_arp_conocida:
                if tabla_arp_conocida[ip_real] != mac_recibida:
                    alerta = f"¡ALERTA DE ARP SPOOFING! La IP {ip_real} cambió su MAC de {tabla_arp_conocida[ip_real]} a {mac_recibida}"
                    print(f"\033[93m\n[!] {alerta}\033[0m")
                    logging.critical(alerta)
            else:
                tabla_arp_conocida[ip_real] = mac_recibida
# Función principal que enruta el procesamiento de paquetes
def procesar_paquete(paquete):
    """Función enrutadora que procesa cada paquete capturado por Scapy."""
    analizar_trafico_tcp(paquete)
    analizar_trafico_arp(paquete)
# Función de inicio del IDS y sistema de defensa activa
def iniciar_ids():
    print("=" * 60)
    print("  BLUE TEAM: IDS & Active Defense (Scapy + Iptables)")
    print("=" * 60)
    print("[*] Monitoreando interfaces de red en busca de anomalías...")
    print("[*] Reglas activas: Detección de Nmap, SYN Flood y ARP Spoofing.")
    print("[*] Presiona Ctrl+C para detener el sistema de defensa.\n")
    
    try:
        # Captura general de paquetes de red de forma continua
        sniff(prn=procesar_paquete, store=False)
    except PermissionError:
        print("\n[-] Error: Se requieren permisos de superusuario (sudo) para capturar tráfico y modificar iptables.")
    except KeyboardInterrupt:
        print("\n\n[*] Sistema IDS detenido de forma segura. Logs guardados en 'intrusion_defense.log'.")
# Inicio del programa
if __name__ == "__main__":
    iniciar_ids()