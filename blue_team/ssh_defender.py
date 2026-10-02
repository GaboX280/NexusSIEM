#!/usr/bin/env python3
import subprocess
import re
import time
import logging
from collections import defaultdict
# Configuración de logs
logging.basicConfig(
    filename="ssh_defender.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
# Configuración del monitor
LIMITE_FALLOS = 5 # Número de intentos fallidos antes de bloquear
VENTANA_TIEMPO = 60  # Segundos
# Diccionario para almacenar los timestamps de los fallos por IP
intentos_fallidos = defaultdict(list)
## FUNCIONES DEL PROGRAMA ##
# Funcion para bloquear IPs maliciosas usando iptables
def bloquear_ip(ip_atacante):
    """Ejecuta iptables para bloquear la IP y registra la acción."""
    try:
        # Verificar si la IP ya está bloqueada
        verificacion = subprocess.run(
            f"sudo iptables -C INPUT -s {ip_atacante} -j DROP", 
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if verificacion.returncode != 0:
            subprocess.run(f"sudo iptables -A INPUT -s {ip_atacante} -j DROP", shell=True, check=True)
            mensaje = f"[BLOQUEO AUTOMÁTICO] IP bloqueada por fuerza bruta SSH: {ip_atacante}"
            print(f"\033[91m\n[!] {mensaje}\033[0m")
            logging.critical(mensaje)
        else:
            print(f"[*] La IP {ip_atacante} ya está bloqueada.")
    except Exception as e:
        print(f"[-] Error al bloquear la IP {ip_atacante}: {e}")
# Funcion para analizar cada línea de log y detectar intentos fallidos de SSH
def analizar_linea(linea):
    """Busca patrones de fallo de autenticación SSH y extrae la IP."""
    # Expresiones regulares para capturar IPs en "Failed password" o "Invalid user"
    patron_ip = re.search(r"(Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)", linea)
    
    if patron_ip:
        ip_atacante = patron_ip.group(2)
        tiempo_actual = time.time()
        
        # Limpiar registros antiguos fuera de la ventana de tiempo (60 segundos)
        intentos_fallidos[ip_atacante] = [t for t in intentos_fallidos[ip_atacante] if tiempo_actual - t < VENTANA_TIEMPO]
        
        # Registrar el nuevo intento fallido
        intentos_fallidos[ip_atacante].append(tiempo_actual)
        fallos_recientes = len(intentos_fallidos[ip_atacante])
        
        print(f"[*] Intento fallido SSH detectado desde {ip_atacante} (Total reciente: {fallos_recientes})")
        
        # Evaluar si supera el límite establecido
        if fallos_recientes >= LIMITE_FALLOS:
            alerta = f"Ataque de fuerza bruta detectado desde {ip_atacante}."
            logging.error(alerta)
            bloquear_ip(ip_atacante)
            # Limpiar el historial de esa IP para no repetir el bloqueo en cada línea sucesiva
            intentos_fallidos[ip_atacante].clear()
# Funcion principal para iniciar el monitoreo de logs SSH
def iniciar_monitoreo():
    print("=" * 60)
    print("  BLUE TEAM: SSH Defender (Prevención de Fuerza Bruta)")
    print("=" * 60)
    print(f"[*] Escuchando logs de autenticación mediante journalctl...")
    print(f"[*] Regla activa: Bloqueo tras {LIMITE_FALLOS} fallos en {VENTANA_TIEMPO}s.")
    print("[*] Presiona Ctrl+C para detener.\n")
    
    # Se utiliza journalctl para leer los logs del servicio ssh en tiempo real (-f)
    comando = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
    
    try:
        proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for linea in proceso.stdout:
            analizar_linea(linea.strip())
    except PermissionError:
        print("\n[-] Error: Ejecuta el script con 'sudo' para leer logs y aplicar iptables.")
    except KeyboardInterrupt:
        print("\n[*] Monitoreo SSH detenido. Revisa 'ssh_defender.log' para detalles.")
# Inicio del programa
if __name__ == "__main__":
    iniciar_monitoreo()