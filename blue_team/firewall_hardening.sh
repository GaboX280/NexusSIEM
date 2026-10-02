#!/bin/bash
echo "[*] Iniciando el proceso de Hardening del Firewall (UFW)..."
# 1. Asegurarse de que el script se ejecuta como root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Por favor, ejecuta este script como root (sudo ./firewall_hardening.sh)"
  exit 1
fi
# 2. Resetear UFW a su estado de fábrica para evitar conflictos
echo "[+] Reseteando reglas anteriores de UFW..."
ufw --force reset
# 3. Políticas por defecto (Denegar todo lo que entra, permitir lo que sale)
echo "[+] Configurando políticas por defecto..."
ufw default deny incoming
ufw default allow outgoing
# 4. Permitir tráfico esencial (Puertos 80 y 443 para web, si aplica)
echo "[+] Abriendo puertos permitidos (HTTP/HTTPS)..."
ufw allow 80/tcp
ufw allow 443/tcp
# 5. Configuración Avanzada: Rate-limiting para SSH (Puerto 22)
# Esto denegará las conexiones si una IP intenta iniciar sesión más de 6 veces en 30 segundos,
# lo cual complementa tu script de Python ssh_defender.py y suma puntos en la rúbrica.
echo "[+] Configurando Rate-limiting (limitación de tasa) para SSH en el puerto 22..."
ufw limit 22/tcp
# 6. Activar el registro de paquetes bloqueados (logging)
echo "[+] Activando logging para registrar paquetes sospechosos bloqueados..."
ufw logging on
# 7. Habilitar el firewall
echo "[+] Habilitando UFW..."
ufw --force enable
echo "[===================================================]"
echo "[✔] Hardening completado. Estado actual del firewall:"
echo "[===================================================]"
ufw status verbose