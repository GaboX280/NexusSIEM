#!/usr/bin/env bash
set -Eeuo pipefail

echo "[*] Iniciando hardening conservador de UFW..."

if [[ "${EUID}" -ne 0 ]]; then
  echo "[-] Ejecuta este script con sudo."
  exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "[-] UFW no está instalado. No se realizaron cambios."
  exit 1
fi

# Set SSH_PORT to the actual SSH port before running this script. The SSH
# rule is added BEFORE the default deny policy to reduce remote lockout risk.
SSH_PORT="${SSH_PORT:-22}"
if ! [[ "${SSH_PORT}" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
  echo "[-] SSH_PORT debe ser un puerto entre 1 y 65535."
  exit 1
fi

echo "[+] Preservando reglas existentes: no se ejecutará 'ufw reset'."
echo "[+] Permitimos SSH limitado en el puerto ${SSH_PORT}/tcp..."
ufw limit "${SSH_PORT}/tcp"

echo "[+] Aplicando políticas por defecto..."
ufw default deny incoming
ufw default allow outgoing

# Only open web ports when explicitly requested by the operator.
if [[ "${NEXUS_ALLOW_WEB:-0}" == "1" ]]; then
  echo "[+] NEXUS_ALLOW_WEB=1: permitiendo HTTP/HTTPS."
  ufw allow 80/tcp
  ufw allow 443/tcp
else
  echo "[*] Puertos web no abiertos automáticamente. Define NEXUS_ALLOW_WEB=1 si son necesarios."
fi

echo "[+] Activando registro de paquetes bloqueados..."
ufw logging on

echo "[+] Habilitando UFW..."
ufw --force enable

echo "[+] Estado actual del firewall:"
ufw status verbose
