# 🛡️ Blue Team SIEM & Automated Defense Framework

> **Proyecto Universitario - Bachillerato en Ingeniería en Ciberseguridad**  
> **Institución:** Universidad Fidélitas, Costa Rica  
> **Autor:** Gabriel Villalobos Alpízar  

---

## 📌 Contexto del Proyecto

Este proyecto nace como una solución integral de **Defensa Activa y Monitoreo de Seguridad (Blue Team)** diseñada para entornos virtuales basados en Linux (CachyOS / Arch Linux) desplegados en la nube de Microsoft Azure. 

En la práctica moderna de la ciberseguridad, la velocidad de respuesta ante incidentes es tan crítica como la prevención. Este framework automatiza la detección de intrusiones (IDS), endurece la superficie de ataque del sistema operativo, centraliza los eventos en un **SIEM liviano basado en Flask**, y despacha notificaciones de alerta en tiempo real a canales de comunicación corporativos (Microsoft Teams) mediante Tarjetas Adaptables, ejecutando bloqueos automáticos en el firewall (`iptables`/`UFW`) sin intervención humana.

---

## 🏗️ Arquitectura y Estructura del Repositorio

El proyecto está organizado de manera modular para separar las capacidades defensivas, las herramientas de auditoría y los reportes técnicos:

```text
NexusSIEM/
│
├── blue_team/                     # Módulo defensivo principal
│   ├── web_app/                   # Aplicación central SIEM y Dashboard
│   │   ├── static/
│   │   │   └── style.css          # Estilos profesionales en modo oscuro (UI/UX)
│   │   ├── templates/
│   │   │   └── index.html         # Interfaz web interactiva con auto-refresco
│   │   └── app.py                 # Servidor Flask, API de alertas y Webhook de Teams
│   ├── atom.py                    # Framework personalizado de auditoría del SO
│   ├── sniffer_defense.py         # IDS basado en Scapy con respuesta activa en iptables
│   └── firewall_hardening.sh      # Script de endurecimiento de UFW y control de tráfico
│
├── red_team/                      # Módulo de simulación y pruebas ofensivas
│   └── (Herramientas de prueba y escaneo automatizado)
│
├── docs/                          # Documentación académica y reportes técnicos
│   └── report.md                  # Reporte detallado del proyecto
│
├── .gitignore                     # Exclusión de entornos virtuales, logs y caché
├── requirements.txt               # Dependencias del proyecto Python
└── README.md                      # Documentación principal del repositorio
```

---

## ⚙️ Stack Tecnológico

* **Core & Backend:** Python 3 (Flask, Scapy, Requests, Subprocess)
* **Seguridad & Redes:** UFW, `iptables`, Bash Scripting, análisis de paquetes de red
* **Alertas & Automatización:** Microsoft Teams (Power Automate Webhooks & Adaptive Cards)
* **Entorno:** Linux (CachyOS / Arch Linux) / Microsoft Azure VMs

---

## 🚀 Guía de Despliegue e Instalación

Sigue estos pasos para clonar, configurar y poner en marcha el framework en tu entorno local o máquina virtual de Azure:

### 1. Clonar el repositorio
```bash
git clone https://github.com/GaboX280/NexusSIEM.git
cd NexusSIEM
```

### 2. Configurar el entorno virtual de Python
```bash
python -m venv venv
# Activar entorno
source venv/bin/activate.fish   # o 'source venv/bin/activate' en bash
```

### 3. Instalar las dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar el Firewall y el Hardening
Dale permisos de ejecución al script de endurecimiento y aplícalo:
```bash
cd blue_team
chmod +x firewall_hardening.sh
sudo ./firewall_hardening.sh
```

### 5. Iniciar el Dashboard SIEM y el Servidor Web
Navega a la carpeta de la aplicación web y pon en marcha el servidor Flask:
```bash
cd web_app
python app.py
```
*El panel de control estará accesible en `http://<IP_DE_AZURE_O_LOCALHOST>:5000`.*

---

## 📊 Características Clave

1. **Respuesta Automática a Incidentes (SOAR básico):** Al recibir una alerta crítica con una dirección IP de origen, el sistema interactúa de forma nativa con `iptables` para aplicar una regla `DROP` instantánea.
2. **Dashboard en Tiempo Real:** Interfaz web con diseño oscuro, tarjetas de estado y auto-refresco para la supervisión continua del SOC.
3. **Integración con Teams:** Envío automático de alertas estructuradas mediante Tarjetas Adaptables (*Adaptive Cards*), facilitando la trazabilidad del equipo.

---

## 📄 Licencia

Este proyecto se desarrolla con fines académicos e investigativos bajo los estándares del programa de Ingeniería en Ciberseguridad de la Universidad Fidélitas.