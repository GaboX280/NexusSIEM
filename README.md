# 🛡️ NexusSIEM

> **Blue Team SIEM & Automated Defense Framework**  
> **Proyecto Universitario — Bachillerato en Ingeniería en Ciberseguridad**  
> **Universidad Fidélitas, Costa Rica**

NexusSIEM es un proyecto académico de **monitoreo, detección y respuesta defensiva** para máquinas virtuales Linux desplegadas en **Microsoft Azure**.

El objetivo es construir un laboratorio de seguridad que combine **detección de intrusiones, hardening, monitoreo de SSH, centralización de alertas y respuesta automatizada**, manteniendo una arquitectura ligera y fácil de desplegar.

> ⚠️ **Estado:** proyecto en desarrollo. Algunas capacidades descritas en la hoja de ruta todavía no están implementadas.

---

## 🎯 Objetivos

NexusSIEM busca experimentar con un flujo defensivo completo:

```text
          Eventos / Tráfico
                  │
                  ▼
        ┌──────────────────┐
        │ Detection Engine │
        └────────┬─────────┘
                 │
                 ▼
           Alert / IOC
                 │
        ┌────────┴────────┐
        ▼                 ▼
   SIEM Dashboard      Teams Alert
        │
        ▼
 Incident Investigation
        │
        ▼
 Automated Response
        │
        ▼
   Firewall / Host
```

El proyecto está pensado como **laboratorio educativo**, no como sustituto de una plataforma SIEM empresarial.

---

## 🏗️ Arquitectura actual

La estructura implementada actualmente es:

```text
NexusSIEM/
│
├── blue_team/
│   ├── firewall_hardening.sh    # Hardening y configuración de UFW
│   ├── sniffer_defense.py       # Detección de tráfico con Scapy
│   ├── ssh_defender.py          # Monitoreo/defensa relacionada con SSH
│   └── web_app/                 # Dashboard y API Flask
│
├── .gitignore
├── requirements.txt
└── README.md
```

La arquitectura se irá ampliando conforme se implementen nuevos módulos.

---

## 🛡️ Capacidades actuales

### 🔥 Firewall Hardening

Script Bash para aplicar una configuración defensiva inicial mediante **UFW**, reduciendo la superficie de exposición del host.

### 🔎 Network Detection

`sniffer_defense.py` utiliza **Scapy** para analizar tráfico de red y detectar determinados patrones de actividad.

Cuando corresponde, el sistema puede iniciar una respuesta defensiva mediante reglas del firewall.

### 🔐 SSH Defense

`ssh_defender.py` está orientado al monitoreo y respuesta frente a actividad sospechosa relacionada con SSH.

### 🖥️ SIEM Dashboard

La aplicación web utiliza **Flask** para proporcionar una interfaz centralizada de monitoreo y una API para trabajar con las alertas generadas por los módulos defensivos.

### 🚨 Automated Response

Una de las ideas centrales del proyecto es cerrar el ciclo:

**Detection → Alert → Response**

Por ejemplo, una alerta asociada a una dirección IP puede desencadenar una acción de bloqueo mediante `iptables`.

> Las acciones automáticas deben probarse únicamente en sistemas propios o laboratorios autorizados.

### 📢 Microsoft Teams

El proyecto contempla el envío de alertas estructuradas a Microsoft Teams mediante webhooks/Adaptive Cards para facilitar la notificación y seguimiento de incidentes.

---

## ⚙️ Stack tecnológico

| Área | Tecnología |
|---|---|
| Lenguaje | Python 3 |
| Web/API | Flask |
| Network Security | Scapy |
| Firewall | UFW / iptables |
| Scripting | Bash |
| Alerting | Microsoft Teams / Adaptive Cards |
| OS | Linux |
| Cloud | Microsoft Azure |
| Virtualización | Azure Virtual Machines |

---

## 🚀 Instalación

### 1. Clonar

```bash
git clone https://github.com/GaboX280/NexusSIEM.git
cd NexusSIEM
```

### 2. Crear entorno virtual

En Bash:

```bash
python -m venv venv
source venv/bin/activate
```

En Fish:

```fish
python -m venv venv
source venv/bin/activate.fish
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar el firewall

> Ejecuta esto únicamente sobre una máquina propia o de laboratorio. Una configuración incorrecta puede bloquear tu propio acceso SSH.

```bash
cd blue_team
chmod +x firewall_hardening.sh
sudo ./firewall_hardening.sh
```

### 5. Ejecutar el dashboard

```bash
cd web_app
python app.py
```

El dashboard estará disponible en:

```text
http://<IP_DE_LA_VM>:5000
```

Para una VM de Azure, configura el acceso de red de forma explícita y evita exponer innecesariamente el puerto del dashboard a Internet.

---

## ☁️ Azure Lab

NexusSIEM está diseñado para experimentar con máquinas virtuales Linux en Azure.

Un laboratorio futuro puede utilizar una arquitectura como:

```text
                 Microsoft Azure
                       │
              ┌────────┴────────┐
              │                 │
          Target VM         Analyst VM
              │                 │
        ┌─────┴─────┐           │
        │ NexusSIEM │◄──────────┘
        └─────┬─────┘
              │
       ┌──────┴──────┐
       ▼             ▼
    Network        System
    Events          Logs
```

La arquitectura final dependerá de los componentes que se incorporen al proyecto.

---

## 🧪 Casos de prueba

El laboratorio está pensado para generar y detectar actividad controlada, por ejemplo:

- intentos de autenticación SSH fallidos
- reconocimiento de puertos
- conexiones sospechosas
- patrones de tráfico anómalos
- actividad que active reglas de detección
- eventos que produzcan una alerta
- respuesta automática mediante firewall

Todas las pruebas deben realizarse sobre infraestructura propia o expresamente autorizada.

---

## 🗺️ Roadmap

### Phase 1 — Core Defense
- [x] Firewall hardening
- [x] Network monitoring
- [x] SSH defense module
- [x] Flask dashboard
- [x] Basic automated response

### Phase 2 — SIEM
- [ ] Normalización de eventos
- [ ] Persistencia de alertas
- [ ] Event severity
- [ ] IOC management
- [ ] Search and filtering
- [ ] Authentication/RBAC
- [ ] Audit trail

### Phase 3 — Detection Engineering
- [ ] Rule-based detection engine
- [ ] MITRE ATT&CK mapping
- [ ] Detection rules
- [ ] False-positive handling
- [ ] Threat hunting queries

### Phase 4 — Incident Response
- [ ] Incident lifecycle
- [ ] Evidence collection
- [ ] Investigation timeline
- [ ] Automated containment
- [ ] Incident reports

### Phase 5 — Azure
- [ ] Multi-VM deployment
- [ ] Centralized log collection
- [ ] Azure Monitor integration
- [ ] Azure-native security telemetry
- [ ] Secure deployment architecture

### Phase 6 — AI-assisted SOC
- [ ] Alert triage assistance
- [ ] Event summarization
- [ ] IOC enrichment
- [ ] Detection-rule assistance
- [ ] Analyst investigation assistant

> La integración de IA se diseñará como **asistencia al analista**, manteniendo controles y validación humana para acciones sensibles.

---

## 🔴 Red Team / Purple Team

Aunque NexusSIEM es principalmente un proyecto **Blue Team**, también se utilizará para estudiar la relación entre ataque y detección.

La intención es generar actividad ofensiva **controlada** en el laboratorio y observar cómo el sistema defensivo:

```text
Red Team Simulation
        │
        ▼
    Attack Event
        │
        ▼
      Detection
        │
        ▼
       Alert
        │
        ▼
   Investigation
        │
        ▼
     Response
```

Esto permitirá evolucionar el proyecto hacia ejercicios de **Purple Team**, donde las técnicas ofensivas se utilizan para validar y mejorar las capacidades defensivas.

---

## 📊 ¿Qué intenta demostrar?

NexusSIEM no pretende competir con plataformas empresariales como Microsoft Sentinel, Splunk o Elastic.

El objetivo es demostrar, mediante código y laboratorio, comprensión práctica de:

- Linux security
- network monitoring
- firewalls
- intrusion detection
- SIEM concepts
- incident response
- security automation
- cloud security
- detection engineering
- Python/Bash
- Blue Team workflows

---

## 🔐 Seguridad

NexusSIEM puede ejecutar acciones privilegiadas, modificar reglas de firewall y analizar tráfico de red.

Por eso:

- ejecútalo solamente en sistemas propios o autorizados;
- revisa las reglas antes de aplicarlas;
- evita exponer el dashboard directamente a Internet;
- utiliza credenciales y secretos mediante variables de entorno;
- no subas tokens, API keys, webhooks o credenciales al repositorio.

---

## 📄 Licencia

Proyecto académico y experimental desarrollado para fines educativos e investigativos dentro del programa de Ingeniería en Ciberseguridad de la Universidad Fidélitas.
