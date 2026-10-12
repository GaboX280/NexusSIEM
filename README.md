# 🛡️ Blue Team SIEM & Automated Defense Framework

> **University Project:** Bachelor's Degree in Cybersecurity Engineering  
> **Institution:** Universidad Fidélitas, Costa Rica  
> **Author:** Gabriel Villalobos Alpízar

---

## 📌 Project Overview

This project is an integrated **active defense and security monitoring (Blue Team)** solution designed for Linux-based virtual environments (CachyOS / Arch Linux) deployed in Microsoft Azure.

In modern cybersecurity, responding to incidents quickly is just as critical as prevention. This framework automates intrusion detection (IDS), hardens the operating system's attack surface, centralizes events in a lightweight **Flask-based SIEM**, and sends real-time alerts to corporate communication channels (Microsoft Teams) using Adaptive Cards. It can also automatically apply firewall blocks through `iptables` / `UFW` without human intervention.

---

## 🏗️ Architecture and Repository Structure

The project is organized into modules to separate defensive capabilities, auditing tools, and technical reports:

```text
NexusSIEM/
│
├── blue_team/                     # Main defensive module
│   ├── web_app/                   # SIEM application and dashboard
│   │   ├── static/
│   │   │   └── style.css          # Dark-mode UI/UX styling
│   │   ├── templates/
│   │   │   └── index.html         # Interactive web interface with auto-refresh
│   │   └── app.py                 # Flask server, alert API, and Teams webhook
│   ├── atom.py                    # Custom operating-system auditing framework
│   ├── sniffer_defense.py         # Scapy-based IDS with active iptables response
│   └── firewall_hardening.sh      # UFW hardening and traffic-control script
│
├── red_team/                      # Simulation and offensive-testing module
│   └── (Testing and automated-scanning tools)
│
├── docs/                          # Academic documentation and technical reports
│   └── report.md                 # Detailed project report
│
├── .gitignore                     # Excludes virtual environments, logs, and cache
├── requirements.txt               # Python project dependencies
└── README.md                      # Main repository documentation
```

---

## ⚙️ Technology Stack

- **Core and Backend:** Python 3 (Flask, Scapy, Requests, Subprocess)
- **Security and Networking:** UFW, `iptables`, Bash scripting, network packet analysis
- **Alerts and Automation:** Microsoft Teams (Power Automate webhooks and Adaptive Cards)
- **Environment:** Linux (CachyOS / Arch Linux) and Microsoft Azure virtual machines

---

## 🚀 Installation and Deployment

Follow these steps to clone, configure, and run the framework in a local environment or an Azure virtual machine.

### 1. Clone the repository

```bash
git clone https://github.com/GaboX280/NexusSIEM.git
cd NexusSIEM
```

### 2. Create a Python virtual environment

```bash
python -m venv venv
# Activate the environment
source venv/bin/activate.fish   # or 'source venv/bin/activate' in bash
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the firewall and hardening

Make the hardening script executable and run it:

```bash
cd blue_team
chmod +x firewall_hardening.sh
sudo ./firewall_hardening.sh
```

### 5. Start the SIEM dashboard and web server

Navigate to the web application directory and start the Flask server:

```bash
cd web_app
python app.py
```

The dashboard will be available at `http://<AZURE_IP_OR_LOCALHOST>:5000`.

---

## 📊 Key Features

1. **Automated incident response (basic SOAR):** When a critical alert includes a source IP address, the system can interact with `iptables` to apply an immediate `DROP` rule.
2. **Real-time dashboard:** A dark-themed web interface with status cards and auto-refresh for continuous SOC monitoring.
3. **Teams integration:** Automatically sends structured alerts using Adaptive Cards, improving team visibility and traceability.

---

## 📄 License

This project is developed for academic and research purposes as part of the Cybersecurity Engineering program at Universidad Fidélitas.
