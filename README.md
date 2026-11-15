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
│   ├── sniffer_defense.py         # Scapy-based IDS with active iptables response
│   ├── system_auditor.py          # Native read-only Linux security auditor
│   └── firewall_hardening.sh      # UFW hardening and traffic-control script
│
├── red_team/                      # Simulation and offensive-testing module
│   └── (Testing and automated-scanning tools)
│
├── reports/
│   └── system_audit/              # Native JSON audit reports (local only; ignored by Git)
├── logs/
│   └── system_audit.log            # Native auditor execution log (local runtime file)
├── docs/                          # Academic documentation and technical reports
│   └── report.md                  # Detailed project report
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

### 5. Run the native system auditor

The Linux security audit is implemented directly in NexusSIEM. It runs independently and requires no additional Python packages. The dashboard launches the read-only auditor and reads the latest JSON report from `reports/system_audit/`.

You can also run it manually from the repository root:

```bash
python blue_team/system_auditor.py
```

The auditor creates a timestamped JSON report in `reports/system_audit/`. When launched by the dashboard, its standard output and errors are written to `logs/system_audit.log`.

### 6. Configure administrative dashboard credentials

The dashboard protects administrative routes with HTTP Basic Authentication. Configure the credentials in the environment where Flask will run:

```bash
export NEXUS_ADMIN_USER="your_admin_user"
export NEXUS_ADMIN_PASSWORD="your_strong_password"
```

To enable Microsoft Teams notifications, also configure the Power Automate webhook:

```bash
export NEXUS_TEAMS_WEBHOOK="your_webhook_url"
```

Do not commit real credentials or webhook URLs to the repository.

### 7. Start the SIEM dashboard and web server

From the `blue_team` directory used in step 4, navigate to the web application and start Flask:

```bash
cd web_app
python app.py
```

The dashboard will be available at `http://<AZURE_IP_OR_LOCALHOST>:5000`. Ensure the VM firewall and Azure network rules permit access only from trusted sources.

---

## 📊 Key Features

1. **Automated incident response (basic SOAR):** When a critical alert includes a source IP address, the system can interact with `iptables` to apply an immediate `DROP` rule.
2. **Real-time dashboard:** A dark-themed web interface with status cards and auto-refresh for continuous SOC monitoring.
3. **Teams integration:** Automatically sends structured alerts using Adaptive Cards, improving team visibility and traceability.
4. **Native Linux security auditing:** Executes NexusSIEM's own read-only Linux checks and displays the results in the dashboard. The auditor is an independent module within the project and does not depend on an external hardening framework.

---

## 🔎 Native System Audit: Dashboard Workflow

The **Run System Audit** button in the web dashboard is connected to NexusSIEM's native auditor, `blue_team/system_auditor.py`. Selecting the button starts a new audit process; it does not merely display an existing report.

The execution sequence is:

1. The dashboard JavaScript function `ejecutarAccion('audit')` sends an authenticated `POST` request to `/api/run/audit`.
2. The Flask route validates the administrative credentials and calls `iniciar_auditoria_sistema()`.
3. Flask launches `system_auditor.py` using the same Python interpreter as the running application (`sys.executable`). The process runs independently in the background, with its working directory set to the Blue Team module.
4. The auditor performs its checks and writes a timestamped JSON report to `reports/system_audit/`. Its console output and errors are redirected to `logs/system_audit.log`.
5. Flask records an informational event from **Web Dashboard** and returns HTTP `202 Accepted` to indicate that the audit was started.
6. The dashboard refreshes its state and continues polling `/api/state` every three seconds. When a new report is available, the audit panel renders its summary and findings.

The application prevents a second audit from being started while the previous audit process is still running. If an audit is already in progress, the endpoint responds with HTTP `409 Conflict`. A missing auditor module or a startup failure is reported as an error instead of being treated as a successful run.

### Checks performed

The native auditor currently performs seven checks:

| ID | Area | What is inspected |
|---|---|---|
| `USR-001` | Privileged accounts | Detects unexpected local accounts with UID 0. |
| `SSH-001` | SSH configuration | Reviews effective SSH settings, including root login and password authentication. |
| `FW-001` | Host firewall | Checks UFW status or available iptables rules. |
| `PERM-001` | Sensitive permissions | Inspects permissions on `/etc/passwd`, `/etc/shadow`, and `/etc/ssh/sshd_config`, when present. |
| `DEF-001` | Fail2ban | Checks whether the Fail2ban service is active or enabled. |
| `NET-001` | Listening services | Enumerates listening TCP/UDP sockets using `ss -tuln`. |
| `PKG-001` | Package updates | Queries locally available package metadata through APT, DNF, or Pacman. |

The auditor is designed for **read-only inspection**: it does not change SSH configuration, firewall rules, file permissions, services, or install updates. Package update checks use the package manager's available local metadata; they do not run a package upgrade.

### Report format and dashboard statuses

Each report contains the generation timestamp, host, platform, a summary, and the individual findings. The summary includes the total number of checks, a score, a rating, and counters for each status.

| Status | Meaning |
|---|---|
| `PASS` | The inspected control passed the check. |
| `WARNING` | A condition requires review or could not be fully verified. |
| `FAIL` | The check detected a potentially insecure configuration. |
| `ERROR` | The check could not be completed because of an execution or inspection error. |

The dashboard displays the score, rating, status counts, and detailed findings from the latest valid JSON report. Reports are stored locally and the `reports/system_audit/` directory is excluded from version control.

### Audit-related API routes

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/run/audit` | Starts the native system audit. |
| `GET` | `/api/audit/latest` | Returns the latest valid audit report. |
| `GET` | `/api/state` | Returns dashboard alerts and the latest audit report. |

These dashboard routes require the configured administrative HTTP Basic Authentication credentials.

---

## 📄 License

This project is developed for academic and research purposes as part of the Cybersecurity Engineering program at Universidad Fidélitas.
