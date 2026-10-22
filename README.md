# 🛡️ NexusSIEM — Blue Team SIEM & Automated Defense Framework

> **University project:** Bachelor's Degree in Cybersecurity Engineering  
> **Institution:** Universidad Fidélitas, Costa Rica  
> **Purpose:** Academic and authorized defensive-security labs

NexusSIEM is a lightweight Flask-based security dashboard for collecting alerts, displaying Atom audit results, and integrating defensive tooling such as Scapy, UFW/iptables, and Microsoft Teams.

## Repository layout

```text
NexusSIEM/
├── blue_team/
│   ├── web_app/
│   │   ├── app.py
│   │   ├── .env.example
│   │   ├── templates/index.html
│   │   └── static/style.css
│   ├── atom_launcher.py
│   ├── sniffer_defense.py
│   └── firewall_hardening.sh
├── requirements.txt
├── .gitignore
└── README.md
```

## Run locally (safe demo mode)

The local mode lets teammates clone the repository and test the dashboard without Azure credentials, Atom installed, sudo permissions, or access to a real firewall. Audit data and defensive actions are simulated; no firewall rules are changed, no packet capture is started, and Teams/geolocation integrations are not called.

### 1. Clone and install

```bash
git clone https://github.com/GaboX280/NexusSIEM.git
cd NexusSIEM

python -m venv .venv
```

Activate the virtual environment:

```bash
# Linux/macOS, Bash or Zsh
source .venv/bin/activate

# Fish shell instead:
# source .venv/bin/activate.fish
```

Install dependencies and create local configuration:

```bash
python -m pip install -r requirements.txt
cp blue_team/web_app/.env.example .env
```

The sample configuration uses the local-only demo credentials `localadmin` / `local-dev-change-me`. You can change them in `.env`. The `.env` file is ignored by Git and must never be committed.

### 2. Start the dashboard

From the repository root:

```bash
python blue_team/web_app/app.py
```

Open **http://127.0.0.1:5000**. The browser will request the username and password configured in `.env`.

In demo mode, the dashboard displays a synthetic Atom report and the action buttons return clearly labelled simulated results. The application binds to localhost by default, so it is not exposed to the local network.

### 3. Optional tests

```bash
python -m unittest discover -s tests -v
```

## Production / Azure configuration

Do not use the demo credentials in Azure. Set these variables through the deployment's protected environment (for example, the systemd service environment or a root-readable environment file):

- `NEXUS_ENV=production`
- `NEXUS_ADMIN_USER` — a unique administrative username
- `NEXUS_ADMIN_PASSWORD` — a strong, unique password
- `NEXUS_TEAMS_WEBHOOK` — optional Teams webhook URL

The application defaults to production mode when `NEXUS_ENV` is not set. In production, administrative routes run the configured tools and may affect the host. Review the scripts and permissions before enabling them. Do not expose the Flask development server directly to the public Internet; use a properly configured production WSGI server, HTTPS reverse proxy, network restrictions, and least-privilege service permissions.

**Never run the firewall-hardening script just to test the local dashboard.** It is an optional, potentially disruptive operation and should only be executed in a planned, authorized lab or deployment.

## Main capabilities

- Flask dashboard and recent security-event buffer.
- Protected dashboard and administrative API using HTTP Basic Authentication.
- Atom report display (real reports in production; synthetic report in demo mode).
- Optional Microsoft Teams Adaptive Card alerts.
- Defensive integrations for firewall hardening, packet analysis, and audit execution.

## License

Developed for academic and research purposes as part of the Cybersecurity Engineering program at Universidad Fidélitas.
