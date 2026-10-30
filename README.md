# NexusSIEM — Blue Team SIEM & Automated Defense

**Author:** Gabriel Villalobos Alpízar

NexusSIEM is a personal Blue Team lab for Linux-based environments. It combines security-event monitoring, a Flask dashboard, basic IDS detections, controlled firewall response, Atom-Hardening audit reports, and optional Microsoft Teams notifications.

> **Lab warning:** this project is for controlled environments. Do not expose the Flask development server directly to the Internet. Review firewall changes before running them on a remote machine.

## Architecture

- `blue_team/web_app/`: Flask dashboard, authenticated operator routes, alert API, Teams notifications.
- `blue_team/sniffer_defense.py`: Scapy-based TCP/ARP monitoring with optional iptables response.
- `blue_team/ssh_defender.py`: SSH authentication-failure monitor with optional iptables response.
- `blue_team/firewall_hardening.sh`: conservative UFW configuration; preserves existing rules.
- Atom-Hardening: optional external audit report integration.

## Requirements

- Python 3.10+ (use a version supported by the installed dependencies).
- Linux with Flask, Requests and Scapy dependencies from `requirements.txt`.
- UFW and/or iptables for firewall features.
- Root privileges are required for packet capture and firewall changes.

## Install

```bash
git clone https://github.com/GaboX280/NexusSIEM.git
cd NexusSIEM
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Configure secrets

Set credentials outside the repository. Do not commit real passwords, tokens, or webhook URLs.

```bash
export NEXUS_ADMIN_USER='operator'
export NEXUS_ADMIN_PASSWORD='replace-with-a-long-unique-password'
export NEXUS_ALERT_TOKEN='replace-with-a-long-random-token'
# Optional:
export NEXUS_TEAMS_WEBHOOK='https://your-approved-webhook-url'
```

Generate a random alert token, for example, with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Configure the same token in each trusted sensor or integration that sends events to `POST /api/alert` using the header `Authorization: Bearer <NEXUS_ALERT_TOKEN>`.

The alert API does not trust requests solely because they originate from localhost. An alert containing `ip_to_block` is logged but **does not** trigger a firewall change unless it also explicitly sets `block_ip: true` and `level: "CRITICAL"`. Special-purpose IP addresses are rejected. Review automated response in an isolated lab before enabling it.

## Firewall setup

The script preserves existing UFW rules; it no longer runs `ufw reset`. It adds a rate-limited SSH rule before applying the default incoming-deny policy. Verify your actual SSH port first:

```bash
cd blue_team
chmod +x firewall_hardening.sh
sudo env SSH_PORT=22 ./firewall_hardening.sh
```

HTTP/HTTPS are not opened automatically. If this host intentionally serves web traffic, use `NEXUS_ALLOW_WEB=1` after reviewing the impact. If you administer the host remotely, confirm console/out-of-band access and the SSH port before changing firewall policy.

## Start the dashboard

By default, the Flask server listens only on loopback (`127.0.0.1:5000`), which is the safer choice for local testing:

```bash
cd blue_team/web_app
python app.py
```

Open `http://127.0.0.1:5000` and authenticate with `NEXUS_ADMIN_USER` and `NEXUS_ADMIN_PASSWORD`.

For remote operator access, deploy behind a properly configured HTTPS reverse proxy and restrict access at the network layer. Only set `NEXUS_HOST=0.0.0.0` when you have intentionally configured that deployment path; do not expose Flask's development server directly to the public Internet. Optional port override: `NEXUS_PORT=5000`.

## Security notes

- Administrative routes require HTTP Basic credentials configured through environment variables. Use HTTPS whenever traffic leaves the local host.
- `POST /api/alert` requires the separate Bearer token `NEXUS_ALERT_TOKEN`.
- Firewall commands use argument lists (no shell interpolation), validate IP addresses, and apply execution timeouts.
- For API-triggered firewall blocks, configure a narrowly scoped sudoers rule for the service account to run only the required `iptables` commands non-interactively; do not grant broad passwordless sudo. Confirm the actual `iptables` path on the host first.
- Automatic blocking should be treated as a lab feature, not a production-ready SOAR control. Add allowlists, review/approval workflows, durable audit trails, and automated tests before using it on production systems.
- The dashboard keeps recent alerts in process memory; the list is not a durable incident database.

## License

See the repository's license file, if present.
