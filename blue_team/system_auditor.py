#!/usr/bin/env python3
"""Native, read-only Linux security auditor for NexusSIEM."""
import argparse
import json
import os
import platform
import pwd
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPORT_PREFIX = "system_audit_"


def run_command(command, timeout=8):
    """Run a fixed system command without a shell and return stdout/stderr."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "", str(exc)


def finding(check_id, title, category, status, severity, details, recommendation):
    return {
        "id": check_id,
        "title": title,
        "category": category,
        "status": status,
        "severity": severity,
        "details": details,
        "recommendation": recommendation,
        "module": "NexusSIEM System Auditor",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def check_uid_zero():
    accounts = []
    try:
        accounts = [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == 0]
    except Exception as exc:
        return finding("USR-001", "Privileged accounts", "Accounts", "ERROR", "HIGH",
                       "Could not inspect the local account database: " + str(exc),
                       "Run the auditor with sufficient read permissions.")
    unexpected = [name for name in accounts if name != "root"]
    if unexpected:
        return finding("USR-001", "Privileged accounts", "Accounts", "FAIL", "HIGH",
                       "Additional UID 0 accounts found: " + ", ".join(unexpected),
                       "Review each UID 0 account and remove unintended privileged access.")
    return finding("USR-001", "Privileged accounts", "Accounts", "PASS", "INFO",
                   "UID 0 accounts: " + (", ".join(accounts) if accounts else "none"),
                   "Continue reviewing privileged accounts periodically.")


def check_ssh_configuration():
    config = Path("/etc/ssh/sshd_config")
    if not config.is_file():
        return finding("SSH-001", "SSH daemon configuration", "SSH", "WARNING", "MEDIUM",
                       "The standard sshd_config file was not found.",
                       "Confirm whether OpenSSH server is installed and configured.")
    code, output, error = run_command(["sshd", "-T"], timeout=8)
    values = {}
    if code == 0:
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                values[parts[0].lower()] = parts[1].lower()
    else:
        try:
            for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    values.setdefault(parts[0].lower(), parts[1].lower())
        except OSError as exc:
            return finding("SSH-001", "SSH daemon configuration", "SSH", "ERROR", "HIGH",
                           "Could not read SSH configuration: " + str(exc),
                           "Inspect /etc/ssh/sshd_config with an administrator.")
    risky = []
    if values.get("permitrootlogin") in ("yes", "without-password", "prohibit-password"):
        risky.append("PermitRootLogin=" + values["permitrootlogin"])
    if values.get("passwordauthentication") == "yes":
        risky.append("PasswordAuthentication=yes")
    if risky:
        return finding("SSH-001", "SSH daemon configuration", "SSH", "FAIL", "HIGH",
                       "Potentially risky SSH settings: " + ", ".join(risky),
                       "Prefer PermitRootLogin no and key-based authentication; validate changes before reloading sshd.")
    if values.get("permitrootlogin") == "no" and values.get("passwordauthentication") == "no":
        return finding("SSH-001", "SSH daemon configuration", "SSH", "PASS", "INFO",
                       "Root login and password authentication are disabled.",
                       "Keep key-based access and maintain a tested recovery path.")
    return finding("SSH-001", "SSH daemon configuration", "SSH", "WARNING", "MEDIUM",
                   "Could not confirm that both root login and password authentication are disabled.",
                   "Review effective sshd settings with sshd -T and harden authentication.")


def check_firewall():
    code, output, error = run_command(["ufw", "status"], timeout=5)
    if code == 0 and output:
        if "Status: active" in output:
            return finding("FW-001", "Host firewall", "Firewall", "PASS", "INFO",
                           "UFW reports an active firewall. " + output.splitlines()[0],
                           "Review inbound and outbound rules against the host role.")
        if "Status: inactive" in output:
            return finding("FW-001", "Host firewall", "Firewall", "FAIL", "HIGH",
                           "UFW is installed but inactive.",
                           "Enable and configure a host firewall after confirming remote access rules.")
    code, output, error = run_command(["iptables", "-S"], timeout=5)
    if code == 0:
        rules = [line for line in output.splitlines() if line.startswith("-A ")]
        if rules:
            return finding("FW-001", "Host firewall", "Firewall", "PASS", "INFO",
                           "iptables contains " + str(len(rules)) + " configured rule(s).",
                           "Review rule ordering and default policies; confirm IPv6 filtering separately.")
        return finding("FW-001", "Host firewall", "Firewall", "WARNING", "MEDIUM",
                       "iptables is available but no explicit rules were found.",
                       "Define an appropriate default-deny policy and required service exceptions.")
    return finding("FW-001", "Host firewall", "Firewall", "WARNING", "MEDIUM",
                   "Could not determine firewall state using UFW or iptables.",
                   "Install or configure a supported host firewall and verify its active rules.")


def check_sensitive_permissions():
    targets = {
        "/etc/passwd": (0o644, "Account database"),
        "/etc/shadow": (0o640, "Password hash database"),
        "/etc/ssh/sshd_config": (0o600, "SSH daemon configuration"),
    }
    issues = []
    checked = []
    for raw_path, (max_mode, label) in targets.items():
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            return finding("PERM-001", "Sensitive file permissions", "Permissions", "ERROR", "MEDIUM",
                           "Could not inspect " + raw_path + ": " + str(exc),
                           "Check file metadata using an account with read permissions.")
        checked.append(raw_path + "=" + format(mode, "04o"))
        if mode & 0o022 or mode & ~max_mode:
            issues.append(label + " (" + raw_path + ") has mode " + format(mode, "04o"))
    if issues:
        return finding("PERM-001", "Sensitive file permissions", "Permissions", "FAIL", "HIGH",
                       "; ".join(issues),
                       "Apply distribution-appropriate restrictive ownership and permissions.")
    return finding("PERM-001", "Sensitive file permissions", "Permissions", "PASS", "INFO",
                   "Checked: " + (", ".join(checked) if checked else "no standard files found"),
                   "Preserve restrictive permissions on account and SSH configuration files.")


def check_fail2ban():
    code, output, error = run_command(["systemctl", "is-active", "fail2ban"], timeout=5)
    if code == 0 and output == "active":
        return finding("DEF-001", "Fail2ban service", "Protection", "PASS", "INFO",
                       "Fail2ban is active.",
                       "Review jails, thresholds, and log sources periodically.")
    code, output, error = run_command(["systemctl", "is-enabled", "fail2ban"], timeout=5)
    if code == 0 and output == "enabled":
        return finding("DEF-001", "Fail2ban service", "Protection", "WARNING", "MEDIUM",
                       "Fail2ban is enabled but not currently active.",
                       "Investigate service startup and inspect its journal.")
    return finding("DEF-001", "Fail2ban service", "Protection", "WARNING", "MEDIUM",
                   "Fail2ban is not active or systemd could not verify its state.",
                   "Consider enabling Fail2ban or an equivalent brute-force protection control where appropriate.")


def check_listening_services():
    code, output, error = run_command(["ss", "-tuln"], timeout=5)
    if code != 0:
        return finding("NET-001", "Listening network services", "Network", "ERROR", "MEDIUM",
                       "Could not enumerate listening sockets: " + (error or "ss command unavailable"),
                       "Install iproute2 and rerun the audit.")
    listeners = [line.strip() for line in output.splitlines()[1:] if line.strip()]
    return finding("NET-001", "Listening network services", "Network", "WARNING" if listeners else "PASS",
                   "MEDIUM" if listeners else "INFO",
                   str(len(listeners)) + " listening socket(s) detected. Review exposed addresses and ports.",
                   "Disable unnecessary services and restrict management interfaces to trusted networks.")


def check_pending_updates():
    if shutil.which("apt"):
        code, output, error = run_command(["apt", "list", "--upgradable"], timeout=12)
        if code == 0:
            packages = [line for line in output.splitlines() if "/" in line and not line.startswith("Listing")]
            if packages:
                return finding("PKG-001", "Pending security updates", "Updates", "WARNING", "MEDIUM",
                               str(len(packages)) + " upgradable package(s) reported by the local APT cache.",
                               "Refresh package metadata and apply security updates during an approved maintenance window.")
            return finding("PKG-001", "Pending security updates", "Updates", "PASS", "INFO",
                           "APT did not report upgradable packages from its current local cache.",
                           "Keep package metadata current; this check does not run apt update.")
    if shutil.which("dnf"):
        code, output, error = run_command(["dnf", "check-update", "--security"], timeout=15)
        if code in (0, 100):
            packages = [line for line in output.splitlines() if line and not line.startswith(("Last metadata", "Obsoleting"))]
            if code == 100 or packages:
                return finding("PKG-001", "Pending security updates", "Updates", "WARNING", "MEDIUM",
                               "DNF reports pending security updates.",
                               "Apply security updates during an approved maintenance window.")
            return finding("PKG-001", "Pending security updates", "Updates", "PASS", "INFO",
                           "DNF did not report pending security updates.",
                           "Keep package metadata current.")
    if shutil.which("pacman"):
        code, output, error = run_command(["pacman", "-Qu"], timeout=12)
        if code == 0:
            packages = [line for line in output.splitlines() if line.strip()]
            return finding("PKG-001", "Pending package updates", "Updates",
                           "WARNING" if packages else "PASS", "MEDIUM" if packages else "INFO",
                           str(len(packages)) + " package update(s) available in the local sync database.",
                           "Review and apply updates using the distribution's normal maintenance process.")
        if code == 1 and not output:
            return finding("PKG-001", "Pending package updates", "Updates", "PASS", "INFO",
                           "Pacman did not report pending package updates.",
                           "Keep sync databases current.")
    return finding("PKG-001", "Pending security updates", "Updates", "WARNING", "MEDIUM",
                   "No supported package manager was detected or its local metadata could not be queried.",
                   "Review updates using the package manager for this Linux distribution.")


def calculate_score(findings):
    weights = {"PASS": 100, "WARNING": 60, "FAIL": 0}
    scored = [weights[item["status"]] for item in findings if item["status"] in weights]
    return round(sum(scored) / len(scored)) if scored else 0


def build_report():
    findings = [
        check_uid_zero(),
        check_ssh_configuration(),
        check_firewall(),
        check_sensitive_permissions(),
        check_fail2ban(),
        check_listening_services(),
        check_pending_updates(),
    ]
    counts = {status: sum(1 for item in findings if item["status"] == status)
              for status in ("PASS", "WARNING", "FAIL", "ERROR")}
    score = calculate_score(findings)
    rating = ("EXCELLENT" if score >= 90 else "GOOD" if score >= 75
              else "MODERATE" if score >= 50 else "CRITICAL")
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "summary": {
            "module": "NexusSIEM System Auditor",
            "status": counts,
            "score": score,
            "rating": rating,
            "total": len(findings),
        },
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="NexusSIEM read-only Linux security audit")
    parser.add_argument("--output-dir", default=None, help="Directory where the JSON report is saved")
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else project_root / "reports" / "system_audit"
    output_dir.mkdir(parents=True, exist_ok=True)
    report = build_report()
    filename = REPORT_PREFIX + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    destination = output_dir / filename
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    print(str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
