#!/usr/bin/env python3

import subprocess
from pathlib import Path

ATOM_DIR = Path.home() / "Atom-Hardening"
ATOM_PYTHON = ATOM_DIR / ".venv" / "bin" / "python"
ATOM_MAIN = ATOM_DIR / "main.py"
REPORTS_DIR = ATOM_DIR / "reports"


def ejecutar_atom():
    REPORTS_DIR.mkdir(exist_ok=True)

    comando = [
        str(ATOM_PYTHON),
        str(ATOM_MAIN),
        "--scan",
        "--format", "json",
        "--output-dir", str(REPORTS_DIR),
        "--quiet",
    ]

    return subprocess.Popen(
        comando,
        cwd=ATOM_DIR
    )


if __name__ == "__main__":
    proceso = ejecutar_atom()
    print(f"Atom iniciado. PID: {proceso.pid}")
