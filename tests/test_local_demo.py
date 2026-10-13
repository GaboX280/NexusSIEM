"""Smoke tests for NexusSIEM's isolated local demo mode."""

import base64
import os
import unittest
from unittest.mock import patch

# Force an isolated demo configuration before importing the Flask application.
os.environ["NEXUS_ENV"] = "development"
os.environ["NEXUS_ADMIN_USER"] = "localadmin"
os.environ["NEXUS_ADMIN_PASSWORD"] = "local-dev-change-me"
os.environ["NEXUS_TEAMS_WEBHOOK"] = ""

from blue_team.web_app.app import (  # noqa: E402
    ADMIN_PASSWORD,
    ADMIN_USER,
    DEMO_MODE,
    alertas_recientes,
    app,
    bloquear_ip,
)


class LocalDemoModeTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        alertas_recientes.clear()

    def auth_headers(self):
        token = base64.b64encode(
            f"{ADMIN_USER}:{ADMIN_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def test_demo_mode_is_enabled(self):
        self.assertTrue(DEMO_MODE)

    def test_dashboard_requires_authentication(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)

    def test_dashboard_renders_demo_banner(self):
        response = self.client.get("/", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"LOCAL DEMO MODE", response.data)

    def test_state_returns_synthetic_audit(self):
        response = self.client.get("/api/state", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["demo_mode"])
        self.assertEqual(data["audit"]["filename"], "reporte_atom_demo.json")

    def test_audit_action_is_simulated_without_launching_processes(self):
        with patch("blue_team.web_app.app.subprocess.Popen") as popen:
            response = self.client.post(
                "/api/run/audit", headers=self.auth_headers()
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["demo_mode"])
        self.assertIn("SIMULACIÓN", response.get_json()["message"])
        popen.assert_not_called()
        self.assertEqual(alertas_recientes[0]["fuente"], "Web Dashboard / Demo")

    def test_firewall_block_is_simulated_without_subprocess(self):
        with patch("blue_team.web_app.app.subprocess.run") as run:
            result = bloquear_ip("192.0.2.10")
        self.assertIn("no se bloqueó", result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
