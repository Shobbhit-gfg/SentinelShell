# SentinelShell Fleet Manager

SentinelShell is a secure, cloud-managed kiosk and terminal lockdown system designed for multi-device fleets (20–30+ terminals). It features a FastAPI cloud backend deployed on Render with an integrated SQLite database and a sleek PyQt5-based client shell that enforces system lockdown, URL/command whitelisting, and real-time remote configuration.

## Features

* **Cloud-Managed Fleet Dashboard**: Remotely monitor security logs, toggle device bans, and update tab configurations live via a Tailwind CSS admin panel (`/admin`).
* **Robust Terminal Lockdown**: Traps system keys (Windows, Alt), enforces full-screen headless kiosk mode, and blocks unauthorized navigation or command execution.
* **Smart URL Whitelisting & Navigation**: Built-in slim navigation toolbar (Back, Forward, Refresh, URL display) with domain-level subpage and authentication/verification fallbacks (e.g., Google, Cloudflare, Stripe, reCAPTCHA).
* **Sandboxed Terminal**: Securely execute pre-whitelisted system commands (like `ping`, `ipconfig`, `ifconfig`) from a dedicated terminal tab with automated block logging.
* **Self-Provisioning Clients**: Terminals automatically register themselves on the cloud server using local `client_id.txt` configurations.

---

## Project Structure

```text
SentinelShell/
├── backend.py            # FastAPI backend server & admin dashboard
├── kiosk_client.py       # PyQt5 kiosk application & security sandbox
├── requirements.txt      # Python dependencies
├── .gitignore            # Excludes build artifacts, databases, and local configs
└── README.md             # Project documentation
