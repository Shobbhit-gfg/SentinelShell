import sys
import os
import json
import random
import requests
import subprocess
import keyboard
from urllib.parse import urlparse
from PyQt5.QtCore import Qt, QUrl, QTimer
from PyQt5.QtGui import QPixmap, QPainter
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget,
                             QVBoxLayout, QHBoxLayout, QPushButton, QInputDialog,
                             QMessageBox, QLineEdit, QTextEdit, QLabel)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage

SERVER_IP = "sentinelshell.onrender.com"
API_BASE = f"https://{SERVER_IP}/api"

GITHUB_USERNAME = "Shobbhit-gfg"

# Inline GitHub mark (octocat) as SVG so no network fetch is needed for the header icon.
GITHUB_LOGO_SVG = b"""
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="#c9d1d9">
<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07
-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82
.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12
.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48
0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
</svg>
"""

def render_github_logo(size=24):
    renderer = QSvgRenderer(GITHUB_LOGO_SVG)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return pixmap

CONFIG_FILE = "client_id.txt"
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
        USER_ID = f.read().strip()
else:
    USER_ID = "pc_01"

class WhitelistedWebPage(QWebEnginePage):
    def __init__(self, client_window, profile, parent=None):
        super().__init__(profile, parent)
        self.client_window = client_window

    def acceptNavigationRequest(self, url, nav_type, isMainFrame):
        url_str = url.toString()
        allowed_urls = self.client_window.config.get("allowed_urls", [])

        # 1. Always allow local files, blank frames, data URI schemes, and internal browser schemes
        if url_str.startswith(("file:///", "about:", "data:", "blob:", "chrome:")):
            return True

        # 2. Parse and normalize target domain (strip port numbers & 'www.')
        parsed_target = urlparse(url_str)
        target_domain = parsed_target.netloc.lower().split(':')[0]
        if target_domain.startswith("www."):
            target_domain = target_domain[4:]

        if not target_domain:
            return True

        # 3. Evaluate against configured allowed URLs/domains (STRICT DNS MATCHING)
        for allowed in allowed_urls:
            if not allowed:
                continue

            # Ensure scheme exists for proper urlparse domain extraction
            allowed_clean = allowed if allowed.startswith(("http://", "https://")) else f"https://{allowed}"
            allowed_domain = urlparse(allowed_clean).netloc.lower().split(':')[0]
            if allowed_domain.startswith("www."):
                allowed_domain = allowed_domain[4:]

            if target_domain and allowed_domain:
                # Target MUST be the exact domain or a subdomain of the allowed domain
                if target_domain == allowed_domain or target_domain.endswith("." + allowed_domain):
                    return True

        # 4. Infrastructure & Global Whitelist (CDNs, Auth, Captchas, APIs)
        global_whitelist = [
            "stripe.com", "doubleclick.net", "googletagmanager.com", "cloudflare.com",
            "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
            "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
            "microsoftonline.com", "github.com", "githubusercontent.com", "githubassets.com",
            "recaptcha.net", "hcaptcha.com", "auth0.com", "base64decode.org", "codebeautify.org", "browserling.com"
        ]

        # STRICT MATCH for Global Whitelist
        if any(target_domain == domain or target_domain.endswith("." + domain) for domain in global_whitelist):
            return True

        # Block & log genuine unauthorized access attempts
        print(f"[BLOCKED] Navigation attempt to: {url_str}")
        try:
            requests.post(f"{API_BASE}/logs", json={
                "user_id": USER_ID,
                "event_type": "URL_BLOCKED",
                "details": url_str
            }, timeout=3)
        except Exception:
            pass

        return False

class SandboxedTerminal(QWidget):
    def __init__(self, client_window):
        super().__init__()
        self.client_window = client_window
        layout = QVBoxLayout()

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("background-color: black; color: #10b981; font-family: monospace;")

        self.input_line = QLineEdit()
        self.input_line.setStyleSheet("background-color: black; color: white; font-family: monospace;")
        self.input_line.returnPressed.connect(self.execute_command)

        layout.addWidget(self.output_area)
        layout.addWidget(self.input_line)
        self.setLayout(layout)

    def execute_command(self):
        cmd = self.input_line.text().strip()
        self.input_line.clear()
        self.output_area.append(f"> {cmd}")

        allowed_commands = self.client_window.config.get("allowed_commands", [])

        if cmd not in allowed_commands:
            self.output_area.append("ERROR: Command not whitelisted by Administrator.\n")
            try:
                requests.post(f"{API_BASE}/logs", json={"user_id": USER_ID, "event_type": "CMD_BLOCKED", "details": cmd}, timeout=3)
            except Exception:
                pass
            return

        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            self.output_area.append(result.stdout)
            if result.stderr:
                self.output_area.append(result.stderr)
        except Exception as e:
            self.output_area.append(f"Execution failed: {str(e)}\n")

class KioskWindow(QMainWindow):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.init_ui()
        self.trap_system_keys()

        self.sync_timer = QTimer(self)
        self.sync_timer.timeout.connect(self.fetch_latest_config)

        # Add random jitter (-1s to +2s)
        base_interval = 10000
        jitter = random.randint(-1000, 2000)
        self.sync_timer.start(base_interval + jitter)

    def init_ui(self):
        self.setWindowTitle("SentinelShell Kiosk")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.X11BypassWindowManagerHint)
        self.showFullScreen()

        central = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        central_layout.addWidget(self.build_header())

        self.tabs = QTabWidget()
        central_layout.addWidget(self.tabs)

        central.setLayout(central_layout)
        self.setCentralWidget(central)

        self.build_tabs_from_config()

    def build_header(self):
        header = QWidget()
        header.setFixedHeight(40)
        header.setStyleSheet("background-color: #0d1117; border-bottom: 1px solid #27272a;")

        outer_layout = QHBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)

        # Centered group: avatar + username
        center_group = QWidget()
        center_layout = QHBoxLayout()
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(8)

        avatar_label = QLabel()
        avatar_label.setFixedSize(24, 24)
        avatar_label.setPixmap(render_github_logo(24))
        avatar_label.setScaledContents(True)

        username_label = QLabel(GITHUB_USERNAME)
        username_label.setStyleSheet("color: #c9d1d9; font-family: monospace; font-size: 13px; font-weight: bold;")

        center_layout.addWidget(avatar_label)
        center_layout.addWidget(username_label)
        center_group.setLayout(center_layout)

        outer_layout.addStretch(1)
        outer_layout.addWidget(center_group)
        outer_layout.addStretch(1)

        header.setLayout(outer_layout)
        return header

    def build_tabs_from_config(self):
        self.tabs.clear()
        raw_tabs = self.config.get("tabs", [])

        # Parse JSON string if received as stringified JSON
        if isinstance(raw_tabs, str):
            try:
                tab_list = json.loads(raw_tabs)
            except Exception:
                tab_list = []
        else:
            tab_list = raw_tabs

        allowed_urls = self.config.get("allowed_urls", [])

        # Flatten nested lists (e.g., [[{...}]])
        while isinstance(tab_list, list) and len(tab_list) > 0 and isinstance(tab_list[0], list):
            tab_list = tab_list[0]

        for tab in tab_list:
            if isinstance(tab, dict):
                name = tab.get("name", "Tab")
                t_type = tab.get("type", "url")
                val = tab.get("value", "")

                if t_type == "terminal":
                    self.add_terminal_tab(name)
                elif t_type in ["pdf", "image"]:
                    if os.path.exists(val):
                        file_url = QUrl.fromLocalFile(os.path.abspath(val)).toString()
                    else:
                        file_url = val
                    self.add_web_tab(file_url, name)
                else:
                    self.add_web_tab(val, name)
            elif isinstance(tab, str):
                tab_str = tab.strip()
                if tab_str.startswith("http://") or tab_str.startswith("https://"):
                    self.add_web_tab(tab_str, "Web Tab")
                elif tab_str.lower() in ["terminal", "console"]:
                    self.add_terminal_tab(tab_str)
                else:
                    target_url = allowed_urls[0] if allowed_urls else "https://python.org"
                    self.add_web_tab(target_url, tab_str)

    def add_web_tab(self, url, title):
        container = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Navigation Toolbar (Back, Forward, Refresh, URL display)
        toolbar = QWidget()
        toolbar.setFixedHeight(30)
        toolbar.setStyleSheet("background-color: #18181b; border-bottom: 1px solid #27272a;")
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(6, 2, 6, 2)
        tb_layout.setSpacing(4)

        back_btn = QPushButton("←")
        forward_btn = QPushButton("→")
        reload_btn = QPushButton("⟳")

        btn_style = """
            QPushButton {
                background-color: #27272a; color: #a1a1aa; border: none;
                border-radius: 4px; font-weight: bold; font-size: 13px; padding: 4px 8px;
            }
            QPushButton:hover { background-color: #3f3f46; color: #ffffff; }
        """
        for btn in [back_btn, forward_btn, reload_btn]:
            btn.setStyleSheet(btn_style)
            btn.setFixedWidth(32)

        url_bar = QLineEdit()
        url_bar.setReadOnly(True)
        url_bar.setStyleSheet("""
            background-color: #09090b; color: #71717a; border: 1px solid #27272a;
            border-radius: 4px; padding: 4px 8px; font-size: 11px; font-family: monospace;
        """)

        tb_layout.addWidget(back_btn)
        tb_layout.addWidget(forward_btn)
        tb_layout.addWidget(reload_btn)
        tb_layout.addWidget(url_bar)
        toolbar.setLayout(tb_layout)

        browser = QWebEngineView()
        page = WhitelistedWebPage(self, browser.page().profile(), browser)
        browser.setPage(page)

        # Ensure scheme prefix for QUrl parsing
        if not (url.startswith("http://") or url.startswith("https://") or url.startswith("file:///")):
            url = "https://" + url

        browser.setUrl(QUrl(url))

        # Wire up navigation controls
        back_btn.clicked.connect(browser.back)
        forward_btn.clicked.connect(browser.forward)
        reload_btn.clicked.connect(browser.reload)
        browser.urlChanged.connect(lambda qurl: url_bar.setText(qurl.toString()))

        layout.addWidget(toolbar)
        layout.addWidget(browser)
        container.setLayout(layout)

        self.tabs.addTab(container, title)

    def add_terminal_tab(self, title):
        terminal = SandboxedTerminal(self)
        self.tabs.addTab(terminal, title)

    def fetch_latest_config(self):
        try:
            response = requests.get(f"{API_BASE}/config/{USER_ID}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "banned":
                    QMessageBox.critical(self, "Access Revoked", "This device has been banned by the administrator.")
                    keyboard.unhook_all()
                    sys.exit(0)

                if data.get("tabs") != self.config.get("tabs"):
                    self.config = data
                    self.build_tabs_from_config()
                else:
                    self.config = data
        except Exception:
            pass

    def trap_system_keys(self):
        try:
            keyboard.block_key('windows')
            keyboard.block_key('alt')
        except Exception as e:
            print("System key trapping requires root/admin privileges.")

    def keyPressEvent(self, event):
        if event.modifiers() == (Qt.ControlModifier | Qt.ShiftModifier) and event.key() == Qt.Key_X:
            self.trigger_exit_protocol()
        else:
            super().keyPressEvent(event)

    def trigger_exit_protocol(self):
        password, ok = QInputDialog.getText(self, 'Admin Override', 'Enter Administrator Password:', QLineEdit.Password)
        if ok and password == self.config.get("admin_password", ""):
            keyboard.unhook_all()
            QApplication.quit()
        else:
            try:
                requests.post(f"{API_BASE}/logs", json={"user_id": USER_ID, "event_type": "FAILED_EXIT", "details": "Invalid admin password attempt"}, timeout=3)
            except Exception:
                pass
            QMessageBox.critical(self, 'Access Denied', 'Security violation logged.')

if __name__ == '__main__':
    app = QApplication(sys.argv)

    target_url = f"{API_BASE}/config/{USER_ID}"
    print(f"Connecting to cloud server at: {target_url}")

    try:
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        config = response.json()
        if config.get("status") == "banned":
            print("Client device is currently banned. Halting boot.")
            sys.exit(1)
    except Exception as e:
        print(f"\n[BOOT ERROR] Unable to connect to cloud server.")
        print(f"Details: {e}")
        print("Please check your internet connection or cloud service status.\n")
        sys.exit(1)

    kiosk = KioskWindow(config)
    sys.exit(app.exec_())
