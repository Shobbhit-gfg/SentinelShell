from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
import datetime
import sqlite3
import json
import os

app = FastAPI(title="SentinelShell Fleet Manager")

DB_FILE = "sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configs (
            user_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'active',
            tabs TEXT,
            allowed_commands TEXT,
            admin_password TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id TEXT,
            event_type TEXT,
            details TEXT
        )
    ''')
    
    cursor.execute("SELECT COUNT(*) FROM configs")
    if cursor.fetchone()[0] == 0:
        default_tabs = [
            {
                "name": "Base64Decode",
                "type": "url",
                "value": "https://www.base64decode.org/"
            },
            {
                "name": "HexToIP Browserling",
                "type": "url",
                "value": "https://www.browserling.com/tools/hex-to-ip"
            },
            {
                "name": "HexToIP CodeBeautify",
                "type": "url",
                "value": "https://codebeautify.org/hex-to-ip-converter"
            },
            {
                "name": "Rulebook",
                "type": "pdf",
                "value": "Photography_and_Filming_Club_Rulebook.pdf"
            },
            {
                "name": "Terminal",
                "type": "terminal",
                "value": ""
            }
        ]
        default_commands = ["ping 8.8.8.8", "ipconfig", "ifconfig"]
        cursor.execute("INSERT INTO configs VALUES (?, ?, ?, ?, ?)", (
            "pc_01",
            "active",
            json.dumps(default_tabs),
            json.dumps(default_commands),
            "123"
        ))
    conn.commit()
    conn.close()

init_db()

class SecurityLog(BaseModel):
    user_id: str
    event_type: str
    details: str
    timestamp: Optional[str] = None

class ConfigUpdate(BaseModel):
    status: Optional[str] = "active"
    tabs: List[Any]
    allowed_commands: List[str]
    admin_password: str

@app.get("/api/config/{user_id}")
async def get_config(user_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT status, tabs, allowed_commands, admin_password FROM configs WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    
    if not row:
        # Auto-provision new client from default template
        cursor.execute("SELECT status, tabs, allowed_commands, admin_password FROM configs LIMIT 1")
        row = cursor.fetchone()
        if row:
            cursor.execute("INSERT INTO configs VALUES (?, ?, ?, ?, ?)", (user_id, "active", row[1], row[2], row[3]))
            conn.commit()
            row = ("active", row[1], row[2], row[3])
            
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Configuration not found")
        
    if row[0] == "banned":
        return {"status": "banned"}

    tabs_data = json.loads(row[1])
    allowed_urls = []
    for t in tabs_data:
        if isinstance(t, dict) and t.get("value"):
            allowed_urls.append(t["value"])
        elif isinstance(t, str):
            allowed_urls.append(t)

    return {
        "status": row[0],
        "tabs": tabs_data,
        "allowed_urls": allowed_urls,
        "allowed_commands": json.loads(row[2]),
        "admin_password": row[3]
    }

@app.put("/api/config/{user_id}")
async def update_config(user_id: str, new_config: ConfigUpdate):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if user_id == "ALL":
        cursor.execute('''
            UPDATE configs SET tabs = ?, allowed_commands = ?, admin_password = ?
        ''', (
            json.dumps(new_config.tabs),
            json.dumps(new_config.allowed_commands),
            new_config.admin_password
        ))
    else:
        cursor.execute('''
            INSERT OR REPLACE INTO configs (user_id, status, tabs, allowed_commands, admin_password)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id,
            new_config.status,
            json.dumps(new_config.tabs),
            json.dumps(new_config.allowed_commands),
            new_config.admin_password
        ))
        
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Configuration for {user_id} updated successfully"}

@app.post("/api/client/status/{user_id}")
async def set_client_status(user_id: str, data: dict):
    new_status = data.get("status")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if user_id == "ALL":
        cursor.execute("UPDATE configs SET status = ?", (new_status,))
    else:
        cursor.execute("UPDATE configs SET status = ? WHERE user_id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"status": "success", "client": user_id, "new_status": new_status}

@app.post("/api/logs")
async def receive_log(log: SecurityLog):
    timestamp = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, user_id, event_type, details) VALUES (?, ?, ?, ?)",
                   (timestamp, log.user_id, log.event_type, log.details))
    conn.commit()
    conn.close()
    print(f"[SECURITY ALERT] {timestamp} | {log.user_id} | {log.event_type} | {log.details}")
    return {"status": "logged"}

@app.get("/api/logs")
async def get_logs(user_id: Optional[str] = None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if user_id and user_id != "ALL":
        cursor.execute("SELECT timestamp, user_id, event_type, details FROM logs WHERE user_id = ? ORDER BY id DESC LIMIT 100", (user_id,))
    else:
        cursor.execute("SELECT timestamp, user_id, event_type, details FROM logs ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [{"timestamp": r[0], "user_id": r[1], "event_type": r[2], "details": r[3]} for r in rows]

@app.get("/api/clients")
async def get_clients():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, status FROM configs")
    rows = cursor.fetchall()
    conn.close()
    return [{"user_id": r[0], "status": r[1]} for r in rows]

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard():
    return """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SentinelShell Fleet Admin</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', sans-serif; }
            .font-mono { font-family: 'JetBrains Mono', monospace; }
        </style>
    </head>
    <body class="bg-zinc-950 text-zinc-100 min-h-screen p-8 selection:bg-emerald-500 selection:text-zinc-950">
        <div class="max-w-6xl mx-auto space-y-8">
            <header class="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-zinc-800 pb-5 gap-4">
                <div>
                    <h1 class="text-2xl font-bold tracking-tight text-emerald-400 flex items-center gap-2">
                        <span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        SentinelShell Fleet Management
                    </h1>
                    <p class="text-xs text-zinc-400 mt-1">Real-time kiosk terminal oversight & remote configuration sync</p>
                </div>
                <div class="flex items-center space-x-3 bg-zinc-900/80 border border-zinc-800 p-2 rounded-xl shadow-sm">
                    <label class="text-xs font-medium text-zinc-400 pl-2">Target Client:</label>
                    <select id="client-select" onchange="loadClientData()" class="bg-zinc-950 border border-zinc-700/80 text-emerald-400 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500/50 transition"></select>
                    <button id="ban-btn" onclick="toggleBanStatus()" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition shadow-sm"></button>
                </div>
            </header>
            
            <div class="bg-zinc-900/60 border border-zinc-800/80 p-6 rounded-2xl shadow-xl backdrop-blur-sm">
                <h2 id="form-title" class="text-base font-semibold mb-5 text-zinc-200 tracking-tight flex items-center gap-2">Configuration Editor</h2>
                <form id="config-form" class="space-y-5">
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">Tabs Configuration (JSON Format)</label>
                        <textarea id="tabs-json" rows="6" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-4 text-xs focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 font-mono text-emerald-300 transition leading-relaxed shadow-inner"></textarea>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                        <div>
                            <label class="block text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">Allowed Commands (one per line)</label>
                            <textarea id="allowed-commands" rows="3" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-4 text-xs focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 font-mono text-zinc-300 transition shadow-inner"></textarea>
                        </div>
                        <div>
                            <label class="block text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">Admin Password</label>
                            <input type="text" id="admin-password" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-3 text-xs focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 font-mono text-zinc-300 transition shadow-inner">
                        </div>
                    </div>
                    <div class="flex items-center pt-2">
                        <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold px-6 py-2.5 rounded-xl text-xs transition shadow-lg shadow-emerald-950/50 active:scale-[0.98]">Save Client Configuration</button>
                        <span id="save-status" class="ml-4 text-xs font-medium text-emerald-400 hidden flex items-center gap-1.5">✓ Saved successfully!</span>
                    </div>
                </form>
            </div>
            
            <div class="bg-zinc-900/60 border border-zinc-800/80 p-6 rounded-2xl shadow-xl backdrop-blur-sm">
                <div class="flex justify-between items-center mb-5">
                    <h2 class="text-base font-semibold text-zinc-200 tracking-tight">Fleet Security Logs</h2>
                    <button onclick="fetchLogs()" class="text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-medium px-3.5 py-1.5 rounded-xl transition border border-zinc-700/50 shadow-sm">Refresh Logs</button>
                </div>
                <div class="overflow-x-auto rounded-xl border border-zinc-800/80 bg-zinc-950/50">
                    <table class="w-full text-left border-collapse text-xs">
                        <thead>
                            <tr class="border-b border-zinc-800 text-zinc-400 bg-zinc-900/40">
                                <th class="p-3.5 font-semibold">Timestamp</th>
                                <th class="p-3.5 font-semibold">Client ID</th>
                                <th class="p-3.5 font-semibold">Event Type</th>
                                <th class="p-3.5 font-semibold">Details</th>
                            </tr>
                        </thead>
                        <tbody id="logs-table">
                            <tr><td colspan="4" class="p-6 text-center text-zinc-500">Loading logs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <script>
            let clientStatuses = {};
            async function loadClients() {
                const res = await fetch('/api/clients');
                const clients = await res.json();
                const select = document.getElementById('client-select');
                
                let optionsHtml = '<option value="ALL">🌐 All Terminals (Broadcast)</option>';
                optionsHtml += clients.map(c => `<option value="${c.user_id}">${c.user_id} (${c.status})</option>`).join('');
                select.innerHTML = optionsHtml;
                
                clients.forEach(c => clientStatuses[c.user_id] = c.status);
                updateBanButton();
                loadClientData();
            }
            function updateBanButton() {
                const clientId = document.getElementById('client-select').value;
                const btn = document.getElementById('ban-btn');
                if (clientId === 'ALL') {
                    btn.style.display = 'none';
                    return;
                }
                btn.style.display = 'inline-block';
                const status = clientStatuses[clientId] || 'active';
                if (status === 'banned') {
                    btn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-zinc-950 transition shadow-sm";
                    btn.innerText = "Unban Client";
                } else {
                    btn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-600/90 hover:bg-rose-500 text-white transition shadow-sm";
                    btn.innerText = "Ban Client";
                }
            }
            async function toggleBanStatus() {
                const clientId = document.getElementById('client-select').value;
                if (clientId === 'ALL') return;
                const newStatus = clientStatuses[clientId] === 'banned' ? 'active' : 'banned';
                await fetch(`/api/client/status/${clientId}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: newStatus }) });
                loadClients();
            }
            async function loadClientData() {
                const clientId = document.getElementById('client-select').value;
                updateBanButton();
                if (clientId === 'ALL') {
                    document.getElementById('form-title').innerText = 'Configuration for ALL Terminals (Broadcast Mode)';
                } else {
                    document.getElementById('form-title').innerText = `Configuration for ${clientId}`;
                }
                const res = await fetch(`/api/config/${clientId === 'ALL' ? 'pc_01' : clientId}`);
                const data = await res.json();
                document.getElementById('tabs-json').value = JSON.stringify(data.tabs, null, 4);
                document.getElementById('allowed-commands').value = data.allowed_commands.join('\\n');
                document.getElementById('admin-password').value = data.admin_password;
            }
            async function fetchLogs() {
                const clientId = document.getElementById('client-select').value;
                const res = await fetch(`/api/logs?user_id=${clientId}`);
                const logs = await res.json();
                const tbody = document.getElementById('logs-table');
                if (logs.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="p-6 text-center text-zinc-500">No logs found.</td></tr>'; return; }
                tbody.innerHTML = logs.map(log => `<tr class="border-b border-zinc-800/60 hover:bg-zinc-900/30 transition"><td class="p-3.5 font-mono text-[11px] text-zinc-400">${log.timestamp}</td><td class="p-3.5 font-mono text-[11px] text-emerald-400">${log.user_id}</td><td class="p-3.5"><span class="bg-rose-950/80 text-rose-400 border border-rose-800/50 px-2 py-0.5 rounded-md text-[10px] font-mono">${log.event_type}</span></td><td class="p-3.5 font-mono text-[11px] text-zinc-300 break-all">${log.details}</td></tr>`).join('');
            }
            document.getElementById('config-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const clientId = document.getElementById('client-select').value;
                try {
                    const payload = {
                        status: clientId === 'ALL' ? 'active' : (clientStatuses[clientId] || 'active'),
                        tabs: JSON.parse(document.getElementById('tabs-json').value),
                        allowed_commands: document.getElementById('allowed-commands').value.split('\\n').map(s => s.trim()).filter(Boolean),
                        admin_password: document.getElementById('admin-password').value
                    };
                    const res = await fetch(`/api/config/${clientId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                    if (res.ok) {
                        const status = document.getElementById('save-status');
                        status.classList.remove('hidden');
                        setTimeout(() => status.classList.add('hidden'), 3000);
                    }
                } catch (err) { alert("Invalid JSON format in Tabs Configuration!"); }
            });
            loadClients();
            setInterval(fetchLogs, 5000);
        </script>
    </body>
    </html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)