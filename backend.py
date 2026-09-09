from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
import datetime
import sqlite3
import json

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
            {"name": "Wikipedia", "type": "url", "value": "https://en.wikipedia.org"},
            {"name": "Python Docs", "type": "url", "value": "https://python.org"},
            {"name": "Terminal", "type": "terminal", "value": ""}
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
    <head><meta charset="UTF-8"><title>SentinelShell Fleet Admin</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-900 text-gray-100 font-sans min-h-screen p-8">
        <div class="max-w-6xl mx-auto space-y-8">
            <header class="flex justify-between items-center border-b border-gray-800 pb-4">
                <h1 class="text-2xl font-bold tracking-tight text-emerald-400">SentinelShell Fleet Management</h1>
                <div class="flex items-center space-x-3">
                    <label class="text-sm text-gray-400">Target Client:</label>
                    <select id="client-select" onchange="loadClientData()" class="bg-gray-800 border border-gray-700 text-emerald-300 rounded-lg px-3 py-1.5 text-sm font-mono focus:outline-none"></select>
                    <button id="ban-btn" onclick="toggleBanStatus()" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition"></button>
                </div>
            </header>
            <div class="bg-gray-800/50 border border-gray-800 p-6 rounded-xl shadow-lg">
                <h2 id="form-title" class="text-lg font-semibold mb-4 text-gray-200">Configuration Editor</h2>
                <form id="config-form" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-400 mb-1">Tabs Configuration (JSON Format)</label>
                        <textarea id="tabs-json" rows="6" class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm focus:ring-2 focus:ring-emerald-500 font-mono text-emerald-300"></textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-400 mb-1">Allowed Commands (one per line)</label>
                        <textarea id="allowed-commands" rows="3" class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm focus:ring-2 focus:ring-emerald-500 font-mono"></textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-400 mb-1">Admin Password</label>
                        <input type="text" id="admin-password" class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm focus:ring-2 focus:ring-emerald-500">
                    </div>
                    <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2.5 rounded-lg text-sm transition">Save Client Configuration</button>
                    <span id="save-status" class="ml-3 text-sm text-emerald-400 hidden">Saved successfully!</span>
                </form>
            </div>
            <div class="bg-gray-800/50 border border-gray-800 p-6 rounded-xl shadow-lg">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-lg font-semibold text-gray-200">Fleet Security Logs</h2>
                    <button onclick="fetchLogs()" class="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition">Refresh Logs</button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-sm">
                        <thead><tr class="border-b border-gray-700 text-gray-400"><th class="p-3">Timestamp</th><th class="p-3">Client ID</th><th class="p-3">Event Type</th><th class="p-3">Details</th></tr></thead>
                        <tbody id="logs-table"><tr><td colspan="4" class="p-4 text-center text-gray-500">Loading logs...</td></tr></tbody>
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
                select.innerHTML = clients.map(c => `<option value="${c.user_id}">${c.user_id} (${c.status})</option>`).join('');
                clients.forEach(c => clientStatuses[c.user_id] = c.status);
                updateBanButton();
                loadClientData();
            }
            function updateBanButton() {
                const clientId = document.getElementById('client-select').value;
                const status = clientStatuses[clientId] || 'active';
                const btn = document.getElementById('ban-btn');
                if (status === 'banned') {
                    btn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white transition";
                    btn.innerText = "Unban Client";
                } else {
                    btn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-700 hover:bg-red-600 text-white transition";
                    btn.innerText = "Ban Client";
                }
            }
            async function toggleBanStatus() {
                const clientId = document.getElementById('client-select').value;
                const newStatus = clientStatuses[clientId] === 'banned' ? 'active' : 'banned';
                await fetch(`/api/client/status/${clientId}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: newStatus }) });
                loadClients();
            }
            async function loadClientData() {
                const clientId = document.getElementById('client-select').value;
                updateBanButton();
                document.getElementById('form-title').innerText = `Configuration for ${clientId}`;
                const res = await fetch(`/api/config/${clientId}`);
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
                if (logs.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="p-4 text-center text-gray-500">No logs found.</td></tr>'; return; }
                tbody.innerHTML = logs.map(log => `<tr class="border-b border-gray-800"><td class="p-3 text-xs text-gray-400">${log.timestamp}</td><td class="p-3 text-xs text-emerald-400">${log.user_id}</td><td class="p-3"><span class="bg-red-900/40 text-red-400 px-2 py-0.5 rounded text-xs">${log.event_type}</span></td><td class="p-3 text-xs text-gray-300 break-all">${log.details}</td></tr>`).join('');
            }
            document.getElementById('config-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const clientId = document.getElementById('client-select').value;
                try {
                    const payload = {
                        status: clientStatuses[clientId] || 'active',
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
    uvicorn.run(app, host="0.0.0.0", port=8000)