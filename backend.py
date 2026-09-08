from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import datetime

app = FastAPI(title="Kiosk Admin API")

# Updated Configuration with your custom tools, URLs, and admin password
KIOSK_CONFIGS = {
    "user_001": {
        "allowed_urls": [
            "https://explainshell.com/",
            "https://www.base64decode.org/",
            "https://www.browserling.com/tools/hex-to-ip",
            "https://python.org",
            "https://en.wikipedia.org"
        ],
        "allowed_commands": ["ping 8.8.8.8", "ipconfig", "ifconfig"],
        "tabs": ["ExplainShell", "Base64Decode", "HexToIP", "Python Docs", "Wikipedia", "Terminal"],
        "admin_password": "123"
    }
}

class SecurityLog(BaseModel):
    user_id: str
    event_type: str
    details: str
    timestamp: Optional[str] = None

@app.get("/api/config/{user_id}")
async def get_config(user_id: str):
    config = KIOSK_CONFIGS.get(user_id)
    if not config:
        raise HTTPException(status_code=404, detail="User configuration not found")
    return config

@app.post("/api/logs")
async def receive_log(log: SecurityLog):
    log.timestamp = datetime.datetime.utcnow().isoformat()
    # In production, commit to SQLite/PostgreSQL here
    print(f"[SECURITY ALERT] {log.timestamp} | {log.user_id} | {log.event_type} | {log.details}")
    return {"status": "logged"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)