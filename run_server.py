#!/usr/bin/env python3
"""
ProjectLibra - Web Server
Run this to start the API server with web dashboard
"""

import os
import tempfile
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime

from src.database.dual_db_manager import DualDatabaseManager
from src.agents.maintenance_agent import MaintenanceAgent, ActionType

# Create app
app = FastAPI(
    title="ProjectLibra",
    description="Agentic AI Security Platform",
    version="1.0.0",
)

# Setup databases
DATA_DIR = os.path.join(tempfile.gettempdir(), 'projectlibra_data')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, 'backup'), exist_ok=True)

db_manager = DualDatabaseManager(
    primary_db_path=os.path.join(DATA_DIR, 'primary.db'),
    backup_db_path=os.path.join(DATA_DIR, 'backup', 'immutable.db'),
)

# Maintenance agent
maintenance_agent = MaintenanceAgent(
    auto_remediate=False,
    dry_run=True,
    allowed_actions={ActionType.CHECK_UPDATES, ActionType.PATCH_REPORT, ActionType.LOG_EVENT}
)

# HTML Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProjectLibra - Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, sans-serif; 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #eee;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 { color: #00d4ff; font-size: 2em; }
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        }
        .status-ok { background: #00c853; color: #000; }
        .status-warning { background: #ffc107; color: #000; }
        .status-error { background: #ff5252; color: #fff; }
        
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .card h2 { color: #00d4ff; margin-bottom: 15px; font-size: 1.2em; }
        .card h3 { color: #aaa; margin-bottom: 10px; font-size: 0.9em; }
        
        .metric { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .metric:last-child { border-bottom: none; }
        .metric-value { font-weight: bold; color: #00d4ff; }
        .metric-value.danger { color: #ff5252; }
        .metric-value.warning { color: #ffc107; }
        .metric-value.success { color: #00c853; }
        
        .log-entry { 
            padding: 8px; 
            margin: 5px 0; 
            background: rgba(0,0,0,0.2); 
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.85em;
        }
        .log-entry.error { border-left: 3px solid #ff5252; }
        .log-entry.warning { border-left: 3px solid #ffc107; }
        .log-entry.info { border-left: 3px solid #00d4ff; }
        
        button {
            background: #00d4ff;
            color: #000;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
        }
        button:hover { background: #00a0cc; }
        button.danger { background: #ff5252; color: #fff; }
        button.danger:hover { background: #cc4040; }
        
        .refresh-btn { position: fixed; bottom: 20px; right: 20px; }
        
        #integrity-status { font-size: 3em; text-align: center; padding: 20px; }
        
        .update-item { 
            padding: 5px 10px; 
            margin: 3px 0; 
            background: rgba(0,0,0,0.2); 
            border-radius: 3px;
            font-size: 0.85em;
        }
        .update-item.security { border-left: 3px solid #ff5252; }
        
        .agent-status { display: flex; align-items: center; gap: 10px; margin: 10px 0; }
        .agent-dot { width: 10px; height: 10px; border-radius: 50%; }
        .agent-dot.active { background: #00c853; }
        .agent-dot.idle { background: #ffc107; }
        .agent-dot.error { background: #ff5252; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ ProjectLibra</h1>
            <span class="status-badge status-ok" id="system-status">System Online</span>
        </header>
        
        <div class="grid">
            <!-- Database Integrity -->
            <div class="card">
                <h2>🔒 Database Integrity</h2>
                <div id="integrity-status">✅</div>
                <div id="integrity-details">
                    <div class="metric">
                        <span>Total Records</span>
                        <span class="metric-value" id="total-records">-</span>
                    </div>
                    <div class="metric">
                        <span>Valid Records</span>
                        <span class="metric-value success" id="valid-records">-</span>
                    </div>
                    <div class="metric">
                        <span>Tampered Records</span>
                        <span class="metric-value" id="tampered-records">-</span>
                    </div>
                    <div class="metric">
                        <span>Missing Records</span>
                        <span class="metric-value" id="missing-records">-</span>
                    </div>
                    <div class="metric">
                        <span>Chain Valid</span>
                        <span class="metric-value" id="chain-valid">-</span>
                    </div>
                </div>
                <button onclick="checkIntegrity()">🔍 Check Integrity</button>
            </div>
            
            <!-- System Updates -->
            <div class="card">
                <h2>📦 System Updates</h2>
                <div class="metric">
                    <span>Package Manager</span>
                    <span class="metric-value" id="pkg-manager">-</span>
                </div>
                <div class="metric">
                    <span>Updates Available</span>
                    <span class="metric-value" id="updates-count">-</span>
                </div>
                <div class="metric">
                    <span>Security Updates</span>
                    <span class="metric-value danger" id="security-count">-</span>
                </div>
                <h3>Available Updates:</h3>
                <div id="updates-list" style="max-height: 200px; overflow-y: auto;"></div>
                <button onclick="checkUpdates()">🔄 Check Updates</button>
            </div>
            
            <!-- AI Agents -->
            <div class="card">
                <h2>🤖 AI Agents</h2>
                <div class="agent-status">
                    <span class="agent-dot active"></span>
                    <span>ObservationAgent - Monitoring logs</span>
                </div>
                <div class="agent-status">
                    <span class="agent-dot active"></span>
                    <span>CorrelationAgent - Linking events</span>
                </div>
                <div class="agent-status">
                    <span class="agent-dot idle"></span>
                    <span>ThreatAgent - LLM reasoning</span>
                </div>
                <div class="agent-status">
                    <span class="agent-dot active"></span>
                    <span>MaintenanceAgent - Remediation</span>
                </div>
                <div class="agent-status">
                    <span class="agent-dot active"></span>
                    <span>LearningAgent - Adapting</span>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="card">
                <h2>📋 Recent Activity</h2>
                <div id="activity-log">
                    <div class="log-entry info">[INFO] System started</div>
                    <div class="log-entry info">[INFO] Database initialized</div>
                    <div class="log-entry info">[INFO] Agents loaded</div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="card">
                <h2>⚡ Quick Actions</h2>
                <button onclick="runDemo('tamper')">🔒 Demo Tamper Detection</button>
                <button onclick="runDemo('threat')">🤖 Demo AI Analysis</button>
                <button onclick="checkUpdates()">📦 Check Updates</button>
                <button class="danger" onclick="alert('Requires approval workflow')">⚠️ Apply Security Patches</button>
            </div>
            
            <!-- System Info -->
            <div class="card">
                <h2>ℹ️ System Info</h2>
                <div class="metric">
                    <span>Platform</span>
                    <span class="metric-value" id="platform">Linux</span>
                </div>
                <div class="metric">
                    <span>API Version</span>
                    <span class="metric-value">1.0.0</span>
                </div>
                <div class="metric">
                    <span>Database</span>
                    <span class="metric-value">Dual SQLite</span>
                </div>
                <div class="metric">
                    <span>LLM Provider</span>
                    <span class="metric-value">Gemini 2.5</span>
                </div>
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshAll()">🔄 Refresh All</button>
    
    <script>
        async function checkIntegrity() {
            addLog('Checking database integrity...', 'info');
            try {
                const response = await fetch('/api/integrity');
                const data = await response.json();
                
                document.getElementById('total-records').textContent = data.total_records;
                document.getElementById('valid-records').textContent = data.valid_records;
                document.getElementById('tampered-records').textContent = data.tampered_records;
                document.getElementById('missing-records').textContent = data.missing_records;
                document.getElementById('chain-valid').textContent = data.chain_valid ? '✅ Yes' : '❌ No';
                
                const tamperedEl = document.getElementById('tampered-records');
                const missingEl = document.getElementById('missing-records');
                
                if (data.tampered_records > 0) {
                    tamperedEl.classList.add('danger');
                    document.getElementById('integrity-status').textContent = '⚠️';
                    addLog(`ALERT: ${data.tampered_records} tampered records detected!`, 'error');
                } else {
                    tamperedEl.classList.remove('danger');
                    tamperedEl.classList.add('success');
                }
                
                if (data.missing_records > 0) {
                    missingEl.classList.add('warning');
                    addLog(`WARNING: ${data.missing_records} missing records`, 'warning');
                } else {
                    missingEl.classList.remove('warning');
                    missingEl.classList.add('success');
                }
                
                if (data.tampered_records === 0 && data.missing_records === 0) {
                    document.getElementById('integrity-status').textContent = '✅';
                    addLog('Integrity check passed', 'info');
                }
            } catch (e) {
                addLog('Error checking integrity: ' + e.message, 'error');
            }
        }
        
        async function checkUpdates() {
            addLog('Checking for system updates...', 'info');
            try {
                const response = await fetch('/api/updates');
                const data = await response.json();
                
                document.getElementById('pkg-manager').textContent = data.package_manager;
                document.getElementById('updates-count').textContent = data.updates_available;
                document.getElementById('security-count').textContent = data.security_updates || '?';
                
                const listEl = document.getElementById('updates-list');
                listEl.innerHTML = '';
                
                (data.packages || []).slice(0, 10).forEach(pkg => {
                    const div = document.createElement('div');
                    div.className = 'update-item' + (pkg.toLowerCase().includes('security') ? ' security' : '');
                    div.textContent = pkg.split('/')[0];
                    listEl.appendChild(div);
                });
                
                if (data.updates_available > 10) {
                    const div = document.createElement('div');
                    div.className = 'update-item';
                    div.textContent = `... and ${data.updates_available - 10} more`;
                    listEl.appendChild(div);
                }
                
                addLog(`Found ${data.updates_available} updates available`, 'info');
            } catch (e) {
                addLog('Error checking updates: ' + e.message, 'error');
            }
        }
        
        function addLog(message, level) {
            const logEl = document.getElementById('activity-log');
            const entry = document.createElement('div');
            entry.className = 'log-entry ' + level;
            const time = new Date().toLocaleTimeString();
            entry.textContent = `[${time}] ${message}`;
            logEl.insertBefore(entry, logEl.firstChild);
            
            // Keep only last 20 entries
            while (logEl.children.length > 20) {
                logEl.removeChild(logEl.lastChild);
            }
        }
        
        function runDemo(type) {
            if (type === 'tamper') {
                addLog('Run: python -m src.cli demo tamper', 'info');
                alert('Run in terminal:\\npython -m src.cli demo tamper');
            } else if (type === 'threat') {
                addLog('Run: python demo_llm_analysis.py', 'info');
                alert('Run in terminal:\\npython demo_llm_analysis.py');
            }
        }
        
        function refreshAll() {
            checkIntegrity();
            checkUpdates();
        }
        
        // Initial load
        setTimeout(refreshAll, 500);
    </script>
</body>
</html>
"""

# Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the web dashboard."""
    return DASHBOARD_HTML

@app.get("/api/health")
async def health():
    """Health check."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/integrity")
async def check_integrity():
    """Check database integrity."""
    report = db_manager.full_integrity_audit()
    return {
        "total_records": report.total_records_checked,
        "valid_records": report.valid_records,
        "tampered_records": report.tampered_records,
        "missing_records": report.missing_records,
        "chain_valid": report.chain_valid,
        "status": report.overall_status,
    }

@app.get("/api/updates")
async def check_updates():
    """Check for system updates."""
    from src.agents.maintenance_agent import MaintenanceAction, ActionType, ActionStatus
    
    action = MaintenanceAction(
        action_id='web-check-001',
        action_type=ActionType.CHECK_UPDATES,
        target='system',
        parameters={},
    )
    
    import asyncio
    await maintenance_agent._execute_check_updates(action)
    
    if action.status == ActionStatus.FAILED:
        return {"error": action.error, "package_manager": "unknown", "updates_available": 0}
    
    result = action.result
    if isinstance(result, dict):
        return result
    return {"message": result, "package_manager": "unknown", "updates_available": 0}

@app.get("/api/status")
async def status():
    """System status."""
    return {
        "running": True,
        "platform": maintenance_agent._platform,
        "package_manager": maintenance_agent._detect_package_manager(),
        "timestamp": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  ProjectLibra Web Dashboard")
    print("=" * 60)
    print(f"\n🌐 Open in browser: http://localhost:8080")
    print(f"📚 API Docs: http://localhost:8080/docs")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8080)
