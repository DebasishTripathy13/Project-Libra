# ProjectLibra - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies
```bash
cd ~/Debasish/ProjectLibra
pip3 install --break-system-packages \
    fastapi uvicorn jinja2 python-multipart \
    psutil aiohttp scikit-learn numpy pandas \
    google-genai
```

### Step 2: Configure Gemini AI

**Get Your API Key:**
1. Visit: https://aistudio.google.com/app/apikey
2. Click "Create API Key"
3. Copy the key

**Set Environment Variable:**
```bash
export GEMINI_API_KEY="AIza..."
```

Or create `.env` file:
```bash
cat > .env << EOF
GEMINI_API_KEY=AIza...
DEFAULT_LLM_PROVIDER=gemini
EOF
```

### Step 3: Initialize Database
```bash
python3 -m src.cli init-db
```

### Step 4: Start Dashboard
```bash
python3 run_dashboard.py
```

### Step 5: Access Dashboard
```
http://localhost:8080
```

---

## ✨ Try These Features

### 1. AI Log Analysis
- Navigate to "Log Analysis" tab
- Click "Analyze with AI" button
- View AI-categorized logs with severity levels

### 2. Tamper Detection Demo
```bash
python3 -m src.cli demo-tamper
```

### 3. ML Anomaly Detection
- Click "ML Status" button in dashboard
- View active models: IsolationForest, BaselineLearner, PatternDetector

### 4. Generate Report
```bash
python3 -m src.cli generate-report --format md
cat reports/security_report_*.md
```

### 5. Configure Log Sources
Edit `config/log_sources.yaml` to customize which logs to monitor:

```yaml
# Enable/disable entire categories
system_logs:
  enabled: true    # journalctl, syslog

auth_logs:
  enabled: true    # auth.log, secure

web_logs:
  enabled: true    # apache, nginx

# Add custom log sources
custom_logs:
  enabled: true
  sources:
    - name: "myapp"
      type: "file"
      path: "/var/log/myapp/app.log"
      enabled: true
      priority: "high"
```

**Reload config without restart:**
```bash
curl -X POST http://localhost:8080/api/log-sources/reload
```

**View configured sources:**
```bash
curl http://localhost:8080/api/log-sources
```

---

## 🛠️ Troubleshooting

### Dashboard Won't Start
```bash
# Check if port 8080 is in use
lsof -i:8080

# Kill existing process
pkill -f run_dashboard

# Restart
python3 run_dashboard.py
```

### Gemini API Not Working
```bash
# Verify API key
echo $GEMINI_API_KEY

# Test connection
python3 -c "
import os
os.environ['GEMINI_API_KEY'] = 'your_key'
from src.llm import LLMFactory
client = LLMFactory.create('gemini')
print('✓ Gemini OK!')
"
```

### No System Logs
```bash
# Add user to log groups
sudo usermod -aG adm,systemd-journal $USER
newgrp systemd-journal
```

---

## 📚 Next Steps

- Read full README.md
- Explore dashboard features
- Check API documentation
- Join our community

**Support:** support@projectlibra.dev
