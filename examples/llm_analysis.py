#!/usr/bin/env python3
"""
ProjectLibra - LLM Integration Example

This script demonstrates how to use different LLM backends
for threat analysis and security reasoning.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.llm import LLMFactory


async def analyze_with_llm(provider: str, events: list):
    """Analyze security events with specified LLM provider."""
    print(f"\n{'='*50}")
    print(f"Analyzing with {provider.upper()}")
    print('='*50)
    
    try:
        # Create LLM client
        llm = LLMFactory.create(provider)
        
        # Format events for analysis
        events_text = "\n".join([
            f"- {e['timestamp']}: {e['type']} - {e['description']}"
            for e in events
        ])
        
        prompt = f"""Analyze these security events and provide:
1. Risk assessment (Critical/High/Medium/Low)
2. Potential attack pattern identification
3. Recommended immediate actions

Events:
{events_text}

Provide a concise security analysis."""

        print(f"\nSending {len(events)} events for analysis...")
        
        response = await llm.generate(prompt)
        
        print(f"\n{provider.upper()} Analysis:")
        print("-" * 40)
        print(response)
        
    except Exception as e:
        print(f"Error with {provider}: {e}")


async def main():
    """Demonstrate LLM integration for security analysis."""
    print("=" * 60)
    print("ProjectLibra - LLM Security Analysis Demo")
    print("=" * 60)
    
    # Sample security events to analyze
    events = [
        {
            "timestamp": "2024-01-15 10:23:45",
            "type": "authentication_failure",
            "description": "Multiple failed SSH logins from IP 203.0.113.50 to user root"
        },
        {
            "timestamp": "2024-01-15 10:24:01",
            "type": "authentication_success",
            "description": "SSH login success from IP 203.0.113.50 to user admin"
        },
        {
            "timestamp": "2024-01-15 10:24:15",
            "type": "process_spawn",
            "description": "Process 'wget' spawned by admin downloading script from external URL"
        },
        {
            "timestamp": "2024-01-15 10:24:30",
            "type": "privilege_escalation",
            "description": "User admin executed 'sudo chmod +s /tmp/backdoor'"
        },
        {
            "timestamp": "2024-01-15 10:25:00",
            "type": "network_connection",
            "description": "Outbound connection to IP 198.51.100.25:4444 established"
        }
    ]
    
    print("\nSample Security Events:")
    print("-" * 40)
    for event in events:
        print(f"  [{event['timestamp']}] {event['type']}")
        print(f"    {event['description']}")
    
    # Try different providers
    # Ollama (local) - Best for air-gapped environments
    await analyze_with_llm("ollama", events)
    
    # Uncomment to try other providers (requires API keys):
    # await analyze_with_llm("openai", events)
    # await analyze_with_llm("groq", events)
    # await analyze_with_llm("gemini", events)
    
    print("\n" + "=" * 60)
    print("LLM Demo Complete!")
    print("=" * 60)
    print("\nTo use other providers, set the appropriate API keys:")
    print("  - OPENAI_API_KEY for OpenAI")
    print("  - GROQ_API_KEY for Groq")
    print("  - GEMINI_API_KEY for Google Gemini")


if __name__ == "__main__":
    asyncio.run(main())
