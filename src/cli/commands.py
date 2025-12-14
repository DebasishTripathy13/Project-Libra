"""
CLI Commands for ProjectLibra.

Provides command-line interface using Click.
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from ..config import ProjectLibraConfig, generate_sample_config
from ..database.dual_db_manager import DualDatabaseManager
from ..main import ProjectLibra


@click.group()
@click.version_option(version='1.0.0', prog_name='ProjectLibra')
@click.option('-c', '--config', 'config_path', help='Path to configuration file')
@click.pass_context
def cli(ctx, config_path: Optional[str]):
    """ProjectLibra - Agentic AI Security Platform CLI."""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config_path


@cli.command()
@click.pass_context
def run(ctx):
    """Start the ProjectLibra platform."""
    config_path = ctx.obj.get('config_path')
    
    try:
        config = ProjectLibraConfig.load(config_path)
        app = ProjectLibra(config)
        asyncio.run(app.run())
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', default='config.yaml.sample', help='Output file path')
def init(output: str):
    """Generate a sample configuration file."""
    generate_sample_config(output)
    click.echo(f"Sample configuration written to {output}")
    click.echo("Copy to config.yaml and customize for your environment.")


@cli.command()
@click.pass_context
def validate(ctx):
    """Validate configuration file."""
    config_path = ctx.obj.get('config_path')
    
    try:
        config = ProjectLibraConfig.load(config_path)
        errors = config.validate()
        
        if errors:
            click.echo("Configuration errors:", err=True)
            for error in errors:
                click.echo(f"  ✗ {error}", err=True)
            sys.exit(1)
        else:
            click.echo("✓ Configuration is valid")
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.group()
def db():
    """Database management commands."""
    pass


@db.command('check')
@click.pass_context
def db_check(ctx):
    """Check database integrity."""
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    click.echo("Checking database integrity...")
    
    db_manager = DualDatabaseManager(
        primary_db_path=config.database.primary_path,
        backup_db_path=config.database.backup_path,
    )
    
    report = db_manager.full_integrity_audit()
    
    click.echo("\nIntegrity Check Results:")
    click.echo(f"  Verified records: {report.total_records_checked}")
    click.echo(f"  Valid records:    {report.valid_records}")
    click.echo(f"  Missing records:  {report.missing_records}")
    click.echo(f"  Tampered records: {report.tampered_records}")
    click.echo(f"  Chain valid:      {report.chain_valid}")
    click.echo(f"  Status:           {report.overall_status}")
    
    if report.issues:
        click.echo("\n  Issues found:")
        for issue in report.issues[:10]:
            click.echo(f"    - [{issue['severity']}] {issue['message']}")
        if len(report.issues) > 10:
            click.echo(f"    ... and {len(report.issues) - 10} more")
    
    if report.tampered_records == 0 and report.missing_records == 0:
        click.echo("\n✓ Database integrity verified")
    else:
        click.echo("\n✗ Database integrity issues detected!", err=True)
        sys.exit(1)


@db.command('forensic')
@click.argument('record_id', type=int)
@click.pass_context
def db_forensic(ctx, record_id: int):
    """Get forensic comparison for a tampered record."""
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    db_manager = DualDatabaseManager(
        primary_db_path=config.database.primary_path,
        backup_db_path=config.database.backup_path,
    )
    
    forensic = db_manager.get_forensic_comparison(record_id)
    
    if not forensic:
        click.echo(f"Record {record_id} not found or not tampered")
        sys.exit(1)
    
    click.echo(f"\nForensic Analysis for Record {record_id}:")
    click.echo("-" * 50)
    
    click.echo("\nOriginal (Immutable Backup):")
    for key, value in forensic.get('original', {}).items():
        click.echo(f"  {key}: {value}")
    
    click.echo("\nCurrent (Primary DB):")
    for key, value in forensic.get('current', {}).items():
        click.echo(f"  {key}: {value}")
    
    click.echo("\nChanges:")
    for change in forensic.get('changes', []):
        click.echo(f"  • {change}")


@db.command('stats')
@click.pass_context
def db_stats(ctx):
    """Show database statistics."""
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    db_manager = DualDatabaseManager(
        primary_db_path=config.database.primary_path,
        backup_db_path=config.database.backup_path,
    )
    
    # Get counts using proper methods
    primary_count = len(db_manager.primary_db.get_all_event_ids())
    backup_count = db_manager.backup_db.get_record_count()
    
    click.echo("\nDatabase Statistics:")
    click.echo(f"  Primary DB path:  {config.database.primary_path}")
    click.echo(f"  Backup DB path:   {config.database.backup_path}")
    click.echo(f"  Primary records:  {primary_count}")
    click.echo(f"  Backup records:   {backup_count}")
    
    # File sizes
    primary_size = Path(config.database.primary_path).stat().st_size / 1024
    backup_size = Path(config.database.backup_path).stat().st_size / 1024
    click.echo(f"  Primary size:     {primary_size:.1f} KB")
    click.echo(f"  Backup size:      {backup_size:.1f} KB")


@cli.group()
def analyze():
    """Analysis commands."""
    pass


@analyze.command('log')
@click.argument('message')
@click.option('--source', '-s', default='cli', help='Log source')
@click.pass_context
def analyze_log(ctx, message: str, source: str):
    """Analyze a log message."""
    from ..ml.feature_extractor import FeatureExtractor
    from ..ml.pattern_detector import PatternDetector
    
    extractor = FeatureExtractor()
    detector = PatternDetector()
    
    # Extract features
    features = extractor.extract_log_features(message, source=source)
    
    click.echo("\nFeature Analysis:")
    click.echo("-" * 40)
    
    # Show key features
    key_features = [
        'severity_score', 'max_pattern_score', 'pattern_count',
        'entropy', 'ip_count', 'has_sensitive_path'
    ]
    for key in key_features:
        if key in features.features:
            click.echo(f"  {key}: {features.features[key]:.3f}")
    
    # Pattern detection
    patterns = detector.detect_patterns(log_message=message)
    
    if patterns:
        click.echo("\nDetected Patterns:")
        for p in patterns:
            click.echo(f"  • {p.pattern_name} (confidence: {p.confidence:.2f})")
            click.echo(f"    Category: {p.category.value}")
            click.echo(f"    Severity: {p.severity:.2f}")
    else:
        click.echo("\nNo suspicious patterns detected")


@analyze.command('process')
@click.argument('name')
@click.option('--cmdline', '-c', default='', help='Command line')
@click.option('--user', '-u', default='unknown', help='User running process')
@click.pass_context
def analyze_process(ctx, name: str, cmdline: str, user: str):
    """Analyze a process."""
    from ..ml.feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    
    features = extractor.extract_process_features(
        pid=0,
        name=name,
        cmdline=cmdline or name,
        user=user,
        cpu_percent=0,
        memory_percent=0,
    )
    
    click.echo(f"\nProcess Analysis: {name}")
    click.echo("-" * 40)
    
    key_features = [
        'is_suspicious_name', 'has_suspicious_in_cmdline',
        'is_root', 'has_shell_operators', 'has_encoded_data'
    ]
    
    for key in key_features:
        if key in features.features:
            value = features.features[key]
            indicator = "⚠️ " if value > 0 else "  "
            click.echo(f"{indicator}{key}: {value:.0f}")


@cli.group()
def demo():
    """Demonstration commands."""
    pass


@demo.command('tamper')
@click.pass_context
def demo_tamper(ctx):
    """Run tamper detection demonstration."""
    import uuid
    
    click.echo("\n" + "=" * 60)
    click.echo("  ProjectLibra Tamper Detection Demo")
    click.echo("=" * 60)
    
    # Use temporary databases for demo
    import tempfile
    import os
    
    temp_dir = tempfile.mkdtemp()
    primary_path = os.path.join(temp_dir, 'demo_primary.db')
    backup_path = os.path.join(temp_dir, 'demo_backup.db')
    
    db_manager = DualDatabaseManager(
        primary_db_path=primary_path,
        backup_db_path=backup_path,
    )
    
    click.echo("\n1. Adding sample security events...")
    
    # Store event IDs for later use
    event_ids = []
    sample_events = [
        {'source': 'auth', 'event_type': 'login', 'severity': 'info', 
         'host_id': 'server01', 'raw_data': {'message': 'User admin logged in', 'user': 'admin'}},
        {'source': 'syslog', 'event_type': 'alert', 'severity': 'warning', 
         'host_id': 'server01', 'raw_data': {'message': 'High CPU usage detected', 'cpu': 95}},
        {'source': 'auth', 'event_type': 'login_failed', 'severity': 'error', 
         'host_id': 'server01', 'raw_data': {'message': 'Failed login attempt for root', 'user': 'root'}},
    ]
    
    for event in sample_events:
        event_id = str(uuid.uuid4())
        event_ids.append(event_id)
        db_manager.store_event(
            event_id=event_id,
            timestamp=datetime.now(),
            source=event['source'],
            event_type=event['event_type'],
            severity=event['severity'],
            host_id=event['host_id'],
            raw_data=event['raw_data'],
            normalized_data={}
        )
        click.echo(f"   Added: {event['raw_data']['message'][:40]}...")
    
    click.echo("\n2. Verifying initial integrity...")
    report = db_manager.full_integrity_audit()
    click.echo(f"   Records: {report.total_records_checked}, Tampered: {report.tampered_records}, Missing: {report.missing_records}")
    
    click.echo("\n3. Simulating attacker modifying record 2...")
    # Use proper update method
    db_manager.primary_db.update_event(event_ids[1], {
        'raw_data': {'message': 'MODIFIED BY ATTACKER', 'hacked': True}
    })
    click.echo("   ✗ Attacker modified record 2")
    
    click.echo("\n4. Checking integrity after tampering...")
    report = db_manager.full_integrity_audit()
    click.echo(f"   Records: {report.total_records_checked}, Tampered: {report.tampered_records}, Missing: {report.missing_records}")
    
    if report.tampered_records > 0:
        click.echo("\n5. 🚨 TAMPERING DETECTED!")
        click.echo("   Forensic analysis:")
        
        tampered = db_manager.get_tampered_records()
        for record in tampered:
            if record['backup_data'] and record['primary_data']:
                original_msg = record['backup_data'].get('raw_data', {}).get('message', 'N/A')
                current_msg = record['primary_data'].get('raw_data', {}).get('message', 'N/A')
                click.echo(f"\n   Original: {original_msg}")
                click.echo(f"   Modified: {current_msg}")
    
    click.echo("\n6. Simulating attacker deleting record 1...")
    db_manager.primary_db.delete_event(event_ids[0])
    click.echo("   ✗ Attacker deleted record 1")
    
    click.echo("\n7. Final integrity check...")
    report = db_manager.full_integrity_audit()
    click.echo(f"   Records: {report.total_records_checked}, Tampered: {report.tampered_records}, Missing: {report.missing_records}")
    
    if report.missing_records > 0:
        click.echo("\n   🚨 DELETION DETECTED!")
        missing_ids = [issue['record_id'] for issue in report.issues if issue['type'] == 'deleted_from_primary']
        click.echo(f"   Missing record IDs: {missing_ids}")
    
    click.echo("\n" + "=" * 60)
    click.echo("  Demo Complete - Tamper detection working!")
    click.echo("=" * 60 + "\n")
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


@demo.command('anomaly')
@click.pass_context
def demo_anomaly(ctx):
    """Run anomaly detection demonstration."""
    from ..ml.feature_extractor import FeatureExtractor
    from ..ml.anomaly_detector import AnomalyDetector
    from ..ml.baseline_learner import BaselineLearner
    
    click.echo("\n" + "=" * 60)
    click.echo("  ProjectLibra Anomaly Detection Demo")
    click.echo("=" * 60)
    
    extractor = FeatureExtractor()
    learner = BaselineLearner()
    detector = AnomalyDetector(baseline_learner=learner)
    
    click.echo("\n1. Training baseline on normal logs...")
    
    normal_logs = [
        "User john logged in successfully",
        "Session started for user mary",
        "Scheduled backup completed",
        "System health check passed",
        "Database connection established",
    ] * 50  # Generate 250 samples
    
    for msg in normal_logs:
        features = extractor.extract_log_features(msg)
        learner.learn(features)
    
    click.echo(f"   Trained on {learner.get_profile('log').sample_count} samples")
    
    click.echo("\n2. Testing normal log...")
    normal_test = "User alice logged in successfully"
    features = extractor.extract_log_features(normal_test)
    result = detector.detect(features)
    click.echo(f"   Message: {normal_test}")
    click.echo(f"   Anomaly: {result.is_anomaly}, Score: {result.anomaly_score:.3f}")
    
    click.echo("\n3. Testing suspicious log...")
    suspicious_test = "Failed password for invalid user root from 192.168.1.100"
    features = extractor.extract_log_features(suspicious_test)
    result = detector.detect(features)
    click.echo(f"   Message: {suspicious_test}")
    click.echo(f"   Anomaly: {result.is_anomaly}, Score: {result.anomaly_score:.3f}")
    click.echo(f"   Severity: {result.severity.value}")
    if result.reasons:
        click.echo("   Reasons:")
        for reason in result.reasons[:3]:
            click.echo(f"     • {reason}")
    
    click.echo("\n" + "=" * 60)
    click.echo("  Demo Complete")
    click.echo("=" * 60 + "\n")


@cli.command()
@click.pass_context
def status(ctx):
    """Show quick status of the system."""
    config_path = ctx.obj.get('config_path')
    
    try:
        config = ProjectLibraConfig.load(config_path)
        
        click.echo("\nProjectLibra Status")
        click.echo("-" * 40)
        click.echo(f"Environment:  {config.environment}")
        click.echo(f"Data Dir:     {config.data_dir}")
        click.echo(f"LLM:          {config.llm.provider if config.llm.enabled else 'Disabled'}")
        click.echo(f"Auto-Remedy:  {'Enabled' if config.agents.auto_remediate else 'Disabled'}")
        click.echo(f"API:          Port {config.api.port if config.api.enabled else 'Disabled'}")
        
        # Check database
        if Path(config.database.primary_path).exists():
            db_manager = DualDatabaseManager(
                primary_db_path=config.database.primary_path,
                backup_db_path=config.database.backup_path,
            )
            report = db_manager.full_integrity_audit()
            db_healthy = report.tampered_records == 0 and report.missing_records == 0
            click.echo(f"Database:     {'✓ Healthy' if db_healthy else '✗ Issues detected'}")
        else:
            click.echo("Database:     Not initialized")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ========== AI COMMANDS ==========

@cli.group()
def ai():
    """AI-powered analysis commands."""
    pass


@ai.command('analyze-logs')
@click.option('--limit', '-n', default=50, help='Number of log entries to analyze')
@click.option('--provider', '-p', default='gemini', help='LLM provider (gemini, openai, ollama)')
@click.option('--output', '-o', help='Output file for report (markdown)')
@click.pass_context
def ai_analyze_logs(ctx, limit: int, provider: str, output: str):
    """Analyze system logs with AI and categorize by severity."""
    from ..services.log_source_loader import LogSourceLoader
    from ..services.log_analyzer import LogAnalyzer
    from ..llm import LLMFactory
    from ..llm.base_client import LLMConfig
    import os
    
    click.echo("\n" + "=" * 60)
    click.echo("  ProjectLibra AI Log Analysis")
    click.echo("=" * 60)
    
    # Load logs from configured sources
    click.echo("\n1. Fetching logs from configured sources...")
    loader = LogSourceLoader()
    logs_by_source = loader.fetch_logs(limit)
    
    if not logs_by_source:
        click.echo("   No logs found. Check config/log_sources.yaml")
        return
    
    total_lines = sum(len(c.strip().split('\n')) for c in logs_by_source.values())
    click.echo(f"   Found {total_lines} log entries from {len(logs_by_source)} sources")
    
    # Analyze with local analyzer first
    click.echo("\n2. Running pattern analysis...")
    analyzer = LogAnalyzer()
    combined_logs = "\n".join(logs_by_source.values())
    analysis = analyzer.analyze_text(combined_logs)
    
    click.echo(f"   Entries analyzed: {len(analysis.recent_entries)}")
    click.echo(f"   Patterns matched: {len(analysis.matched_patterns)}")
    
    # Get API key
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    api_key = None
    if provider == 'gemini':
        api_key = os.environ.get('GEMINI_API_KEY') or (config.llm.gemini.api_key if hasattr(config.llm, 'gemini') else None)
    elif provider == 'openai':
        api_key = os.environ.get('OPENAI_API_KEY') or (config.llm.openai.api_key if hasattr(config.llm, 'openai') else None)
    
    if not api_key and provider not in ['ollama']:
        click.echo(f"\n⚠️  No API key found for {provider}. Set {provider.upper()}_API_KEY environment variable.")
        click.echo("   Showing pattern analysis only.\n")
        _show_pattern_results(analysis)
        return
    
    # AI Analysis
    click.echo(f"\n3. Running AI analysis with {provider}...")
    
    # Get default model for provider
    default_models = {
        'gemini': 'gemini-flash-latest',
        'openai': 'gpt-4',
        'ollama': 'llama2',
        'groq': 'llama-3.1-70b-versatile'
    }
    model = default_models.get(provider, 'gemini-flash-latest')
    
    try:
        llm = LLMFactory.create(provider=provider, model=model, api_key=api_key)
        
        # Prepare prompt
        sample_logs = combined_logs[:8000]  # Limit context
        prompt = f"""Analyze these security logs and provide:
1. SEVERITY SUMMARY: Count of Critical/High/Medium/Low events
2. TOP THREATS: List the top 3 most concerning patterns
3. RECOMMENDATIONS: 3 specific actions to take
4. RISK SCORE: Overall risk score 1-10 with explanation

Logs:
{sample_logs}

Provide a concise, actionable security assessment."""

        response = asyncio.run(llm.generate(prompt))
        ai_report = response.content
        
        click.echo("\n" + "=" * 60)
        click.echo("  AI Security Assessment")
        click.echo("=" * 60)
        click.echo(ai_report)
        
        # Save report if output specified
        if output:
            report_content = f"""# ProjectLibra AI Security Report
Generated: {datetime.now().isoformat()}
Provider: {provider}
Log Sources: {', '.join(logs_by_source.keys())}
Total Entries: {total_lines}

## AI Analysis

{ai_report}

## Pattern Detection

Patterns Found: {len(analysis.patterns)}

### Detected Patterns:
"""
            for pattern in analysis.patterns[:10]:
                report_content += f"- {pattern}\n"
            
            with open(output, 'w') as f:
                f.write(report_content)
            click.echo(f"\n✓ Report saved to {output}")
        
    except Exception as e:
        click.echo(f"\n✗ AI analysis failed: {e}")
        click.echo("   Showing pattern analysis only.\n")
        _show_pattern_results(analysis)


@ai.command('categorize')
@click.argument('log_message')
@click.option('--provider', '-p', default='gemini', help='LLM provider')
@click.pass_context
def ai_categorize(ctx, log_message: str, provider: str):
    """Categorize a single log message with AI."""
    from ..llm import LLMFactory
    from ..llm.base_client import LLMConfig
    import os
    
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    api_key = None
    if provider == 'gemini':
        api_key = os.environ.get('GEMINI_API_KEY') or (config.llm.gemini.api_key if hasattr(config.llm, 'gemini') else None)
    elif provider == 'openai':
        api_key = os.environ.get('OPENAI_API_KEY')
    
    if not api_key and provider not in ['ollama']:
        click.echo(f"Error: No API key for {provider}. Set {provider.upper()}_API_KEY")
        sys.exit(1)
    
    prompt = f"""Categorize this log entry:
"{log_message}"

Respond in this exact format:
SEVERITY: [Critical/High/Medium/Low]
CATEGORY: [Authentication/System/Network/Application/Security]
THREAT: [Yes/No]
SUMMARY: [One sentence description]"""

    # Get default model for provider
    default_models = {
        'gemini': 'gemini-flash-latest',
        'openai': 'gpt-4',
        'ollama': 'llama2',
        'groq': 'llama-3.1-70b-versatile'
    }
    model = default_models.get(provider, 'gemini-flash-latest')
    
    try:
        llm = LLMFactory.create(provider=provider, model=model, api_key=api_key)
        response = asyncio.run(llm.generate(prompt))
        
        click.echo("\nAI Categorization:")
        click.echo("-" * 40)
        click.echo(response.content)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@ai.command('threat-hunt')
@click.option('--hours', '-h', default=1, help='Hours of logs to analyze')
@click.option('--provider', '-p', default='gemini', help='LLM provider')
@click.pass_context
def ai_threat_hunt(ctx, hours: int, provider: str):
    """Hunt for threats in recent logs using AI."""
    from ..services.log_source_loader import LogSourceLoader
    from ..llm import LLMFactory
    from ..llm.base_client import LLMConfig
    import os
    
    click.echo("\n🔍 ProjectLibra Threat Hunt")
    click.echo("=" * 50)
    
    # Get logs
    loader = LogSourceLoader()
    logs = loader.fetch_logs(500)
    
    if not logs:
        click.echo("No logs available")
        return
    
    combined = "\n".join(logs.values())[:10000]
    
    config_path = ctx.obj.get('config_path')
    config = ProjectLibraConfig.load(config_path)
    
    api_key = None
    if provider == 'gemini':
        api_key = os.environ.get('GEMINI_API_KEY') or (config.llm.gemini.api_key if hasattr(config.llm, 'gemini') else None)
    elif provider == 'openai':
        api_key = os.environ.get('OPENAI_API_KEY')
    
    if not api_key and provider not in ['ollama']:
        click.echo(f"Error: Set {provider.upper()}_API_KEY")
        return
    
    prompt = f"""You are a security analyst. Hunt for threats in these logs.

Look for:
1. Brute force attacks (repeated failed logins)
2. Privilege escalation attempts
3. Suspicious process execution
4. Network anomalies
5. Data exfiltration signs
6. Malware indicators

Logs:
{combined}

Report format:
THREAT LEVEL: [None/Low/Medium/High/Critical]
FINDINGS: List each suspicious finding with evidence
INDICATORS OF COMPROMISE (IOCs): Any IPs, users, files to investigate
RECOMMENDED ACTIONS: Specific steps to take"""

    # Get default model for provider
    default_models = {
        'gemini': 'gemini-flash-latest',
        'openai': 'gpt-4',
        'ollama': 'llama2',
        'groq': 'llama-3.1-70b-versatile'
    }
    model = default_models.get(provider, 'gemini-flash-latest')
    
    try:
        llm = LLMFactory.create(provider=provider, model=model, api_key=api_key)
        
        click.echo(f"Analyzing with {provider}...")
        response = asyncio.run(llm.generate(prompt))
        
        click.echo("\n" + "=" * 50)
        click.echo("THREAT HUNT RESULTS")
        click.echo("=" * 50)
        click.echo(response.content)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


# ========== LOG SOURCE COMMANDS ==========

@cli.group()
def logs():
    """Log source management commands."""
    pass


@logs.command('sources')
def logs_sources():
    """List configured log sources."""
    from ..services.log_source_loader import LogSourceLoader
    
    loader = LogSourceLoader()
    sources = loader.get_source_info()
    
    click.echo("\nConfigured Log Sources:")
    click.echo("-" * 60)
    click.echo(f"Config: {loader.config_path}")
    click.echo("")
    
    for source in sources:
        status = "✓" if source['enabled'] and source['available'] else "○" if source['enabled'] else "✗"
        avail = "available" if source['available'] else "not found"
        click.echo(f"  {status} {source['name']:20} [{source['priority']:8}] ({avail})")
        if source['description']:
            click.echo(f"      {source['description']}")
    
    enabled = len([s for s in sources if s['enabled']])
    available = len([s for s in sources if s['available']])
    click.echo(f"\nTotal: {len(sources)} | Enabled: {enabled} | Available: {available}")


@logs.command('fetch')
@click.option('--limit', '-n', default=50, help='Lines per source')
def logs_fetch(limit: int):
    """Fetch and display logs from configured sources."""
    from ..services.log_source_loader import LogSourceLoader
    
    loader = LogSourceLoader()
    logs = loader.fetch_logs(limit)
    
    click.echo(f"\nFetched logs from {len(logs)} sources:\n")
    
    for source, content in logs.items():
        lines = content.strip().split('\n') if content else []
        click.echo(f"=== {source} ({len(lines)} lines) ===")
        for line in lines[:10]:
            click.echo(f"  {line[:100]}")
        if len(lines) > 10:
            click.echo(f"  ... and {len(lines) - 10} more lines")
        click.echo("")


@logs.command('reload')
def logs_reload():
    """Reload log source configuration."""
    from ..services.log_source_loader import reload_log_sources
    reload_log_sources()
    click.echo("✓ Log sources configuration reloaded")


def _show_pattern_results(analysis):
    """Helper to display pattern analysis results."""
    click.echo("Pattern Analysis Results:")
    click.echo("-" * 40)
    
    if analysis.patterns:
        click.echo("\nDetected Patterns:")
        for pattern in analysis.patterns[:10]:
            click.echo(f"  • {pattern}")
    else:
        click.echo("  No suspicious patterns detected")
    
    if analysis.recent_entries:
        click.echo(f"\nRecent entries: {len(analysis.recent_entries)}")


# ========== DASHBOARD COMMAND ==========

@cli.command()
@click.option('--port', '-p', default=8080, help='Port to run dashboard on')
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind to')
def dashboard(port: int, host: str):
    """Start the web dashboard."""
    import uvicorn
    from ..web.dashboard import create_dashboard_app
    
    click.echo(f"\n🚀 Starting ProjectLibra Dashboard on http://{host}:{port}")
    click.echo("   Press Ctrl+C to stop\n")
    
    app = create_dashboard_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


def main():
    """Main entry point for CLI."""
    cli(obj={})


if __name__ == '__main__':
    main()
