"""
ProjectLibra Interactive Console - Metasploit-style interface.

Features:
- Colored ASCII banner
- Interactive shell with command history
- Module-based command system
- Tab completion
- Status bar with live info
"""

import cmd
import os
import sys
import shutil
import readline
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
import tempfile
import uuid

# ANSI Color codes
class Colors:
    # Basic
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    
    # Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def colorize(text: str, *colors) -> str:
    """Apply colors to text."""
    color_codes = ''.join(colors)
    return f"{color_codes}{text}{Colors.RESET}"


# ASCII Art Banners
BANNER_MAIN = f"""
{Colors.BRIGHT_CYAN}
    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗
    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝
    ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║   
    ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║   
    ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║   
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   
{Colors.BRIGHT_RED}
                    ██╗     ██╗██████╗ ██████╗  █████╗ 
                    ██║     ██║██╔══██╗██╔══██╗██╔══██╗
                    ██║     ██║██████╔╝██████╔╝███████║
                    ██║     ██║██╔══██╗██╔══██╗██╔══██║
                    ███████╗██║██████╔╝██║  ██║██║  ██║
                    ╚══════╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.WHITE}       ═══════════════════════════════════════════════════════════
{Colors.BRIGHT_GREEN}         [ Agentic AI-Powered Security Log Analysis Platform ]
{Colors.WHITE}       ═══════════════════════════════════════════════════════════{Colors.RESET}

"""

BANNER_SMALL = f"""{Colors.BRIGHT_CYAN}╔═╗┬─┐┌─┐ ┬┌─┐┌─┐┌┬┐  {Colors.BRIGHT_RED}╦  ┬┌┐ ┬─┐┌─┐{Colors.RESET}
{Colors.BRIGHT_CYAN}╠═╝├┬┘│ │ │├┤ │   │   {Colors.BRIGHT_RED}║  │├┴┐├┬┘├─┤{Colors.RESET}
{Colors.BRIGHT_CYAN}╩  ┴└─└─┘└┘└─┘└─┘ ┴   {Colors.BRIGHT_RED}╩═╝┴└─┘┴└─┴ ┴{Colors.RESET}"""


class LibraConsole(cmd.Cmd):
    """Interactive console for ProjectLibra."""
    
    intro = ""
    doc_header = f"{Colors.BRIGHT_GREEN}Core Commands{Colors.RESET} (type help <command>):"
    misc_header = f"{Colors.BRIGHT_YELLOW}Module Commands{Colors.RESET}:"
    undoc_header = f"{Colors.DIM}Other Commands{Colors.RESET}:"
    ruler = '─'
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.config_path = config_path
        self.config = None
        self.db_manager = None
        self.current_module = None
        self.module_options = {}
        self.session_start = datetime.now()
        self.command_history = []
        
        # Module definitions
        self.modules = {
            'ai/analyze': {
                'name': 'AI Log Analyzer',
                'description': 'Analyze logs using AI/LLM for threat detection',
                'options': {
                    'PROVIDER': {'value': 'gemini', 'required': True, 'desc': 'LLM provider (gemini, openai, ollama)'},
                    'LIMIT': {'value': '100', 'required': False, 'desc': 'Number of log entries to analyze'},
                    'OUTPUT': {'value': '', 'required': False, 'desc': 'Output file for report'},
                }
            },
            'ai/threat_hunt': {
                'name': 'AI Threat Hunter',
                'description': 'Hunt for threats and IOCs using AI analysis',
                'options': {
                    'PROVIDER': {'value': 'gemini', 'required': True, 'desc': 'LLM provider'},
                    'DEPTH': {'value': 'standard', 'required': False, 'desc': 'Analysis depth (quick, standard, deep)'},
                }
            },
            'ai/categorize': {
                'name': 'Log Categorizer',
                'description': 'Categorize log messages by severity',
                'options': {
                    'PROVIDER': {'value': 'gemini', 'required': True, 'desc': 'LLM provider'},
                    'MESSAGE': {'value': '', 'required': True, 'desc': 'Log message to categorize'},
                }
            },
            'ml/train': {
                'name': 'ML Baseline Trainer',
                'description': 'Train ML baseline on normal system behavior',
                'options': {
                    'SOURCE': {'value': 'journalctl', 'required': False, 'desc': 'Log source to train on'},
                    'SAMPLES': {'value': '500', 'required': False, 'desc': 'Number of samples to train on'},
                }
            },
            'ml/detect': {
                'name': 'ML Anomaly Detector',
                'description': 'Detect anomalies in real-time using trained model',
                'options': {
                    'THRESHOLD': {'value': '0.7', 'required': False, 'desc': 'Anomaly score threshold (0.0-1.0)'},
                    'NOTIFY': {'value': 'true', 'required': False, 'desc': 'Send notifications on detection'},
                }
            },
            'ml/status': {
                'name': 'ML Model Status',
                'description': 'Show ML model training status and statistics',
                'options': {}
            },
            'db/integrity': {
                'name': 'Integrity Checker',
                'description': 'Check database integrity and detect tampering',
                'options': {
                    'NOTIFY': {'value': 'true', 'required': False, 'desc': 'Send notifications on tampering'},
                }
            },
            'db/forensic': {
                'name': 'Forensic Analyzer',
                'description': 'Forensic analysis of tampered records',
                'options': {
                    'RECORD_ID': {'value': '', 'required': True, 'desc': 'Record ID to analyze'},
                }
            },
            'db/monitor': {
                'name': 'Integrity Monitor',
                'description': 'Continuous integrity monitoring with alerts',
                'options': {
                    'INTERVAL': {'value': '60', 'required': False, 'desc': 'Check interval in seconds'},
                    'NOTIFY': {'value': 'true', 'required': False, 'desc': 'Send notifications on issues'},
                }
            },
            'demo/tamper': {
                'name': 'Tamper Detection Demo',
                'description': 'Demonstrate tamper-proof logging with notifications',
                'options': {}
            },
            'demo/anomaly': {
                'name': 'Anomaly Detection Demo',
                'description': 'Demonstrate ML-based anomaly detection',
                'options': {}
            },
            'demo/notify': {
                'name': 'Notification Demo',
                'description': 'Test system notifications and sound alerts',
                'options': {
                    'SEVERITY': {'value': 'high', 'required': False, 'desc': 'Alert severity (critical, high, medium, low)'},
                }
            },
            'logs/fetch': {
                'name': 'Log Fetcher',
                'description': 'Fetch logs from configured sources',
                'options': {
                    'LIMIT': {'value': '50', 'required': False, 'desc': 'Lines per source'},
                }
            },
            'logs/monitor': {
                'name': 'Live Log Monitor',
                'description': 'Real-time log monitoring with threat detection',
                'options': {
                    'SOURCE': {'value': 'journalctl', 'required': False, 'desc': 'Log source to monitor'},
                    'NOTIFY': {'value': 'true', 'required': False, 'desc': 'Send notifications on threats'},
                }
            },
        }
        
        self._update_prompt()
        self._init_config()
    
    def _update_prompt(self):
        """Update the command prompt."""
        if self.current_module:
            module_name = colorize(self.current_module, Colors.BRIGHT_RED)
            self.prompt = f"{Colors.BRIGHT_CYAN}libra{Colors.RESET} {module_name} > "
        else:
            self.prompt = f"{Colors.BRIGHT_CYAN}libra{Colors.RESET} > "
    
    def _init_config(self):
        """Initialize configuration."""
        try:
            from ..config import ProjectLibraConfig
            self.config = ProjectLibraConfig.load(self.config_path)
        except Exception:
            self.config = None
    
    def _init_db(self):
        """Initialize database manager."""
        if self.db_manager is None and self.config:
            try:
                from ..database.dual_db_manager import DualDatabaseManager
                self.db_manager = DualDatabaseManager(
                    primary_db_path=self.config.database.primary_path,
                    backup_db_path=self.config.database.backup_path,
                )
            except Exception as e:
                self._error(f"Failed to initialize database: {e}")
    
    def _print(self, text: str, color: str = Colors.RESET):
        """Print colored text."""
        print(f"{color}{text}{Colors.RESET}")
    
    def _success(self, text: str):
        """Print success message."""
        print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} {text}")
    
    def _info(self, text: str):
        """Print info message."""
        print(f"{Colors.BRIGHT_BLUE}[*]{Colors.RESET} {text}")
    
    def _warning(self, text: str):
        """Print warning message."""
        print(f"{Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {text}")
    
    def _error(self, text: str):
        """Print error message."""
        print(f"{Colors.BRIGHT_RED}[-]{Colors.RESET} {text}")
    
    def _header(self, text: str):
        """Print section header."""
        width = shutil.get_terminal_size().columns - 4
        print(f"\n{Colors.BRIGHT_WHITE}{'─' * width}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{text}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}{'─' * width}{Colors.RESET}")
    
    def preloop(self):
        """Show banner on start."""
        os.system('clear' if os.name != 'nt' else 'cls')
        print(BANNER_MAIN)
        self._show_status_bar()
        print()
    
    def _show_status_bar(self):
        """Show system status bar."""
        width = shutil.get_terminal_size().columns
        
        # Count modules
        module_count = len(self.modules)
        
        # Get log sources count
        try:
            from ..services.log_source_loader import LogSourceLoader
            loader = LogSourceLoader()
            sources = loader.get_source_status()
            available = len([s for s in sources if s['available']])
            sources_status = f"{available} sources"
        except Exception:
            sources_status = "N/A"
        
        # Check DB status
        try:
            self._init_db()
            if self.db_manager:
                primary_count = len(self.db_manager.primary_db.get_all_event_ids())
                db_status = f"{primary_count} records"
            else:
                db_status = "Not initialized"
        except Exception:
            db_status = "Offline"
        
        # Build status line
        status_parts = [
            f"{Colors.BRIGHT_GREEN}●{Colors.RESET} Modules: {Colors.BRIGHT_CYAN}{module_count}{Colors.RESET}",
            f"{Colors.BRIGHT_GREEN}●{Colors.RESET} Logs: {Colors.BRIGHT_CYAN}{sources_status}{Colors.RESET}",
            f"{Colors.BRIGHT_GREEN}●{Colors.RESET} DB: {Colors.BRIGHT_CYAN}{db_status}{Colors.RESET}",
        ]
        
        status_line = "  │  ".join(status_parts)
        
        # Center and print
        print(f"{Colors.DIM}{'═' * width}{Colors.RESET}")
        print(f"  {status_line}")
        print(f"{Colors.DIM}{'═' * width}{Colors.RESET}")
    
    def emptyline(self):
        """Do nothing on empty line."""
        pass
    
    def default(self, line: str):
        """Handle unknown commands."""
        self._error(f"Unknown command: {line}")
        self._info("Type 'help' for available commands")
    
    # ========== CORE COMMANDS ==========
    
    def do_help(self, arg):
        """Show help information."""
        if arg:
            # Show help for specific command
            try:
                func = getattr(self, 'help_' + arg, None)
                if func:
                    func()
                else:
                    doc = getattr(self, 'do_' + arg).__doc__
                    if doc:
                        self._info(doc)
                    else:
                        self._warning(f"No help available for '{arg}'")
            except AttributeError:
                self._error(f"Unknown command: {arg}")
        else:
            self._show_help()
    
    def _show_help(self):
        """Show main help screen."""
        self._header("ProjectLibra Console Commands")
        
        print(f"""
{Colors.BRIGHT_GREEN}Core Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}help{Colors.RESET}                 Show this help message
  {Colors.BRIGHT_CYAN}banner{Colors.RESET}               Display the banner
  {Colors.BRIGHT_CYAN}version{Colors.RESET}              Show version information
  {Colors.BRIGHT_CYAN}status{Colors.RESET}               Show system status
  {Colors.BRIGHT_CYAN}clear{Colors.RESET}                Clear the screen
  {Colors.BRIGHT_CYAN}exit{Colors.RESET}, {Colors.BRIGHT_CYAN}quit{Colors.RESET}           Exit the console

{Colors.BRIGHT_YELLOW}Module Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}use{Colors.RESET} <module>         Select a module to use
  {Colors.BRIGHT_CYAN}show modules{Colors.RESET}         List all available modules
  {Colors.BRIGHT_CYAN}show options{Colors.RESET}         Show module options (when module selected)
  {Colors.BRIGHT_CYAN}set{Colors.RESET} <option> <val>   Set a module option
  {Colors.BRIGHT_CYAN}run{Colors.RESET}                  Execute the current module
  {Colors.BRIGHT_CYAN}back{Colors.RESET}                 Deselect current module

{Colors.BRIGHT_MAGENTA}Database Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}db check{Colors.RESET}             Check database integrity
  {Colors.BRIGHT_CYAN}db stats{Colors.RESET}             Show database statistics
  {Colors.BRIGHT_CYAN}db forensic{Colors.RESET} <id>     Forensic analysis of record

{Colors.BRIGHT_RED}Analysis Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}analyze{Colors.RESET} <message>    Quick log message analysis
  {Colors.BRIGHT_CYAN}logs{Colors.RESET}                 List configured log sources
  {Colors.BRIGHT_CYAN}fetch{Colors.RESET}                Fetch logs from sources

{Colors.BRIGHT_BLUE}Demo Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}demo tamper{Colors.RESET}          Run tamper detection demo
  {Colors.BRIGHT_CYAN}demo anomaly{Colors.RESET}         Run anomaly detection demo
  {Colors.BRIGHT_CYAN}demo notify{Colors.RESET}          Test system notifications

{Colors.BRIGHT_MAGENTA}Notification Commands{Colors.RESET}
{Colors.DIM}{'─' * 60}{Colors.RESET}
  {Colors.BRIGHT_CYAN}notify{Colors.RESET} [severity]    Send test notification (critical/high/medium/low)
""")
    
    def do_banner(self, arg):
        """Display the banner."""
        print(BANNER_MAIN)
    
    def do_version(self, arg):
        """Show version information."""
        self._header("Version Information")
        print(f"""
  {Colors.BRIGHT_CYAN}ProjectLibra{Colors.RESET} v1.0.0
  {Colors.DIM}Agentic AI-Powered Security Log Analysis Platform{Colors.RESET}
  
  {Colors.BRIGHT_WHITE}Components:{Colors.RESET}
    • Dual Database Engine (Tamper-Proof)
    • ML Anomaly Detection (IsolationForest)
    • LLM Integration (Gemini, OpenAI, Ollama, Groq)
    • Pattern Detection Engine
    • Real-time Log Monitoring
""")
    
    def do_status(self, arg):
        """Show system status."""
        self._header("System Status")
        
        # Session info
        uptime = datetime.now() - self.session_start
        print(f"\n  {Colors.BRIGHT_WHITE}Session:{Colors.RESET}")
        print(f"    Started:  {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Uptime:   {uptime}")
        print(f"    Commands: {len(self.command_history)}")
        
        # Database status
        print(f"\n  {Colors.BRIGHT_WHITE}Database:{Colors.RESET}")
        try:
            self._init_db()
            if self.db_manager:
                primary_count = len(self.db_manager.primary_db.get_all_event_ids())
                backup_count = self.db_manager.backup_db.get_record_count()
                print(f"    Status:   {Colors.BRIGHT_GREEN}●{Colors.RESET} Online")
                print(f"    Primary:  {primary_count} records")
                print(f"    Backup:   {backup_count} records")
                
                # Quick integrity check
                report = self.db_manager.full_integrity_audit()
                if report.tampered_records == 0 and report.missing_records == 0:
                    print(f"    Integrity: {Colors.BRIGHT_GREEN}✓ Verified{Colors.RESET}")
                else:
                    print(f"    Integrity: {Colors.BRIGHT_RED}✗ Issues detected{Colors.RESET}")
            else:
                print(f"    Status:   {Colors.BRIGHT_YELLOW}●{Colors.RESET} Not initialized")
        except Exception as e:
            print(f"    Status:   {Colors.BRIGHT_RED}●{Colors.RESET} Error: {e}")
        
        # Log sources
        print(f"\n  {Colors.BRIGHT_WHITE}Log Sources:{Colors.RESET}")
        try:
            from ..services.log_source_loader import LogSourceLoader
            loader = LogSourceLoader()
            sources = loader.get_source_status()
            available = [s for s in sources if s['available']]
            print(f"    Configured: {len(sources)}")
            print(f"    Available:  {len(available)}")
        except Exception:
            print(f"    Status:   {Colors.BRIGHT_RED}●{Colors.RESET} Error loading sources")
        
        # LLM Status
        print(f"\n  {Colors.BRIGHT_WHITE}LLM Providers:{Colors.RESET}")
        providers = ['GEMINI_API_KEY', 'OPENAI_API_KEY', 'GROQ_API_KEY']
        for p in providers:
            name = p.replace('_API_KEY', '').title()
            if os.environ.get(p):
                print(f"    {name}:  {Colors.BRIGHT_GREEN}●{Colors.RESET} Configured")
            else:
                print(f"    {name}:  {Colors.DIM}○{Colors.RESET} Not set")
        
        print()
    
    def do_clear(self, arg):
        """Clear the screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
        print(BANNER_SMALL)
        print()
    
    def do_exit(self, arg):
        """Exit the console."""
        self._info("Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the console."""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)
    
    # ========== MODULE COMMANDS ==========
    
    def do_use(self, arg):
        """Select a module to use."""
        if not arg:
            self._error("Usage: use <module>")
            self._info("Type 'show modules' to list available modules")
            return
        
        if arg in self.modules:
            self.current_module = arg
            self.module_options = {k: dict(v) for k, v in self.modules[arg]['options'].items()}
            self._update_prompt()
            self._success(f"Using module: {self.modules[arg]['name']}")
            if self.module_options:
                self._info("Type 'show options' to see configurable options")
        else:
            self._error(f"Unknown module: {arg}")
            self._info("Type 'show modules' to list available modules")
    
    def complete_use(self, text, line, begidx, endidx):
        """Tab completion for use command."""
        return [m for m in self.modules.keys() if m.startswith(text)]
    
    def do_back(self, arg):
        """Deselect current module."""
        if self.current_module:
            self._info(f"Leaving module: {self.current_module}")
            self.current_module = None
            self.module_options = {}
            self._update_prompt()
        else:
            self._warning("No module selected")
    
    def do_show(self, arg):
        """Show various information."""
        args = arg.split()
        if not args:
            self._error("Usage: show <modules|options>")
            return
        
        subcommand = args[0].lower()
        
        if subcommand == 'modules':
            self._show_modules()
        elif subcommand == 'options':
            self._show_options()
        else:
            self._error(f"Unknown show command: {subcommand}")
    
    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for show command."""
        options = ['modules', 'options']
        return [o for o in options if o.startswith(text)]
    
    def _show_modules(self):
        """List all available modules."""
        self._header("Available Modules")
        
        categories = {}
        for name, module in self.modules.items():
            category = name.split('/')[0]
            if category not in categories:
                categories[category] = []
            categories[category].append((name, module))
        
        category_names = {
            'ai': f'{Colors.BRIGHT_RED}AI/LLM Modules{Colors.RESET}',
            'db': f'{Colors.BRIGHT_MAGENTA}Database Modules{Colors.RESET}',
            'demo': f'{Colors.BRIGHT_BLUE}Demo Modules{Colors.RESET}',
            'logs': f'{Colors.BRIGHT_GREEN}Log Modules{Colors.RESET}',
        }
        
        print()
        for cat, modules in sorted(categories.items()):
            cat_name = category_names.get(cat, cat.upper())
            print(f"  {cat_name}")
            print(f"  {Colors.DIM}{'─' * 58}{Colors.RESET}")
            for name, module in modules:
                print(f"    {Colors.BRIGHT_CYAN}{name:<20}{Colors.RESET} {module['description']}")
            print()
    
    def _show_options(self):
        """Show options for current module."""
        if not self.current_module:
            self._error("No module selected")
            self._info("Use 'use <module>' to select a module first")
            return
        
        module = self.modules[self.current_module]
        self._header(f"Module: {module['name']}")
        
        print(f"\n  {module['description']}\n")
        
        if not self.module_options:
            self._info("This module has no configurable options")
            return
        
        print(f"  {Colors.BRIGHT_WHITE}{'Name':<15} {'Current Setting':<20} {'Required':<10} Description{Colors.RESET}")
        print(f"  {Colors.DIM}{'─' * 75}{Colors.RESET}")
        
        for name, opt in self.module_options.items():
            value = opt['value'] or ''
            required = 'yes' if opt['required'] else 'no'
            if value:
                value_display = f"{Colors.BRIGHT_GREEN}{value:<20}{Colors.RESET}"
            else:
                value_display = f"{Colors.DIM}{'(not set)':<20}{Colors.RESET}"
            print(f"  {Colors.BRIGHT_CYAN}{name:<15}{Colors.RESET} {value_display} {required:<10} {opt['desc']}")
        
        print()
    
    def do_set(self, arg):
        """Set a module option."""
        if not self.current_module:
            self._error("No module selected")
            return
        
        args = arg.split(None, 1)
        if len(args) < 2:
            self._error("Usage: set <option> <value>")
            return
        
        option = args[0].upper()
        value = args[1]
        
        if option in self.module_options:
            self.module_options[option]['value'] = value
            self._success(f"{option} => {value}")
        else:
            self._error(f"Unknown option: {option}")
            self._info("Type 'show options' to see available options")
    
    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for set command."""
        if self.module_options:
            return [o for o in self.module_options.keys() if o.lower().startswith(text.lower())]
        return []
    
    def do_run(self, arg):
        """Execute the current module."""
        if not self.current_module:
            self._error("No module selected")
            self._info("Use 'use <module>' to select a module first")
            return
        
        # Check required options
        for name, opt in self.module_options.items():
            if opt['required'] and not opt['value']:
                self._error(f"Required option not set: {name}")
                self._info(f"Use 'set {name} <value>' to set it")
                return
        
        self._info(f"Running module: {self.current_module}")
        print()
        
        # Execute module
        try:
            module_type = self.current_module.split('/')[0]
            module_name = self.current_module.split('/')[1]
            
            if module_type == 'ai':
                self._run_ai_module(module_name)
            elif module_type == 'db':
                self._run_db_module(module_name)
            elif module_type == 'demo':
                self._run_demo_module(module_name)
            elif module_type == 'logs':
                self._run_logs_module(module_name)
            elif module_type == 'ml':
                self._run_ml_module(module_name)
            else:
                self._error(f"Unknown module type: {module_type}")
        except Exception as e:
            self._error(f"Module execution failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _run_ai_module(self, name: str):
        """Run AI modules."""
        from ..services.log_source_loader import LogSourceLoader
        from ..services.log_analyzer import LogAnalyzer
        
        provider = self.module_options.get('PROVIDER', {}).get('value', 'gemini')
        
        if name == 'analyze':
            limit = int(self.module_options.get('LIMIT', {}).get('value', '100'))
            
            self._info("Fetching logs from configured sources...")
            loader = LogSourceLoader()
            logs_by_source = loader.fetch_logs(limit)
            
            if not logs_by_source:
                self._error("No logs fetched from any source")
                return
            
            self._success(f"Fetched logs from {len(logs_by_source)} sources")
            
            self._info("Running pattern analysis...")
            analyzer = LogAnalyzer()
            combined_logs = "\n".join(logs_by_source.values())
            analysis = analyzer.analyze_text(combined_logs)
            
            print(f"  Entries analyzed: {len(analysis.recent_entries)}")
            print(f"  Patterns matched: {len(analysis.matched_patterns)}")
            
            self._info(f"Sending to {provider.upper()} for AI analysis...")
            self._run_llm_analysis(combined_logs, provider)
            
        elif name == 'threat_hunt':
            self._info("Fetching logs for threat hunting...")
            loader = LogSourceLoader()
            logs_by_source = loader.fetch_logs(200)
            
            if not logs_by_source:
                self._error("No logs available")
                return
            
            combined = "\n".join(logs_by_source.values())
            self._info(f"Analyzing with {provider.upper()}...")
            self._run_threat_hunt(combined, provider)
            
        elif name == 'categorize':
            message = self.module_options.get('MESSAGE', {}).get('value', '')
            if not message:
                self._error("MESSAGE option is required")
                return
            
            self._run_categorize(message, provider)
    
    def _run_llm_analysis(self, logs: str, provider: str):
        """Run LLM-based log analysis."""
        from ..llm.llm_factory import LLMFactory
        
        api_key = self._get_api_key(provider)
        if not api_key and provider not in ['ollama']:
            self._error(f"No API key found for {provider}")
            return
        
        try:
            model = 'gemini-2.0-flash' if provider == 'gemini' else None
            client = LLMFactory.create(provider=provider, api_key=api_key, model=model)
            
            prompt = f"""Analyze these security logs and provide:
1. Overall security assessment (Critical/High/Medium/Low)
2. Key findings and patterns
3. Potential threats or anomalies
4. Recommended actions

Logs:
{logs[:8000]}"""
            
            self._info("Waiting for AI response...")
            response = client.query(prompt)
            
            self._header("AI Analysis Results")
            print(f"\n{response}\n")
            self._success("Analysis complete")
            
        except Exception as e:
            self._error(f"LLM analysis failed: {e}")
    
    def _run_threat_hunt(self, logs: str, provider: str):
        """Run threat hunting analysis."""
        from ..llm.llm_factory import LLMFactory
        
        api_key = self._get_api_key(provider)
        if not api_key and provider not in ['ollama']:
            self._error(f"No API key found for {provider}")
            return
        
        try:
            model = 'gemini-2.0-flash' if provider == 'gemini' else None
            client = LLMFactory.create(provider=provider, api_key=api_key, model=model)
            
            prompt = f"""You are a threat hunter analyzing security logs. Search for:

1. INDICATORS OF COMPROMISE (IOCs)
   - Suspicious IP addresses
   - Malicious file hashes
   - Known bad domains
   - Unusual user agents

2. ATTACK PATTERNS
   - Brute force attempts
   - Privilege escalation
   - Lateral movement
   - Data exfiltration signs

3. ANOMALIES
   - Unusual login times
   - Geographic impossibilities
   - Abnormal process behavior
   - Unexpected network connections

Logs to analyze:
{logs[:10000]}

Provide a structured threat hunting report."""
            
            response = client.query(prompt)
            
            self._header("Threat Hunt Results")
            print(f"\n{response}\n")
            self._success("Threat hunt complete")
            
        except Exception as e:
            self._error(f"Threat hunt failed: {e}")
    
    def _run_categorize(self, message: str, provider: str):
        """Categorize a log message."""
        from ..llm.llm_factory import LLMFactory
        
        api_key = self._get_api_key(provider)
        if not api_key and provider not in ['ollama']:
            self._error(f"No API key found for {provider}")
            return
        
        try:
            model = 'gemini-2.0-flash' if provider == 'gemini' else None
            client = LLMFactory.create(provider=provider, api_key=api_key, model=model)
            
            prompt = f"""Categorize this log message:
"{message}"

Provide:
1. Severity (Critical/High/Medium/Low/Info)
2. Category (Authentication/Network/System/Application/Security)
3. Brief explanation
4. Any recommended actions"""
            
            response = client.query(prompt)
            
            print(f"\n  {Colors.BRIGHT_WHITE}Message:{Colors.RESET} {message}")
            print(f"\n{response}\n")
            
        except Exception as e:
            self._error(f"Categorization failed: {e}")
    
    def _get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for provider."""
        key_map = {
            'gemini': 'GEMINI_API_KEY',
            'openai': 'OPENAI_API_KEY',
            'groq': 'GROQ_API_KEY',
        }
        env_var = key_map.get(provider)
        if env_var:
            return os.environ.get(env_var)
        return None
    
    def _run_db_module(self, name: str):
        """Run database modules."""
        self._init_db()
        
        if not self.db_manager:
            self._error("Database not initialized")
            return
        
        if name == 'integrity':
            self._info("Running full integrity audit...")
            report = self.db_manager.full_integrity_audit()
            
            print(f"\n  {Colors.BRIGHT_WHITE}Integrity Check Results:{Colors.RESET}")
            print(f"  {'─' * 40}")
            print(f"  Total records:    {report.total_records_checked}")
            print(f"  Valid records:    {Colors.BRIGHT_GREEN}{report.valid_records}{Colors.RESET}")
            print(f"  Tampered records: {Colors.BRIGHT_RED if report.tampered_records else Colors.DIM}{report.tampered_records}{Colors.RESET}")
            print(f"  Missing records:  {Colors.BRIGHT_YELLOW if report.missing_records else Colors.DIM}{report.missing_records}{Colors.RESET}")
            print(f"  Chain valid:      {Colors.BRIGHT_GREEN if report.chain_valid else Colors.BRIGHT_RED}{report.chain_valid}{Colors.RESET}")
            
            if report.issues:
                print(f"\n  {Colors.BRIGHT_YELLOW}Issues Found:{Colors.RESET}")
                for issue in report.issues[:10]:
                    print(f"    • [{issue['severity']}] {issue['message']}")
            
            if report.tampered_records == 0 and report.missing_records == 0:
                self._success("Database integrity verified")
            else:
                self._warning("Integrity issues detected!")
                
        elif name == 'forensic':
            record_id = self.module_options.get('RECORD_ID', {}).get('value', '')
            if not record_id:
                self._error("RECORD_ID is required")
                return
            
            try:
                record_id = int(record_id)
            except ValueError:
                self._error("RECORD_ID must be an integer")
                return
            
            forensic = self.db_manager.get_forensic_comparison(record_id)
            
            if not forensic:
                self._warning(f"Record {record_id} not found or not tampered")
                return
            
            self._header(f"Forensic Analysis: Record {record_id}")
            
            print(f"\n  {Colors.BRIGHT_GREEN}Original (Immutable Backup):{Colors.RESET}")
            for key, value in forensic.get('original', {}).items():
                print(f"    {key}: {value}")
            
            print(f"\n  {Colors.BRIGHT_RED}Current (Primary DB):{Colors.RESET}")
            for key, value in forensic.get('current', {}).items():
                print(f"    {key}: {value}")
            
            print(f"\n  {Colors.BRIGHT_YELLOW}Changes:{Colors.RESET}")
            for change in forensic.get('changes', []):
                print(f"    • {change}")
    
    def _run_demo_module(self, name: str):
        """Run demo modules."""
        if name == 'tamper':
            self._run_tamper_demo()
        elif name == 'anomaly':
            self._run_anomaly_demo()
        elif name == 'notify':
            self._run_notify_demo()
    
    def _run_notify_demo(self):
        """Run notification demo to test system alerts."""
        from ..services.notification_service import (
            get_notification_service, AlertType, AlertSeverity
        )
        
        notifier = get_notification_service()
        
        self._header("Notification System Demo")
        
        severity_str = self.module_options.get('SEVERITY', {}).get('value', 'high')
        severity_map = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW,
            'info': AlertSeverity.INFO,
        }
        severity = severity_map.get(severity_str.lower(), AlertSeverity.HIGH)
        
        self._info(f"Testing {severity_str.upper()} severity notification...")
        print()
        
        import time
        
        # Test notification
        if severity == AlertSeverity.CRITICAL:
            notifier.alert_tampering(
                "DEMO: Critical security breach detected!",
                details={'demo': True, 'test_type': 'notification_demo'}
            )
        elif severity == AlertSeverity.HIGH:
            notifier.alert_threat(
                "Brute Force Attack",
                "DEMO: Multiple failed login attempts detected from suspicious IP",
                severity=AlertSeverity.HIGH,
                details={'demo': True}
            )
        elif severity == AlertSeverity.MEDIUM:
            notifier.alert_anomaly(
                "DEMO: Unusual system activity detected",
                0.75,
                details={'demo': True}
            )
        else:
            notifier.alert(
                AlertType.SYSTEM_ALERT,
                severity,
                "ProjectLibra Alert Test",
                f"DEMO: This is a {severity_str} severity test notification",
                details={'demo': True}
            )
        
        time.sleep(1)  # Let sound play
        
        print()
        self._success("Notification sent!")
        self._info("You should have heard a sound and seen a system notification")
        self._info("If not, check if notify-send is installed: sudo apt install libnotify-bin")
    
    def _run_tamper_demo(self):
        """Run tamper detection demo."""
        from ..database.dual_db_manager import DualDatabaseManager
        from ..services.notification_service import get_notification_service, AlertType, AlertSeverity
        import shutil
        
        notifier = get_notification_service()
        
        self._header("Tamper Detection Demo")
        
        temp_dir = tempfile.mkdtemp()
        primary_path = os.path.join(temp_dir, 'demo_primary.db')
        backup_path = os.path.join(temp_dir, 'demo_backup.db')
        
        db_manager = DualDatabaseManager(
            primary_db_path=primary_path,
            backup_db_path=backup_path,
        )
        
        self._info("Step 1: Adding sample security events...")
        
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
            print(f"    {Colors.BRIGHT_GREEN}+{Colors.RESET} {event['raw_data']['message']}")
        
        self._info("Step 2: Verifying initial integrity...")
        report = db_manager.full_integrity_audit()
        print(f"    Records: {report.total_records_checked}, Tampered: {report.tampered_records}")
        
        print()
        self._warning("Step 3: Simulating attacker modifying record...")
        db_manager.primary_db.update_event(event_ids[1], {
            'raw_data': {'message': 'MODIFIED BY ATTACKER', 'hacked': True}
        })
        print(f"    {Colors.BRIGHT_RED}✗{Colors.RESET} Attacker modified record 2")
        
        self._info("Step 4: Checking integrity after tampering...")
        report = db_manager.full_integrity_audit()
        print(f"    Records: {report.total_records_checked}, Tampered: {Colors.BRIGHT_RED}{report.tampered_records}{Colors.RESET}")
        
        if report.tampered_records > 0:
            print()
            print(f"    {Colors.BG_RED}{Colors.BRIGHT_WHITE} 🚨 TAMPERING DETECTED! {Colors.RESET}")
            
            # Send system notification with sound!
            notifier.alert_tampering(
                "Database record modified outside of application!",
                details={'tampered_count': report.tampered_records}
            )
            
            tampered = db_manager.get_tampered_records()
            for record in tampered:
                if record['backup_data'] and record['primary_data']:
                    original = record['backup_data'].get('raw_data', {}).get('message', 'N/A')
                    current = record['primary_data'].get('raw_data', {}).get('message', 'N/A')
                    print(f"\n    {Colors.BRIGHT_GREEN}Original:{Colors.RESET} {original}")
                    print(f"    {Colors.BRIGHT_RED}Modified:{Colors.RESET} {current}")
        
        print()
        self._warning("Step 5: Simulating attacker deleting record...")
        db_manager.primary_db.delete_event(event_ids[0])
        print(f"    {Colors.BRIGHT_RED}✗{Colors.RESET} Attacker deleted record 1")
        
        self._info("Step 6: Final integrity check...")
        report = db_manager.full_integrity_audit()
        print(f"    Tampered: {Colors.BRIGHT_RED}{report.tampered_records}{Colors.RESET}, Missing: {Colors.BRIGHT_RED}{report.missing_records}{Colors.RESET}")
        
        if report.missing_records > 0:
            print(f"\n    {Colors.BG_RED}{Colors.BRIGHT_WHITE} 🚨 DELETION DETECTED! {Colors.RESET}")
            
            # Send system notification with sound!
            notifier.alert_tampering(
                "Database records deleted by attacker!",
                details={'missing_count': report.missing_records}
            )
        
        print()
        self._success("Demo complete - Tamper detection working!")
        
        shutil.rmtree(temp_dir)
    
    def _run_anomaly_demo(self):
        """Run anomaly detection demo."""
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.anomaly_detector import AnomalyDetector
        from ..ml.baseline_learner import BaselineLearner
        from ..services.notification_service import get_notification_service
        
        notifier = get_notification_service()
        
        self._header("Anomaly Detection Demo")
        
        extractor = FeatureExtractor()
        learner = BaselineLearner()
        detector = AnomalyDetector(baseline_learner=learner)
        
        self._info("Step 1: Training baseline on normal logs...")
        
        normal_logs = [
            "User john logged in successfully",
            "Session started for user mary",
            "Scheduled backup completed",
            "System health check passed",
            "Database connection established",
        ] * 50
        
        for msg in normal_logs:
            features = extractor.extract_log_features(msg, source='training')
            learner.update_baseline(features)
        
        print(f"    Trained on {len(normal_logs)} samples")
        learner.finalize_baseline()
        self._success("Baseline established")
        
        self._info("Step 2: Testing normal logs...")
        
        test_normal = [
            "User alice logged in from office",
            "Regular backup job completed",
            "Health check status: OK",
        ]
        
        for msg in test_normal:
            features = extractor.extract_log_features(msg, source='test')
            result = detector.detect(features)
            status = f"{Colors.BRIGHT_GREEN}NORMAL{Colors.RESET}" if not result.is_anomaly else f"{Colors.BRIGHT_RED}ANOMALY{Colors.RESET}"
            print(f"    [{status}] {msg[:50]}")
        
        print()
        self._info("Step 3: Testing suspicious logs...")
        
        test_anomalies = [
            "CRITICAL: Multiple failed SSH attempts from 192.168.1.100",
            "ROOT PASSWORD CHANGED by unknown process",
            "WARNING: /etc/passwd modified at 3:00 AM",
            "Unusual outbound connection to 45.33.32.156:4444",
        ]
        
        anomaly_detected = False
        for msg in test_anomalies:
            features = extractor.extract_log_features(msg, source='test')
            result = detector.detect(features)
            is_anomaly = result.is_anomaly
            status = f"{Colors.BRIGHT_RED}ANOMALY{Colors.RESET}" if is_anomaly else f"{Colors.BRIGHT_GREEN}NORMAL{Colors.RESET}"
            score = f"(score: {result.anomaly_score:.2f})"
            print(f"    [{status}] {score} {msg[:45]}...")
            
            if is_anomaly and not anomaly_detected:
                anomaly_detected = True
                # Send notification for first anomaly
                notifier.alert_anomaly(msg[:50], result.anomaly_score, 
                                      details={'full_message': msg})
        
        print()
        self._success("Anomaly detection demo complete!")
    
    def _run_logs_module(self, name: str):
        """Run log modules."""
        from ..services.log_source_loader import LogSourceLoader
        
        if name == 'fetch':
            limit = int(self.module_options.get('LIMIT', {}).get('value', '50'))
            
            loader = LogSourceLoader()
            logs = loader.fetch_logs(limit)
            
            self._info(f"Fetched logs from {len(logs)} sources")
            
            for source, content in logs.items():
                lines = content.strip().split('\n') if content else []
                print(f"\n  {Colors.BRIGHT_CYAN}═══ {source} ({len(lines)} lines) ═══{Colors.RESET}")
                for line in lines[:10]:
                    print(f"    {line[:100]}")
                if len(lines) > 10:
                    print(f"    {Colors.DIM}... and {len(lines) - 10} more lines{Colors.RESET}")
        
        elif name == 'monitor':
            self._run_live_monitor()
    
    def _run_live_monitor(self):
        """Run live log monitoring."""
        from ..services.log_source_loader import LogSourceLoader
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.pattern_detector import PatternDetector
        from ..services.notification_service import get_notification_service
        
        source = self.module_options.get('SOURCE', {}).get('value', 'journalctl')
        notify = self.module_options.get('NOTIFY', {}).get('value', 'true').lower() == 'true'
        
        notifier = get_notification_service() if notify else None
        extractor = FeatureExtractor()
        detector = PatternDetector()
        
        self._header(f"Live Log Monitor - {source}")
        self._info("Press Ctrl+C to stop monitoring")
        print()
        
        import subprocess
        import time
        
        try:
            # Use journalctl -f for live monitoring
            if source == 'journalctl':
                cmd = ['journalctl', '-f', '-n', '0', '--no-pager']
            else:
                self._error(f"Live monitoring not supported for source: {source}")
                return
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True)
            
            threat_count = 0
            line_count = 0
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                line_count += 1
                
                # Analyze for threats
                patterns = detector.detect_patterns(log_message=line)
                features = extractor.extract_log_features(line, source=source)
                
                severity_score = features.features.get('severity_score', 0)
                
                # Determine display color based on severity
                if patterns or severity_score > 0.7:
                    color = Colors.BRIGHT_RED
                    prefix = "🚨"
                    threat_count += 1
                    
                    if notify and notifier:
                        pattern_names = [p.pattern_name for p in patterns] if patterns else ['High severity']
                        notifier.alert_threat(
                            pattern_names[0] if patterns else "Suspicious Activity",
                            line[:100],
                            details={'patterns': pattern_names, 'severity': severity_score}
                        )
                elif severity_score > 0.5:
                    color = Colors.BRIGHT_YELLOW
                    prefix = "⚠️"
                else:
                    color = Colors.DIM
                    prefix = "  "
                
                # Print with timestamp
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {prefix} {color}{line[:100]}{Colors.RESET}")
                
        except KeyboardInterrupt:
            process.terminate()
            print()
            self._info(f"Monitoring stopped. Processed {line_count} lines, {threat_count} threats detected.")
    
    def _run_ml_module(self, name: str):
        """Run ML modules."""
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.anomaly_detector import AnomalyDetector
        from ..ml.baseline_learner import BaselineLearner
        from ..services.log_source_loader import LogSourceLoader
        
        if name == 'train':
            self._run_ml_train()
        elif name == 'detect':
            self._run_ml_detect()
        elif name == 'status':
            self._run_ml_status()
    
    def _run_ml_train(self):
        """Train ML baseline on normal system behavior."""
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.baseline_learner import BaselineLearner
        from ..services.log_source_loader import LogSourceLoader
        
        source = self.module_options.get('SOURCE', {}).get('value', 'journalctl')
        samples = int(self.module_options.get('SAMPLES', {}).get('value', '500'))
        
        self._header("ML Baseline Training")
        
        self._info(f"Fetching {samples} log entries from {source}...")
        
        loader = LogSourceLoader()
        logs = loader.fetch_logs(samples)
        
        if source not in logs:
            self._error(f"Source '{source}' not available")
            self._info(f"Available sources: {', '.join(logs.keys())}")
            return
        
        log_content = logs[source]
        lines = log_content.strip().split('\n') if log_content else []
        
        if not lines:
            self._error("No log data available for training")
            return
        
        self._info(f"Training on {len(lines)} log entries...")
        
        extractor = FeatureExtractor()
        learner = BaselineLearner()
        
        for i, line in enumerate(lines):
            features = extractor.extract_log_features(line, source=source)
            learner.update_baseline(features)
            
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"    Processed {i + 1}/{len(lines)} samples...")
        
        learner.finalize_baseline()
        
        # Save baseline (in memory for now, could persist to file)
        self._ml_baseline = learner
        self._ml_extractor = extractor
        
        print()
        self._success(f"Baseline trained on {len(lines)} samples!")
        
        # Show baseline statistics
        print(f"\n  {Colors.BRIGHT_WHITE}Baseline Statistics:{Colors.RESET}")
        print(f"    Samples processed: {len(lines)}")
        print(f"    Source: {source}")
        print(f"    Status: Ready for anomaly detection")
        
        self._info("Use 'use ml/detect' to start anomaly detection")
    
    def _run_ml_detect(self):
        """Run ML anomaly detection on current logs."""
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.anomaly_detector import AnomalyDetector
        from ..ml.baseline_learner import BaselineLearner
        from ..services.log_source_loader import LogSourceLoader
        from ..services.notification_service import get_notification_service
        
        threshold = float(self.module_options.get('THRESHOLD', {}).get('value', '0.7'))
        notify = self.module_options.get('NOTIFY', {}).get('value', 'true').lower() == 'true'
        
        self._header("ML Anomaly Detection")
        
        # Check if we have a trained baseline
        if hasattr(self, '_ml_baseline') and self._ml_baseline:
            learner = self._ml_baseline
            extractor = self._ml_extractor
            self._info("Using previously trained baseline")
        else:
            self._warning("No trained baseline found. Using default model.")
            extractor = FeatureExtractor()
            learner = BaselineLearner()
            # Quick train on some samples
            loader = LogSourceLoader()
            logs = loader.fetch_logs(100)
            for content in logs.values():
                for line in content.strip().split('\n')[:50]:
                    features = extractor.extract_log_features(line, source='auto')
                    learner.update_baseline(features)
            learner.finalize_baseline()
        
        detector = AnomalyDetector(baseline_learner=learner)
        notifier = get_notification_service() if notify else None
        
        self._info("Fetching recent logs for analysis...")
        
        loader = LogSourceLoader()
        logs = loader.fetch_logs(100)
        
        anomalies_found = []
        total_analyzed = 0
        
        for source, content in logs.items():
            lines = content.strip().split('\n') if content else []
            
            for line in lines:
                total_analyzed += 1
                features = extractor.extract_log_features(line, source=source)
                result = detector.detect(features)
                
                if result.is_anomaly and result.anomaly_score >= threshold:
                    anomalies_found.append({
                        'message': line,
                        'source': source,
                        'score': result.anomaly_score,
                    })
                    
                    # Real-time notification
                    if notify and notifier:
                        notifier.alert_anomaly(
                            line[:80],
                            result.anomaly_score,
                            details={'source': source}
                        )
        
        print()
        print(f"  {Colors.BRIGHT_WHITE}Detection Results:{Colors.RESET}")
        print(f"  {'─' * 60}")
        print(f"    Total logs analyzed: {total_analyzed}")
        print(f"    Anomalies detected:  {Colors.BRIGHT_RED if anomalies_found else Colors.BRIGHT_GREEN}{len(anomalies_found)}{Colors.RESET}")
        print(f"    Threshold:           {threshold}")
        
        if anomalies_found:
            print(f"\n  {Colors.BRIGHT_YELLOW}Anomalies Found:{Colors.RESET}")
            for i, anomaly in enumerate(anomalies_found[:10], 1):
                score_color = Colors.BRIGHT_RED if anomaly['score'] > 0.8 else Colors.BRIGHT_YELLOW
                print(f"    {i}. [{score_color}{anomaly['score']:.2f}{Colors.RESET}] [{anomaly['source']}]")
                print(f"       {anomaly['message'][:70]}...")
            
            if len(anomalies_found) > 10:
                print(f"    ... and {len(anomalies_found) - 10} more")
        else:
            print(f"\n  {Colors.BRIGHT_GREEN}✓ No anomalies detected above threshold{Colors.RESET}")
    
    def _run_ml_status(self):
        """Show ML model status."""
        self._header("ML Model Status")
        
        print(f"\n  {Colors.BRIGHT_WHITE}Baseline Learner:{Colors.RESET}")
        if hasattr(self, '_ml_baseline') and self._ml_baseline:
            print(f"    Status: {Colors.BRIGHT_GREEN}Trained{Colors.RESET}")
            print(f"    Ready for detection: Yes")
        else:
            print(f"    Status: {Colors.BRIGHT_YELLOW}Not trained{Colors.RESET}")
            print(f"    Run 'use ml/train' to train baseline")
        
        print(f"\n  {Colors.BRIGHT_WHITE}Available ML Components:{Colors.RESET}")
        print(f"    • IsolationForest - Unsupervised anomaly detection")
        print(f"    • BaselineLearner - Behavioral baseline modeling")
        print(f"    • PatternDetector - Security pattern matching")
        print(f"    • FeatureExtractor - Log feature extraction")
        
        print(f"\n  {Colors.BRIGHT_WHITE}Detection Capabilities:{Colors.RESET}")
        print(f"    • Brute force attacks")
        print(f"    • Privilege escalation")
        print(f"    • Unusual login patterns")
        print(f"    • Suspicious process activity")
        print(f"    • Network anomalies")
        print(f"    • File system modifications")
    
    # ========== QUICK COMMANDS ==========
    
    def do_db(self, arg):
        """Quick database commands: db check | db stats | db forensic <id>"""
        args = arg.split()
        if not args:
            self._error("Usage: db <check|stats|forensic> [args]")
            return
        
        subcmd = args[0]
        
        if subcmd == 'check':
            self.current_module = 'db/integrity'
            self.module_options = {}
            self._run_db_module('integrity')
            self.current_module = None
        elif subcmd == 'stats':
            self._init_db()
            if self.db_manager:
                primary_count = len(self.db_manager.primary_db.get_all_event_ids())
                backup_count = self.db_manager.backup_db.get_record_count()
                
                print(f"\n  {Colors.BRIGHT_WHITE}Database Statistics:{Colors.RESET}")
                print(f"  Primary records: {primary_count}")
                print(f"  Backup records:  {backup_count}")
                
                if self.config:
                    primary_size = Path(self.config.database.primary_path).stat().st_size / 1024
                    backup_size = Path(self.config.database.backup_path).stat().st_size / 1024
                    print(f"  Primary size:    {primary_size:.1f} KB")
                    print(f"  Backup size:     {backup_size:.1f} KB")
            else:
                self._error("Database not initialized")
        elif subcmd == 'forensic':
            if len(args) < 2:
                self._error("Usage: db forensic <record_id>")
                return
            self.current_module = 'db/forensic'
            self.module_options = {'RECORD_ID': {'value': args[1], 'required': True, 'desc': ''}}
            self._run_db_module('forensic')
            self.current_module = None
            self.module_options = {}
    
    def complete_db(self, text, line, begidx, endidx):
        """Tab completion for db command."""
        options = ['check', 'stats', 'forensic']
        return [o for o in options if o.startswith(text)]
    
    def do_demo(self, arg):
        """Quick demo commands: demo tamper | demo anomaly | demo notify"""
        if arg == 'tamper':
            self._run_tamper_demo()
        elif arg == 'anomaly':
            self._run_anomaly_demo()
        elif arg == 'notify':
            self.module_options = {'SEVERITY': {'value': 'high', 'required': False, 'desc': ''}}
            self._run_notify_demo()
            self.module_options = {}
        else:
            self._error("Usage: demo <tamper|anomaly|notify>")
    
    def complete_demo(self, text, line, begidx, endidx):
        """Tab completion for demo command."""
        options = ['tamper', 'anomaly', 'notify']
        return [o for o in options if o.startswith(text)]
    
    def do_notify(self, arg):
        """Send a test notification: notify [critical|high|medium|low]"""
        from ..services.notification_service import (
            get_notification_service, AlertType, AlertSeverity
        )
        
        severity_str = arg.lower() if arg else 'high'
        severity_map = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW,
            'info': AlertSeverity.INFO,
        }
        
        if severity_str not in severity_map:
            self._error(f"Unknown severity: {severity_str}")
            self._info("Valid options: critical, high, medium, low, info")
            return
        
        severity = severity_map[severity_str]
        notifier = get_notification_service()
        
        self._info(f"Sending {severity_str.upper()} test notification...")
        
        notifier.alert(
            AlertType.SYSTEM_ALERT,
            severity,
            f"ProjectLibra Test - {severity_str.upper()}",
            f"This is a test {severity_str} notification from ProjectLibra",
            details={'test': True}
        )
        
        import time
        time.sleep(0.5)
        
        self._success("Notification sent! Check your system notifications.")
    
    def complete_notify(self, text, line, begidx, endidx):
        """Tab completion for notify command."""
        options = ['critical', 'high', 'medium', 'low', 'info']
        return [o for o in options if o.startswith(text)]
    
    def do_logs(self, arg):
        """Show configured log sources."""
        from ..services.log_source_loader import LogSourceLoader
        
        loader = LogSourceLoader()
        sources = loader.get_source_status()
        
        print(f"\n  {Colors.BRIGHT_WHITE}Configured Log Sources:{Colors.RESET}")
        print(f"  {'─' * 60}")
        
        for source in sources:
            if source['available']:
                status = f"{Colors.BRIGHT_GREEN}●{Colors.RESET}"
            else:
                status = f"{Colors.BRIGHT_RED}○{Colors.RESET}"
            
            enabled = f"{Colors.BRIGHT_CYAN}enabled{Colors.RESET}" if source['enabled'] else f"{Colors.DIM}disabled{Colors.RESET}"
            print(f"  {status} {source['name']:<20} [{enabled}]  {source['type']}")
        
        available = len([s for s in sources if s['available']])
        print(f"\n  Total: {len(sources)} | Available: {available}")
    
    def do_fetch(self, arg):
        """Fetch logs from configured sources."""
        self.current_module = 'logs/fetch'
        limit = arg if arg else '50'
        self.module_options = {'LIMIT': {'value': limit, 'required': False, 'desc': ''}}
        self._run_logs_module('fetch')
        self.current_module = None
        self.module_options = {}
    
    def do_analyze(self, arg):
        """Quick analyze a log message."""
        if not arg:
            self._error("Usage: analyze <log message>")
            return
        
        from ..ml.feature_extractor import FeatureExtractor
        from ..ml.pattern_detector import PatternDetector
        
        extractor = FeatureExtractor()
        detector = PatternDetector()
        
        features = extractor.extract_log_features(arg, source='cli')
        patterns = detector.detect_patterns(log_message=arg)
        
        print(f"\n  {Colors.BRIGHT_WHITE}Analysis:{Colors.RESET} {arg[:60]}...")
        print(f"  {'─' * 60}")
        
        key_features = ['severity_score', 'max_pattern_score', 'entropy']
        for key in key_features:
            if key in features.features:
                print(f"  {key}: {features.features[key]:.3f}")
        
        if patterns:
            print(f"\n  {Colors.BRIGHT_YELLOW}Detected Patterns:{Colors.RESET}")
            for p in patterns:
                print(f"    • {p.pattern_name} (confidence: {p.confidence:.2f})")
        else:
            print(f"\n  {Colors.BRIGHT_GREEN}No suspicious patterns detected{Colors.RESET}")
    
    def postcmd(self, stop, line):
        """Track command history."""
        if line and line.strip():
            self.command_history.append(line)
        return stop


def run_console(config_path: Optional[str] = None):
    """Run the interactive console."""
    console = LibraConsole(config_path)
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Colors.BRIGHT_BLUE}[*]{Colors.RESET} Interrupted. Type 'exit' to quit.")
        console.cmdloop()


if __name__ == '__main__':
    run_console()
