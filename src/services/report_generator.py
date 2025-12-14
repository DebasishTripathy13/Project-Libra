"""
ProjectLibra - Report Generator
Generate professional security reports in Markdown and PDF formats
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ReportSection:
    """Report section"""
    title: str
    content: str
    level: int = 2  # Heading level


class ReportGenerator:
    """
    Professional security report generator.
    
    Generates downloadable reports in Markdown format with AI analysis.
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    async def generate_security_report(
        self,
        system_metrics: Dict,
        log_analysis: Dict,
        integrity_status: Dict,
        threat_assessment: Optional[Dict] = None,
        include_ai_analysis: bool = True,
    ) -> str:
        """
        Generate comprehensive security report.
        
        Returns markdown-formatted report.
        """
        sections = []
        
        # Header
        sections.append(self._generate_header())
        
        # Executive Summary
        sections.append(await self._generate_executive_summary(
            system_metrics, log_analysis, integrity_status, threat_assessment
        ))
        
        # System Status
        sections.append(self._generate_system_status(system_metrics))
        
        # Security Analysis
        sections.append(self._generate_security_analysis(log_analysis, integrity_status))
        
        # Threat Assessment
        if threat_assessment:
            sections.append(self._generate_threat_assessment(threat_assessment))
        
        # AI Analysis (if LLM available)
        if include_ai_analysis and self.llm_client:
            sections.append(await self._generate_ai_analysis(
                system_metrics, log_analysis, integrity_status
            ))
        
        # Recommendations
        sections.append(self._generate_recommendations(
            system_metrics, log_analysis, integrity_status
        ))
        
        # Footer
        sections.append(self._generate_footer())
        
        # Combine sections
        return '\n\n'.join([self._format_section(s) for s in sections])
    
    def _generate_header(self) -> ReportSection:
        """Generate report header"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        content = f"""# ProjectLibra Security Report

**Generated:** {timestamp}  
**Report Type:** Comprehensive System Security Analysis  
**Classification:** Confidential

---
"""
        return ReportSection(title='', content=content, level=1)
    
    async def _generate_executive_summary(
        self,
        system_metrics: Dict,
        log_analysis: Dict,
        integrity_status: Dict,
        threat_assessment: Optional[Dict],
    ) -> ReportSection:
        """Generate executive summary"""
        
        # Calculate overall risk level
        risk_score = 0
        
        # Check system resources
        cpu = system_metrics.get('cpu_percent', 0)
        memory = system_metrics.get('memory_percent', 0)
        disk = system_metrics.get('disk_percent', 0)
        
        if cpu > 90: risk_score += 2
        elif cpu > 75: risk_score += 1
        
        if memory > 90: risk_score += 2
        elif memory > 75: risk_score += 1
        
        if disk > 90: risk_score += 3
        elif disk > 75: risk_score += 1
        
        # Check log analysis
        errors = log_analysis.get('by_level', {}).get('error', 0)
        criticals = log_analysis.get('by_level', {}).get('critical', 0)
        
        if criticals > 0: risk_score += 5
        if errors > 10: risk_score += 2
        
        # Check integrity
        tampered = integrity_status.get('tampered_records', 0)
        missing = integrity_status.get('missing_records', 0)
        
        if tampered > 0: risk_score += 10
        if missing > 0: risk_score += 8
        
        # Determine status
        if risk_score >= 10:
            status = '🔴 **CRITICAL**'
            status_desc = 'Immediate action required'
        elif risk_score >= 5:
            status = '🟠 **WARNING**'
            status_desc = 'Issues require attention'
        elif risk_score >= 2:
            status = '🟡 **CAUTION**'
            status_desc = 'Minor issues detected'
        else:
            status = '🟢 **HEALTHY**'
            status_desc = 'System operating normally'
        
        content = f"""## Executive Summary

**Overall Status:** {status}  
**Assessment:** {status_desc}  
**Risk Score:** {risk_score}/20

### Key Findings

- **System Health:** CPU {cpu:.1f}%, Memory {memory:.1f}%, Disk {disk:.1f}%
- **Log Analysis:** {log_analysis.get('total_lines', 0)} lines analyzed, {errors} errors, {criticals} critical events
- **Database Integrity:** {integrity_status.get('verified_records', 0)} verified, {tampered} tampered, {missing} missing
- **Security Patterns:** {len(log_analysis.get('matched_patterns', {}))} pattern types detected

"""
        
        if tampered > 0 or missing > 0:
            content += "\n⚠️ **ALERT:** Database tampering detected! Forensic investigation required.\n"
        
        if criticals > 0:
            content += f"\n⚠️ **ALERT:** {criticals} critical events in logs require immediate review.\n"
        
        return ReportSection(title='Executive Summary', content=content)
    
    def _generate_system_status(self, metrics: Dict) -> ReportSection:
        """Generate system status section"""
        
        content = f"""## System Status

### Hardware Information

| Component | Value |
|-----------|-------|
| **Hostname** | {metrics.get('hostname', 'N/A')} |
| **Platform** | {metrics.get('platform', 'N/A')} |
| **Kernel** | {metrics.get('kernel', 'N/A')} |
| **Uptime** | {self._format_uptime(metrics.get('uptime_seconds', 0))} |
| **CPU Cores** | {metrics.get('cpu_count', 'N/A')} |

### Resource Utilization

| Resource | Usage | Status |
|----------|-------|--------|
| **CPU** | {metrics.get('cpu_percent', 0):.1f}% | {self._status_icon(metrics.get('cpu_percent', 0), 75, 90)} |
| **Memory** | {metrics.get('memory_percent', 0):.1f}% | {self._status_icon(metrics.get('memory_percent', 0), 75, 90)} |
| **Swap** | {metrics.get('swap_percent', 0):.1f}% | {self._status_icon(metrics.get('swap_percent', 0), 50, 75)} |
| **Disk** | {metrics.get('disk_percent', 0):.1f}% | {self._status_icon(metrics.get('disk_percent', 0), 75, 90)} |

### Memory Details

- **Total:** {self._bytes_to_human(metrics.get('memory_total', 0))}
- **Used:** {self._bytes_to_human(metrics.get('memory_used', 0))}
- **Available:** {self._bytes_to_human(metrics.get('memory_available', 0))}

### Disk Details

- **Total:** {self._bytes_to_human(metrics.get('disk_total', 0))}
- **Used:** {self._bytes_to_human(metrics.get('disk_used', 0))}
- **Free:** {self._bytes_to_human(metrics.get('disk_free', 0))}
- **Read:** {self._bytes_to_human(metrics.get('disk_read_bytes', 0))}
- **Write:** {self._bytes_to_human(metrics.get('disk_write_bytes', 0))}

### Network Activity

- **Sent:** {self._bytes_to_human(metrics.get('network_bytes_sent', 0))}
- **Received:** {self._bytes_to_human(metrics.get('network_bytes_recv', 0))}
- **Packets Sent:** {metrics.get('network_packets_sent', 0):,}
- **Packets Received:** {metrics.get('network_packets_recv', 0):,}
"""
        
        return ReportSection(title='System Status', content=content)
    
    def _generate_security_analysis(self, log_analysis: Dict, integrity: Dict) -> ReportSection:
        """Generate security analysis section"""
        
        content = """## Security Analysis

### Log Analysis Summary

"""
        
        # Log statistics
        content += f"""
**Total Lines Analyzed:** {log_analysis.get('total_lines', 0):,}  
**Successfully Parsed:** {log_analysis.get('parsed_lines', 0):,}  

#### Events by Severity

"""
        
        by_level = log_analysis.get('by_level', {})
        content += "| Level | Count |\n|-------|-------|\n"
        for level in ['critical', 'error', 'warning', 'info', 'debug']:
            count = by_level.get(level, 0)
            icon = {'critical': '🔴', 'error': '🔴', 'warning': '🟡', 'info': '🔵', 'debug': '⚪'}.get(level, '⚪')
            content += f"| {icon} **{level.upper()}** | {count:,} |\n"
        
        # Pattern matches
        patterns = log_analysis.get('matched_patterns', {})
        if patterns:
            content += "\n#### Detected Security Patterns\n\n"
            content += "| Pattern | Occurrences | Severity |\n|---------|-------------|----------|\n"
            for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
                severity = self._get_pattern_severity(pattern)
                content += f"| {pattern.replace('_', ' ').title()} | {count} | {severity} |\n"
        
        # Critical events
        criticals = log_analysis.get('criticals', [])
        if criticals:
            content += f"\n#### Critical Events ({len(criticals)})\n\n```\n"
            content += '\n'.join(criticals[:10])
            if len(criticals) > 10:
                content += f"\n... and {len(criticals) - 10} more\n"
            content += "```\n"
        
        # Database integrity
        content += "\n### Database Integrity\n\n"
        content += f"""
**Verified Records:** {integrity.get('verified_records', 0):,}  
**Tampered Records:** {integrity.get('tampered_records', 0)}  
**Missing Records:** {integrity.get('missing_records', 0)}  
**Status:** {"✅ HEALTHY" if integrity.get('tampered_records', 0) == 0 else "⚠️ COMPROMISED"}

"""
        
        if integrity.get('tampered_records', 0) > 0:
            content += "\n**⚠️ WARNING:** Database tampering detected!\n\n"
            tampered_ids = integrity.get('tampered_ids', [])
            if tampered_ids:
                content += f"**Affected Record IDs:** {', '.join(map(str, tampered_ids[:20]))}\n"
        
        return ReportSection(title='Security Analysis', content=content)
    
    def _generate_threat_assessment(self, threat: Dict) -> ReportSection:
        """Generate threat assessment section"""
        
        level = threat.get('threat_level', 'unknown').upper()
        confidence = threat.get('confidence', 0) * 100
        
        level_icon = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'NONE': '⚪'
        }.get(level, '⚪')
        
        content = f"""## Threat Assessment

{level_icon} **Threat Level:** {level}  
**Confidence:** {confidence:.1f}%  
**Assessment ID:** {threat.get('assessment_id', 'N/A')}  
**Timestamp:** {threat.get('timestamp', 'N/A')}

### Summary

{threat.get('summary', 'No summary available')}

### Indicators of Compromise

"""
        
        indicators = threat.get('indicators', [])
        if indicators:
            for indicator in indicators:
                content += f"- {indicator}\n"
        else:
            content += "- No indicators detected\n"
        
        content += "\n### Recommended Actions\n\n"
        
        actions = threat.get('recommended_actions', [])
        if actions:
            for i, action in enumerate(actions, 1):
                content += f"{i}. {action}\n"
        else:
            content += "- Continue monitoring\n"
        
        return ReportSection(title='Threat Assessment', content=content)
    
    async def _generate_ai_analysis(
        self,
        system_metrics: Dict,
        log_analysis: Dict,
        integrity: Dict,
    ) -> ReportSection:
        """Generate AI-powered analysis section"""
        
        if not self.llm_client:
            return ReportSection(
                title='AI Analysis',
                content="## AI Analysis\n\n*AI analysis not available (LLM client not configured)*\n"
            )
        
        # Prepare data for AI
        context = f"""Analyze this security data and provide expert insights:

SYSTEM METRICS:
- CPU: {system_metrics.get('cpu_percent', 0):.1f}%
- Memory: {system_metrics.get('memory_percent', 0):.1f}%
- Disk: {system_metrics.get('disk_percent', 0):.1f}%

LOG ANALYSIS:
- Total lines: {log_analysis.get('total_lines', 0)}
- Errors: {log_analysis.get('by_level', {}).get('error', 0)}
- Critical events: {log_analysis.get('by_level', {}).get('critical', 0)}
- Detected patterns: {list(log_analysis.get('matched_patterns', {}).keys())}

DATABASE INTEGRITY:
- Verified: {integrity.get('verified_records', 0)}
- Tampered: {integrity.get('tampered_records', 0)}
- Missing: {integrity.get('missing_records', 0)}

Provide:
1. Overall security assessment
2. Key concerns and vulnerabilities
3. Recommended immediate actions
4. Long-term security improvements
"""
        
        try:
            analysis = await self.llm_client.generate(context)
            
            content = f"""## AI-Powered Analysis

*Generated by: {self.llm_client.__class__.__name__}*

{analysis.content if hasattr(analysis, 'content') else str(analysis)}
"""
            
            return ReportSection(title='AI Analysis', content=content)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return ReportSection(
                title='AI Analysis',
                content=f"## AI Analysis\n\n*AI analysis failed: {str(e)}*\n"
            )
    
    def _generate_recommendations(
        self,
        system_metrics: Dict,
        log_analysis: Dict,
        integrity: Dict,
    ) -> ReportSection:
        """Generate recommendations section"""
        
        recommendations = []
        
        # System recommendations
        if system_metrics.get('cpu_percent', 0) > 80:
            recommendations.append("🔴 **Critical:** CPU usage is very high. Investigate resource-intensive processes.")
        
        if system_metrics.get('memory_percent', 0) > 80:
            recommendations.append("🔴 **Critical:** Memory usage is very high. Consider increasing RAM or optimizing applications.")
        
        if system_metrics.get('disk_percent', 0) > 85:
            recommendations.append("🟠 **Warning:** Disk space is running low. Clean up unused files or expand storage.")
        
        # Log recommendations
        criticals = log_analysis.get('by_level', {}).get('critical', 0)
        if criticals > 0:
            recommendations.append(f"🔴 **Critical:** {criticals} critical log events require immediate investigation.")
        
        errors = log_analysis.get('by_level', {}).get('error', 0)
        if errors > 50:
            recommendations.append(f"🟡 **Caution:** High error count ({errors}) in logs. Review and address root causes.")
        
        # Security recommendations
        patterns = log_analysis.get('matched_patterns', {})
        if 'SSH_FAILED_LOGIN' in patterns and patterns['SSH_FAILED_LOGIN'] > 5:
            recommendations.append("🟠 **Warning:** Multiple failed SSH login attempts detected. Enable fail2ban or review firewall rules.")
        
        if 'BRUTE_FORCE' in patterns:
            recommendations.append("🔴 **Critical:** Brute force attack detected! Block attacker IPs immediately.")
        
        if 'MALWARE_SIGNATURE' in patterns:
            recommendations.append("🔴 **CRITICAL:** Malware signature detected! Isolate affected systems and run full security scan.")
        
        # Integrity recommendations
        if integrity.get('tampered_records', 0) > 0:
            recommendations.append("🔴 **CRITICAL:** Database tampering detected! Begin forensic investigation immediately.")
        
        if integrity.get('missing_records', 0) > 0:
            recommendations.append("🟠 **Warning:** Missing database records detected. Investigate potential data loss or deletion attacks.")
        
        # General recommendations if all is well
        if not recommendations:
            recommendations.append("🟢 **Status:** System is healthy. Continue regular monitoring and maintain current security posture.")
            recommendations.append("📋 **Best Practice:** Schedule regular security audits and keep systems updated.")
            recommendations.append("🔐 **Best Practice:** Review and rotate credentials periodically.")
        
        content = "## Recommendations\n\n"
        for i, rec in enumerate(recommendations, 1):
            content += f"{i}. {rec}\n"
        
        return ReportSection(title='Recommendations', content=content)
    
    def _generate_footer(self) -> ReportSection:
        """Generate report footer"""
        content = f"""---

## Report Information

**Generated by:** ProjectLibra Security Platform  
**Version:** 1.0.0  
**Timestamp:** {datetime.now().isoformat()}  
**Classification:** Confidential - Internal Use Only

*This report contains sensitive security information. Handle according to your organization's data classification policy.*

---

**ProjectLibra** - Agentic AI Security Platform  
© 2025 | All Rights Reserved
"""
        return ReportSection(title='', content=content, level=1)
    
    def _format_section(self, section: ReportSection) -> str:
        """Format a report section"""
        return section.content
    
    @staticmethod
    def _status_icon(value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status icon based on thresholds"""
        if value >= critical_threshold:
            return '🔴 Critical'
        elif value >= warning_threshold:
            return '🟡 Warning'
        else:
            return '🟢 Normal'
    
    @staticmethod
    def _bytes_to_human(bytes_val: int) -> str:
        """Convert bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format uptime"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{days}d {hours}h {minutes}m"
    
    @staticmethod
    def _get_pattern_severity(pattern_name: str) -> str:
        """Get severity for pattern"""
        critical_patterns = ['MALWARE', 'KERNEL_PANIC', 'OUT_OF_MEMORY', 'BRUTE_FORCE']
        warning_patterns = ['SSH_FAILED_LOGIN', 'AUTHENTICATION_FAILURE', 'PRIVILEGE_ESCALATION']
        
        pattern_upper = pattern_name.upper()
        
        if any(p in pattern_upper for p in critical_patterns):
            return '🔴 Critical'
        elif any(p in pattern_upper for p in warning_patterns):
            return '🟡 Warning'
        else:
            return '🔵 Info'
