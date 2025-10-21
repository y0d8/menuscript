#!/usr/bin/env python3
"""
menuscript.parsers.nikto_parser

Parses Nikto web vulnerability scan output into structured findings.
"""
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


def parse_nikto_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse Nikto text output and extract findings.

    Nikto output format:
    + Target IP:          44.228.249.3
    + Target Hostname:    testphp.vulnweb.com
    + Target Port:        80
    + Server: nginx/1.19.0
    + /path: Description of finding. See: https://reference-url
    - lines starting with '+' are findings
    - lines starting with '-' are informational

    Args:
        output: Raw nikto output text
        target: Target URL/host from job

    Returns:
        Dict with structure:
        {
            'target_ip': str,
            'target_host': str,
            'target_port': int,
            'server': str,
            'findings': [
                {
                    'path': str,
                    'description': str,
                    'reference': str,  # URL if present
                    'severity': str    # 'info', 'low', 'medium', 'high'
                }
            ]
        }
    """
    result = {
        'target_ip': None,
        'target_host': None,
        'target_port': 80,
        'server': None,
        'findings': []
    }

    lines = output.split('\n')

    for line in lines:
        line = line.strip()

        # Extract target metadata
        if '+ Target IP:' in line:
            result['target_ip'] = line.split(':', 1)[1].strip()
        elif '+ Target Hostname:' in line:
            result['target_host'] = line.split(':', 1)[1].strip()
        elif '+ Target Port:' in line:
            try:
                result['target_port'] = int(line.split(':', 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif '+ Server:' in line and 'Start Time' not in line:
            result['server'] = line.split(':', 1)[1].strip()

        # Parse findings (lines starting with '+' that have a path)
        elif line.startswith('+ /'):
            finding = _parse_finding_line(line)
            if finding:
                result['findings'].append(finding)

        # Parse other findings (security headers, etc.)
        elif line.startswith('+ ') and ': ' in line and not any(x in line for x in ['Target', 'Server:', 'Start Time', 'End Time', 'Retrieved', 'Scan terminated', 'host(s) tested']):
            # Generic finding line (e.g., header issues)
            finding = _parse_generic_finding(line)
            if finding:
                result['findings'].append(finding)

    # If target_host not found in output, try to extract from target parameter
    if not result['target_host'] and target:
        parsed = urlparse(target if '://' in target else f'http://{target}')
        result['target_host'] = parsed.hostname or target
        if parsed.port:
            result['target_port'] = parsed.port

    return result


def _parse_finding_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a finding line like:
    + /path: Description. See: https://reference

    Returns finding dict or None if parsing fails.
    """
    try:
        # Remove leading '+' and split on first ':'
        content = line[1:].strip()

        if ': ' not in content:
            return None

        path_part, desc_part = content.split(':', 1)
        path = path_part.strip()
        description = desc_part.strip()

        # Extract reference URL if present
        reference = None
        if 'See: http' in description:
            # Split on 'See:' to get the URL
            parts = description.split('See: http', 1)
            if len(parts) == 2:
                reference = 'http' + parts[1].strip().rstrip('.')
                # Clean up description (remove the See: part)
                description = parts[0].strip().rstrip('.')

        # Determine severity based on keywords
        severity = _determine_severity(description)

        return {
            'path': path,
            'description': description,
            'reference': reference,
            'severity': severity
        }
    except Exception:
        return None


def _parse_generic_finding(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse generic finding lines (non-path findings like headers).

    Example:
    + Retrieved x-powered-by header: PHP/5.6.40
    """
    try:
        # Remove leading '+' and parse
        content = line[1:].strip()

        # Extract reference if present
        reference = None
        if 'See: http' in content:
            parts = content.split('See: http', 1)
            if len(parts) == 2:
                reference = 'http' + parts[1].strip().rstrip('.')
                content = parts[0].strip().rstrip('.')

        severity = _determine_severity(content)

        return {
            'path': '/',  # Generic path for non-path findings
            'description': content,
            'reference': reference,
            'severity': severity
        }
    except Exception:
        return None


def _determine_severity(description: str) -> str:
    """
    Determine finding severity based on description keywords.

    Returns: 'critical', 'high', 'medium', 'low', or 'info'
    """
    desc_lower = description.lower()

    # Critical indicators
    if any(word in desc_lower for word in ['sql injection', 'remote code execution', 'rce', 'command injection']):
        return 'critical'

    # High severity
    if any(word in desc_lower for word in ['authentication bypass', 'directory traversal', 'file inclusion', 'xss', 'cross-site scripting', 'csrf']):
        return 'high'

    # Medium severity
    if any(word in desc_lower for word in ['x-frame-options', 'x-content-type-options', 'clickjacking', 'wildcard', 'crossdomain.xml', 'clientaccesspolicy.xml']):
        return 'medium'

    # Low severity
    if any(word in desc_lower for word in ['header', 'banner', 'version', 'disclosure', 'powered-by']):
        return 'low'

    # Default to info
    return 'info'


def format_finding_title(finding: Dict[str, Any]) -> str:
    """
    Generate a concise title for a finding.

    Args:
        finding: Finding dict with path and description

    Returns:
        Formatted title string
    """
    desc = finding['description']

    # Truncate long descriptions
    if len(desc) > 100:
        desc = desc[:97] + '...'

    # If path is just '/', use description as title
    if finding['path'] == '/':
        return desc

    # Otherwise, include path
    return f"{finding['path']}: {desc}"
