#!/usr/bin/env python3
"""
menuscript.parsers.sqlmap_parser

Parses SQLMap SQL injection detection output into structured findings.
"""
import re
from typing import Dict, List, Any


def parse_sqlmap_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse SQLMap output and extract SQL injection vulnerabilities.

    SQLMap output contains:
    - Testing messages for each parameter
    - Warnings about potential vulnerabilities (XSS, FI, SQLi)
    - Results indicating if parameters are injectable
    - Database enumeration results

    Args:
        output: Raw sqlmap output text
        target: Target URL from job

    Returns:
        Dict with structure:
        {
            'target_url': str,
            'urls_tested': [str, ...],
            'vulnerabilities': [
                {
                    'url': str,
                    'parameter': str,
                    'vuln_type': str,  # 'sqli', 'xss', 'fi'
                    'injectable': bool,
                    'technique': str,  # if SQLi found
                    'dbms': str        # if identified
                },
                ...
            ],
            'databases': [str, ...]  # if enumerated
        }
    """
    result = {
        'target_url': target,
        'urls_tested': [],
        'vulnerabilities': [],
        'databases': []
    }

    lines = output.split('\n')
    current_url = None
    current_param = None

    for i, line in enumerate(lines):
        line = line.strip()

        # Extract URL being tested
        if 'testing URL' in line:
            url_match = re.search(r"testing URL '([^']+)'", line)
            if url_match:
                current_url = url_match.group(1)
                if current_url not in result['urls_tested']:
                    result['urls_tested'].append(current_url)

        # Extract parameter being tested
        elif 'testing if' in line and 'parameter' in line:
            param_match = re.search(r"(?:GET|POST|Cookie|User-Agent|Referer) parameter '([^']+)'", line)
            if param_match:
                current_param = param_match.group(1)

        # Detect XSS vulnerability hint
        elif 'might be vulnerable to cross-site scripting (XSS)' in line:
            param_match = re.search(r"parameter '([^']+)'", line)
            if param_match or current_param:
                param = param_match.group(1) if param_match else current_param
                result['vulnerabilities'].append({
                    'url': current_url or target,
                    'parameter': param,
                    'vuln_type': 'xss',
                    'injectable': False,
                    'severity': 'medium',
                    'description': f"Parameter '{param}' might be vulnerable to XSS"
                })

        # Detect File Inclusion vulnerability hint
        elif 'might be vulnerable to file inclusion (FI)' in line:
            param_match = re.search(r"parameter '([^']+)'", line)
            if param_match or current_param:
                param = param_match.group(1) if param_match else current_param
                result['vulnerabilities'].append({
                    'url': current_url or target,
                    'parameter': param,
                    'vuln_type': 'file_inclusion',
                    'injectable': False,
                    'severity': 'high',
                    'description': f"Parameter '{param}' might be vulnerable to File Inclusion"
                })

        # Detect SQL injection vulnerability
        elif 'parameter' in line and 'is vulnerable' in line:
            param_match = re.search(r"parameter '([^']+)' is vulnerable", line)
            if param_match:
                param = param_match.group(1)
                result['vulnerabilities'].append({
                    'url': current_url or target,
                    'parameter': param,
                    'vuln_type': 'sqli',
                    'injectable': True,
                    'severity': 'critical',
                    'description': f"Parameter '{param}' is vulnerable to SQL injection"
                })

        # Detect not injectable result
        elif 'does not seem to be injectable' in line:
            param_match = re.search(r"parameter '([^']+)' does not seem to be injectable", line)
            # We skip these - only store actual vulnerabilities

        # Extract databases (if enumerated)
        elif 'available databases' in line.lower():
            # Next few lines will contain database names
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith('[*]'):
                db_line = lines[j].strip()
                if db_line.startswith('[*]'):
                    db_name = db_line.replace('[*]', '').strip()
                    if db_name and not db_name.startswith('INFO'):
                        result['databases'].append(db_name)
                j += 1

    return result


def get_sqli_stats(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from parsed SQLMap results.

    Returns:
        Dict with counts and summary info
    """
    sqli_count = sum(1 for v in parsed.get('vulnerabilities', [])
                     if v.get('vuln_type') == 'sqli' and v.get('injectable'))

    xss_count = sum(1 for v in parsed.get('vulnerabilities', [])
                    if v.get('vuln_type') == 'xss')

    fi_count = sum(1 for v in parsed.get('vulnerabilities', [])
                   if v.get('vuln_type') == 'file_inclusion')

    return {
        'total_vulns': len(parsed.get('vulnerabilities', [])),
        'sqli_confirmed': sqli_count,
        'xss_possible': xss_count,
        'fi_possible': fi_count,
        'urls_tested': len(parsed.get('urls_tested', [])),
        'databases_found': len(parsed.get('databases', []))
    }
