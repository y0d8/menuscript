#!/usr/bin/env python3
"""
menuscript.parsers.gobuster_parser

Parses Gobuster directory/file enumeration output into structured data.
"""
import re
from typing import Dict, List, Any
from urllib.parse import urlparse


def parse_gobuster_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse Gobuster dir mode output and extract discovered paths.

    Gobuster output format:
    ===============================================================
    Gobuster v3.8
    ===============================================================
    [+] Url:                     http://example.com
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /path/to/wordlist.txt
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /admin                (Status: 200) [Size: 1234]
    /images               (Status: 301) [Size: 169] [--> http://example.com/images/]
    /cgi-bin/             (Status: 403) [Size: 276]
    ===============================================================
    Finished
    ===============================================================

    Args:
        output: Raw gobuster output text
        target: Target URL from job

    Returns:
        Dict with structure:
        {
            'target_url': str,
            'paths': [
                {
                    'path': str,
                    'status_code': int,
                    'size': int,
                    'redirect': str  # if present
                },
                ...
            ]
        }
    """
    result = {
        'target_url': target,
        'paths': []
    }

    lines = output.split('\n')

    for line in lines:
        line = line.strip()

        # Extract target URL from header
        if line.startswith('[+] Url:'):
            url_match = re.search(r'\[?\+\]?\s*Url:\s+(\S+)', line)
            if url_match:
                result['target_url'] = url_match.group(1)

        # Parse discovered paths
        # Format: /path                (Status: NNN) [Size: NNN] [--> redirect]
        elif line.startswith('/'):
            path_data = _parse_path_line(line, result['target_url'])
            if path_data:
                result['paths'].append(path_data)

    return result


def _parse_path_line(line: str, base_url: str = "") -> Dict[str, Any]:
    """
    Parse a single gobuster path discovery line.

    Example formats:
    /admin                (Status: 200) [Size: 1234]
    /images               (Status: 301) [Size: 169] [--> http://example.com/images/]
    /cgi-bin/             (Status: 403) [Size: 276]

    Returns:
        Dict with path info or None if parsing fails
    """
    try:
        # Extract path (everything before first parenthesis or multiple spaces)
        path_match = re.match(r'^(/[^\s(]+)\s+', line)
        if not path_match:
            return None

        path = path_match.group(1).strip()

        # Extract status code
        status_match = re.search(r'\(Status:\s*(\d+)\)', line)
        status_code = int(status_match.group(1)) if status_match else None

        # Extract size
        size_match = re.search(r'\[Size:\s*(\d+)\]', line)
        size = int(size_match.group(1)) if size_match else None

        # Extract redirect target if present
        redirect_match = re.search(r'\[-+>\s*([^\]]+)\]', line)
        redirect = redirect_match.group(1).strip() if redirect_match else None

        # Build full URL
        if base_url:
            parsed = urlparse(base_url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            full_url = path

        return {
            'path': path,
            'url': full_url,
            'status_code': status_code,
            'size': size,
            'redirect': redirect
        }
    except Exception:
        return None


def get_paths_stats(parsed: Dict[str, Any]) -> Dict[str, int]:
    """
    Get statistics from parsed gobuster results.

    Args:
        parsed: Output from parse_gobuster_output()

    Returns:
        Dict with counts by status code: {'200': 5, '301': 3, '403': 2, ...}
    """
    stats = {
        'total': len(parsed.get('paths', [])),
        'redirects': 0,
        'by_status': {}
    }

    for path in parsed.get('paths', []):
        status = str(path.get('status_code', 'unknown'))
        stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
        
        # Count redirects (301, 302, 303, 307, 308)
        if path.get('redirect'):
            stats['redirects'] += 1

    return stats


def categorize_status(status_code: int) -> str:
    """
    Categorize HTTP status codes.

    Returns: 'success', 'redirect', 'client_error', 'server_error', 'unknown'
    """
    if 200 <= status_code < 300:
        return 'success'
    elif 300 <= status_code < 400:
        return 'redirect'
    elif 400 <= status_code < 500:
        return 'client_error'
    elif 500 <= status_code < 600:
        return 'server_error'
    else:
        return 'unknown'
