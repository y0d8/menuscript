#!/usr/bin/env python3
"""
CVE Matcher - Extract and match CVEs from scan output
"""
import re
from typing import List, Dict, Tuple, Optional


class CVEMatcher:
    """Extract CVEs from scan output and match services to known vulnerabilities."""
    
    # Common vulnerable service versions (simple database)
    KNOWN_VULNS = {
        'openssh': [
            ('7.4', 'CVE-2018-15473', 7.5, 'Username enumeration vulnerability'),
            ('7.7', 'CVE-2019-6109', 6.8, 'Forced command injection'),
            ('8.5', 'CVE-2021-41617', 7.0, 'Privilege escalation'),
        ],
        'vsftpd': [
            ('2.3.4', 'CVE-2011-2523', 10.0, 'Backdoor command execution'),
        ],
        'apache': [
            ('2.4.49', 'CVE-2021-41773', 7.5, 'Path traversal and RCE'),
            ('2.4.50', 'CVE-2021-42013', 9.8, 'Path traversal and RCE'),
        ],
        'nginx': [
            ('1.16.1', 'CVE-2019-20372', 5.3, 'HTTP request smuggling'),
        ],
        'mysql': [
            ('5.5.62', 'CVE-2019-2805', 6.5, 'Partial DOS vulnerability'),
        ],
        'samba': [
            ('3.5.0', 'CVE-2017-7494', 10.0, 'Remote code execution'),
            ('4.5.16', 'CVE-2017-14746', 7.5, 'Use-after-free'),
        ],
        'proftpd': [
            ('1.3.5', 'CVE-2015-3306', 10.0, 'Remote code execution'),
        ]
    }
    
    def extract_cves_from_text(self, text: str) -> List[str]:
        """
        Extract CVE identifiers from text.
        
        Args:
            text: Text to search (nmap output, etc.)
            
        Returns:
            List of CVE IDs found
        """
        # Match CVE-YYYY-NNNNN format
        pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(pattern, text, re.IGNORECASE)
        return list(set([cve.upper() for cve in cves]))
    
    def match_service_version(
        self,
        service: str,
        version: str
    ) -> List[Tuple[str, float, str]]:
        """
        Match service/version to known vulnerabilities.
        
        Args:
            service: Service name (e.g., 'openssh', 'apache')
            version: Version string (e.g., '7.4', '2.4.49')
            
        Returns:
            List of (cve_id, cvss_score, description) tuples
        """
        service_lower = service.lower()
        results = []
        
        # Normalize version (remove 'p' suffix, etc.)
        version_clean = version.split('p')[0].split('-')[0]
        
        if service_lower in self.KNOWN_VULNS:
            for vuln_version, cve, cvss, desc in self.KNOWN_VULNS[service_lower]:
                # Simple version matching (exact or starts with)
                if version_clean.startswith(vuln_version) or version_clean == vuln_version:
                    results.append((cve, cvss, desc))
        
        return results
    
    def parse_nmap_service(self, service_info: Dict) -> List[Dict]:
        """
        Parse nmap service info and return potential vulnerabilities.
        
        Args:
            service_info: Dict with 'service_name', 'version', 'port', etc.
            
        Returns:
            List of vulnerability dicts
        """
        service = service_info.get('service_name', '')
        version = service_info.get('version', '')
        port = service_info.get('port')
        
        if not service or not version:
            return []
        
        findings = []
        
        # Match against known vulnerabilities
        vulns = self.match_service_version(service, version)
        
        for cve_id, cvss_score, description in vulns:
            findings.append({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'title': f"{cve_id} - Vulnerable {service} {version}",
                'description': f"{description}\n\nService: {service} {version}\nPort: {port}",
                'service': service,
                'version': version,
                'port': port,
                'severity': self._cvss_to_severity(cvss_score)
            })
        
        return findings
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score >= 0.1:
            return 'low'
        else:
            return 'info'
    
    def scan_for_common_issues(self, service_info: Dict) -> List[Dict]:
        """
        Scan for common misconfigurations and issues.
        
        Args:
            service_info: Service information
            
        Returns:
            List of finding dicts
        """
        findings = []
        service = service_info.get('service_name', '').lower()
        port = service_info.get('port')
        
        # Check for insecure services
        if service in ['telnet', 'ftp', 'tftp']:
            findings.append({
                'title': f'Insecure Protocol - {service.upper()}',
                'description': f'{service.upper()} transmits data in cleartext and should not be used. Consider using secure alternatives (SSH for telnet, SFTP/FTPS for FTP).',
                'severity': 'high',
                'category': 'misconfiguration',
                'port': port,
                'remediation': f'Disable {service.upper()} and use encrypted alternatives.'
            })
        
        # Check for default/dangerous ports
        if service == 'http' and port == 80:
            findings.append({
                'title': 'Unencrypted HTTP Service',
                'description': 'HTTP service detected without encryption. Data transmitted over HTTP can be intercepted.',
                'severity': 'medium',
                'category': 'misconfiguration',
                'port': port,
                'remediation': 'Enable HTTPS (TLS/SSL) for all web services.'
            })
        
        # Check for SMB
        if service in ['microsoft-ds', 'netbios-ssn', 'smb']:
            findings.append({
                'title': 'SMB Service Exposed',
                'description': 'SMB file sharing is exposed. Ensure proper authentication and encryption are configured.',
                'severity': 'medium',
                'category': 'exposure',
                'port': port,
                'remediation': 'Restrict SMB access to trusted networks, enable SMB signing, disable SMBv1.'
            })
        
        return findings
