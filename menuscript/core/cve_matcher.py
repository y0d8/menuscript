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
        # OpenSSH vulnerabilities
        'openssh': [
            ('4.7', 'CVE-2008-5161', 7.5, 'Privilege escalation via X11 forwarding'),
            ('5.8', 'CVE-2011-4327', 3.5, 'Forced command handling weakness'),
            ('6.6', 'CVE-2015-5600', 8.5, 'Keyboard-interactive authentication brute force'),
            ('7.2', 'CVE-2016-3115', 5.5, 'Command injection via X11 forwarding'),
            ('7.4', 'CVE-2018-15473', 7.5, 'Username enumeration vulnerability'),
            ('7.7', 'CVE-2019-6109', 6.8, 'Forced command injection'),
            ('8.2', 'CVE-2020-15778', 7.8, 'Command injection via scp'),
            ('8.5', 'CVE-2021-41617', 7.0, 'Privilege escalation'),
        ],
        
        # vsftpd vulnerabilities
        'vsftpd': [
            ('2.0.5', 'CVE-2011-0762', 6.8, 'Denial of service'),
            ('2.3.4', 'CVE-2011-2523', 10.0, 'Backdoor command execution'),
        ],
        
        # ProFTPD vulnerabilities
        'proftpd': [
            ('1.3.0', 'CVE-2010-4221', 9.0, 'SQL injection in mod_sql'),
            ('1.3.3', 'CVE-2011-4130', 10.0, 'Remote code execution'),
            ('1.3.5', 'CVE-2015-3306', 10.0, 'Remote code execution via mod_copy'),
            ('1.3.6', 'CVE-2019-12815', 9.8, 'Arbitrary file copy'),
        ],
        
        # Apache HTTP Server vulnerabilities
        'apache': [
            ('2.2.8', 'CVE-2011-3192', 7.8, 'Range header DoS (Killapache)'),
            ('2.4.7', 'CVE-2014-0098', 5.0, 'Denial of service'),
            ('2.4.29', 'CVE-2017-15710', 5.0, 'Out-of-bounds read'),
            ('2.4.43', 'CVE-2020-9490', 7.5, 'HTTP request smuggling'),
            ('2.4.48', 'CVE-2021-40438', 9.0, 'Server-side request forgery'),
            ('2.4.49', 'CVE-2021-41773', 7.5, 'Path traversal and RCE'),
            ('2.4.50', 'CVE-2021-42013', 9.8, 'Path traversal and RCE'),
        ],
        
        # Nginx vulnerabilities
        'nginx': [
            ('1.3.9', 'CVE-2013-2028', 5.8, 'Chunked transfer encoding bypass'),
            ('1.16.1', 'CVE-2019-20372', 5.3, 'HTTP request smuggling'),
            ('1.20.0', 'CVE-2021-23017', 9.8, 'Off-by-one buffer overflow in DNS resolver'),
        ],
        
        # MySQL vulnerabilities
        'mysql': [
            ('5.0.51', 'CVE-2009-2446', 8.5, 'Format string vulnerability'),
            ('5.5.62', 'CVE-2019-2805', 6.5, 'Partial DOS vulnerability'),
            ('5.7.29', 'CVE-2020-2922', 3.7, 'Information disclosure'),
            ('8.0.19', 'CVE-2020-2780', 6.5, 'Server component vulnerability'),
        ],
        
        # Samba vulnerabilities
        'samba': [
            ('3.0', 'CVE-2007-2447', 10.0, 'Remote command execution via MS-RPC'),
            ('3.5.0', 'CVE-2017-7494', 10.0, 'Remote code execution (SambaCry)'),
            ('4.4', 'CVE-2017-12150', 7.5, 'SMB encryption downgrade'),
            ('4.5.16', 'CVE-2017-14746', 7.5, 'Use-after-free'),
            ('4.11.6', 'CVE-2020-1472', 10.0, 'Zerologon privilege escalation'),
        ],
        
        # PostgreSQL vulnerabilities
        'postgresql': [
            ('8.3.0', 'CVE-2009-3230', 6.5, 'Privilege escalation'),
            ('9.3.10', 'CVE-2016-0766', 8.0, 'Privilege escalation'),
            ('11.2', 'CVE-2019-10130', 4.0, 'Partition routing information disclosure'),
        ],
        
        # Tomcat vulnerabilities
        'tomcat': [
            ('7.0.0', 'CVE-2017-12615', 8.1, 'Remote code execution via PUT'),
            ('8.5.0', 'CVE-2017-12617', 8.1, 'Remote code execution via PUT'),
            ('9.0.0', 'CVE-2020-1938', 9.8, 'Ghostcat - AJP file read/inclusion'),
            ('9.0.30', 'CVE-2020-9484', 7.0, 'Remote code execution via session persistence'),
        ],
        
        # ISC BIND vulnerabilities
        'bind': [
            ('9.4.2', 'CVE-2009-0696', 7.8, 'Dynamic update message DoS'),
            ('9.8.0', 'CVE-2012-1667', 7.8, 'Denial of service'),
            ('9.11.0', 'CVE-2017-3137', 5.9, 'Denial of service'),
        ],
        
        # Postfix vulnerabilities
        'postfix': [
            ('2.5.0', 'CVE-2011-1720', 6.8, 'SMTP server STARTTLS plaintext injection'),
            ('3.3.0', 'CVE-2018-16554', 5.3, 'Denial of service'),
        ],
        
        # UnrealIRCd vulnerabilities
        'unrealircd': [
            ('3.2.8', 'CVE-2010-2075', 10.0, 'Backdoor command execution'),
        ],
        
        # distcc vulnerabilities
        'distccd': [
            ('1.0', 'CVE-2004-2687', 9.3, 'Remote command execution'),
        ],
        
        # Ruby DRb vulnerabilities
        'drb': [
            ('1.8', 'CVE-2011-1004', 10.0, 'Arbitrary command execution'),
        ],
        
        # VNC vulnerabilities
        'vnc': [
            ('3.3', 'CVE-2006-2369', 7.5, 'Authentication bypass'),
        ],
        
        # Jetty vulnerabilities
        'jetty': [
            ('8.1.7', 'CVE-2017-7656', 7.5, 'HTTP request smuggling'),
            ('9.3.0', 'CVE-2017-7658', 9.8, 'Remote code execution'),
        ],
        
        # ElasticSearch vulnerabilities
        'elasticsearch': [
            ('1.4.2', 'CVE-2015-1427', 10.0, 'Remote code execution via Groovy scripting'),
        ],
        
        # Redis vulnerabilities
        'redis': [
            ('4.0.0', 'CVE-2018-11218', 7.5, 'Integer overflow'),
            ('5.0.0', 'CVE-2019-10192', 7.2, 'Hyperloglog DoS'),
        ],
        
        # MongoDB vulnerabilities
        'mongodb': [
            ('3.6.0', 'CVE-2019-2386', 9.8, 'Incorrect authorization'),
        ],
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
            version: Version string (e.g., '7.4', '2.4.49', 'syn-ack ttl 64 vsftpd 2.3.4')
            
        Returns:
            List of (cve_id, cvss_score, description) tuples
        """
        service_lower = service.lower()
        results = []
        
        # Clean version string - extract actual version number
        # Handle formats like: "syn-ack ttl 64 ProFTPD 1.3.5", "OpenSSH 8.5p1", "vsftpd 2.3.4"
        version_clean = version
        
        # Remove nmap response prefixes
        for prefix in ['syn-ack', 'reset', 'no-response', 'ttl']:
            if prefix in version_clean:
                parts = version_clean.split(prefix)
                version_clean = ' '.join(parts[1:]).strip() if len(parts) > 1 else parts[0]
        
        # Extract version number (digits and dots)
        import re
        version_match = re.search(r'(\d+\.[\d.]+(?:p\d+)?(?:-\w+)?)', version_clean)
        if version_match:
            version_clean = version_match.group(1)
        
        # Normalize further (remove 'p' suffix for matching, keep letters/hyphens)
        version_for_match = version_clean.split('p')[0].split('-')[0]
        
        if service_lower in self.KNOWN_VULNS:
            for vuln_version, cve, cvss, desc in self.KNOWN_VULNS[service_lower]:
                # Simple version matching (exact or starts with)
                if version_for_match.startswith(vuln_version) or version_for_match == vuln_version:
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
        service = service_info.get('service_name', '').lower()
        version = service_info.get('version', '')
        port = service_info.get('port')
        
        if not version:
            return []
        
        findings = []
        
        # Extract actual product name from version string if generic service name
        # e.g., "syn-ack ttl 64 vsftpd 2.3.4" → extract "vsftpd"
        version_lower = version.lower()
        product_name = service
        
        # Check if version string contains a known product name
        for known_service in self.KNOWN_VULNS.keys():
            if known_service in version_lower:
                product_name = known_service
                break
        
        # Match against known vulnerabilities using extracted product name
        vulns = self.match_service_version(product_name, version)
        
        for cve_id, cvss_score, description in vulns:
            findings.append({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'title': f"{cve_id} - Vulnerable {product_name} detected",
                'description': f"{description}\n\nService: {service}\nVersion: {version}\nPort: {port}",
                'service': product_name,
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
