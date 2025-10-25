#!/usr/bin/env python3
"""
menuscript.core.credential_tester

Test discovered credentials against hosts to find working authentication.
"""
import subprocess
import time
from typing import List, Dict, Optional, Tuple
from menuscript.storage.credentials import CredentialsManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.findings import FindingsManager
from menuscript.storage.engagements import EngagementManager


class CredentialTester:
    """Test credentials against hosts and track results."""
    
    def __init__(self):
        self.cm = CredentialsManager()
        self.hm = HostManager()
        self.fm = FindingsManager()
        self.em = EngagementManager()
    
    def test_ssh_credential(self, host: str, username: str, password: str = None, timeout: int = 10) -> Tuple[bool, str]:
        """
        Test SSH credential against a host.
        
        Returns:
            (success: bool, message: str)
        """
        if not password:
            # Username-only, can't test
            return (False, "No password to test")
        
        try:
            # Use sshpass to test credentials non-interactively
            cmd = [
                'sshpass', '-p', password,
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=5',
                '-o', 'BatchMode=yes',
                f'{username}@{host}',
                'echo', 'SUCCESS'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0 and 'SUCCESS' in result.stdout:
                return (True, "SSH authentication successful")
            else:
                return (False, f"Authentication failed (rc={result.returncode})")
                
        except subprocess.TimeoutExpired:
            return (False, "Connection timeout")
        except FileNotFoundError:
            return (False, "sshpass not installed (apt install sshpass)")
        except Exception as e:
            return (False, f"Error: {str(e)}")
    
    def test_smb_credential(self, host: str, username: str, password: str = None, timeout: int = 10) -> Tuple[bool, str]:
        """
        Test SMB credential against a host.
        
        Returns:
            (success: bool, message: str)
        """
        if not password:
            password = ""  # Try anonymous/blank password
        
        try:
            # Use smbclient to test credentials
            cmd = [
                'smbclient',
                f'//{host}/IPC$',
                '-U', f'{username}%{password}',
                '-c', 'exit'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # smbclient returns 0 on success
            if result.returncode == 0:
                return (True, "SMB authentication successful")
            else:
                # Check for specific error messages
                stderr = result.stderr.lower()
                if 'logon failure' in stderr or 'access denied' in stderr:
                    return (False, "Invalid credentials")
                elif 'connection refused' in stderr:
                    return (False, "SMB service not available")
                else:
                    return (False, f"Authentication failed (rc={result.returncode})")
                    
        except subprocess.TimeoutExpired:
            return (False, "Connection timeout")
        except FileNotFoundError:
            return (False, "smbclient not installed (apt install smbclient)")
        except Exception as e:
            return (False, f"Error: {str(e)}")
    
    def test_credential_against_host(self, cred: Dict, host: Dict) -> Dict:
        """
        Test a credential against a specific host.
        
        Returns:
            {
                'credential_id': int,
                'host_id': int,
                'service': str,
                'success': bool,
                'message': str,
                'tested_at': str
            }
        """
        service = cred.get('service', '').lower()
        username = cred.get('username')
        password = cred.get('password')
        host_ip = host.get('ip_address')
        
        result = {
            'credential_id': cred.get('id'),
            'host_id': host.get('id'),
            'service': service,
            'success': False,
            'message': 'Unknown service',
            'tested_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }
        
        if service == 'ssh':
            success, message = self.test_ssh_credential(host_ip, username, password)
            result['success'] = success
            result['message'] = message
        elif service == 'smb':
            success, message = self.test_smb_credential(host_ip, username, password)
            result['success'] = success
            result['message'] = message
        else:
            result['message'] = f"Testing not implemented for service: {service}"
        
        return result
    
    def test_all_credentials(self, engagement_id: int) -> Dict:
        """
        Test all credentials in an engagement against all hosts.
        
        Returns:
            {
                'total_tests': int,
                'successful': int,
                'failed': int,
                'findings_created': int,
                'results': [...]
            }
        """
        # Get all credentials and hosts
        credentials = self.cm.list_credentials(engagement_id)
        hosts = self.hm.list_hosts(engagement_id)
        
        # Filter to only active hosts
        active_hosts = [h for h in hosts if h.get('status') == 'up']
        
        results = {
            'total_tests': 0,
            'successful': 0,
            'failed': 0,
            'findings_created': 0,
            'results': []
        }
        
        # Test each credential against each host
        for cred in credentials:
            # Skip username-only credentials for now (need password to test)
            if not cred.get('password'):
                continue
            
            service = cred.get('service', '').lower()
            
            for host in active_hosts:
                # Only test if host has the service running
                if not self._host_has_service(host, service, engagement_id):
                    continue
                
                results['total_tests'] += 1
                
                # Test the credential
                test_result = self.test_credential_against_host(cred, host)
                results['results'].append(test_result)
                
                if test_result['success']:
                    results['successful'] += 1
                    
                    # Create a finding for successful authentication
                    finding = self._create_finding_for_success(
                        engagement_id,
                        host,
                        cred,
                        test_result
                    )
                    if finding:
                        results['findings_created'] += 1
                else:
                    results['failed'] += 1
        
        return results
    
    def _host_has_service(self, host: Dict, service: str, engagement_id: int) -> bool:
        """Check if a host has a specific service running."""
        from menuscript.storage.services import ServiceManager
        sm = ServiceManager()
        
        # Get services for this host
        services = sm.list_services(engagement_id)
        host_services = [s for s in services if s.get('host_id') == host.get('id')]
        
        # Check if service type matches
        service_ports = {
            'ssh': [22],
            'smb': [139, 445],
            'rdp': [3389],
            'ftp': [21],
            'mysql': [3306],
            'postgres': [5432]
        }
        
        target_ports = service_ports.get(service, [])
        for svc in host_services:
            if svc.get('port') in target_ports:
                return True
        
        return False
    
    def _create_finding_for_success(self, engagement_id: int, host: Dict, cred: Dict, test_result: Dict) -> Optional[Dict]:
        """Create a finding for successful credential test."""
        service = cred.get('service', 'unknown')
        username = cred.get('username', 'unknown')
        host_ip = host.get('ip_address', 'unknown')
        
        title = f"Valid {service.upper()} Credentials - {username}@{host_ip}"
        description = f"""
Valid credentials discovered for {service.upper()} service.

**Host:** {host_ip}
**Service:** {service.upper()}
**Username:** {username}
**Authentication:** Successful

**Impact:**
An attacker with these credentials can:
- Authenticate to the {service.upper()} service
- Access files and resources
- Potentially escalate privileges
- Move laterally to other systems

**Recommendation:**
- Review if this account is necessary
- Ensure strong password policy is enforced
- Implement multi-factor authentication
- Monitor for suspicious access patterns
- Consider rotating credentials regularly
"""
        
        # Determine severity based on context
        severity = self._determine_credential_severity(cred, host)
        
        finding_data = {
            'title': title,
            'description': description.strip(),
            'severity': severity,
            'host_id': host.get('id'),
            'category': 'authentication',
            'tool': 'credential_tester'
        }
        
        try:
            finding = self.fm.add_finding(engagement_id, finding_data)
            return finding
        except Exception as e:
            print(f"Error creating finding: {e}")
            return None
    
    def _determine_credential_severity(self, cred: Dict, host: Dict) -> str:
        """Determine severity based on credential and host context."""
        username = cred.get('username', '').lower()
        password = cred.get('password', '')
        
        # High severity for privileged accounts
        privileged_users = ['root', 'admin', 'administrator', 'sa', 'postgres', 'mysql']
        if username in privileged_users:
            return 'high'
        
        # High severity for weak/default passwords
        weak_passwords = ['password', 'admin', '123456', 'root', 'toor', 'changeme', '']
        if password.lower() in weak_passwords:
            return 'high'
        
        # High severity for short passwords
        if len(password) < 8:
            return 'high'
        
        # Medium severity for standard users
        return 'medium'
