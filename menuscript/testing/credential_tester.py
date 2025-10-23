#!/usr/bin/env python3
"""
menuscript.testing.credential_tester - Test credentials against services
"""
import socket
import subprocess
from typing import Dict, List, Optional, Tuple
import click


class CredentialTester:
    """Test credentials against various services."""

    def __init__(self, timeout: int = 5):
        """
        Initialize credential tester.

        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        self.results = []

    def test_credential(
        self,
        host: str,
        port: int,
        service: str,
        username: str,
        password: str,
        protocol: str = 'tcp'
    ) -> Dict:
        """
        Test a single credential against a service.

        Args:
            host: Target host IP/hostname
            port: Target port
            service: Service name (ssh, smb, mysql, etc.)
            username: Username to test
            password: Password to test
            protocol: Protocol (tcp/udp)

        Returns:
            Dict with test results
        """
        result = {
            'host': host,
            'port': port,
            'service': service,
            'username': username,
            'status': 'unknown',
            'message': '',
            'tested_at': None
        }

        # Check if port is open first
        if not self._check_port(host, port, protocol):
            result['status'] = 'port_closed'
            result['message'] = f"Port {port}/{protocol} is not open"
            return result

        # Route to appropriate tester
        service_lower = service.lower()

        if service_lower in ['ssh', 'ssh-2']:
            return self._test_ssh(host, port, username, password)
        elif service_lower in ['smb', 'microsoft-ds', 'netbios-ssn']:
            return self._test_smb(host, username, password)
        elif service_lower in ['mysql', 'mariadb']:
            return self._test_mysql(host, port, username, password)
        elif service_lower in ['postgresql', 'postgres']:
            return self._test_postgresql(host, port, username, password)
        elif service_lower in ['rdp', 'ms-wbt-server', 'terminal-server']:
            return self._test_rdp(host, port, username, password)
        elif service_lower in ['ftp', 'ftps']:
            return self._test_ftp(host, port, username, password)
        elif service_lower in ['telnet']:
            return self._test_telnet(host, port, username, password)
        else:
            result['status'] = 'unsupported'
            result['message'] = f"Service '{service}' testing not yet supported"
            return result

    def _check_port(self, host: str, port: int, protocol: str = 'tcp') -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _test_ssh(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test SSH credentials using sshpass."""
        result = {
            'host': host,
            'port': port,
            'service': 'ssh',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            # Use sshpass with ssh
            cmd = [
                'sshpass', '-p', password,
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', f'ConnectTimeout={self.timeout}',
                '-p', str(port),
                f'{username}@{host}',
                'echo "SUCCESS"'
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 5,
                text=True
            )

            if 'SUCCESS' in proc.stdout:
                result['status'] = 'valid'
                result['message'] = 'Authentication successful'
            elif 'Permission denied' in proc.stderr:
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {proc.stderr[:100]}'

        except FileNotFoundError:
            result['status'] = 'error'
            result['message'] = 'sshpass not installed (apt install sshpass)'
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['message'] = 'Connection timeout'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_smb(self, host: str, username: str, password: str) -> Dict:
        """Test SMB credentials using smbclient."""
        result = {
            'host': host,
            'port': 445,
            'service': 'smb',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            # Use smbclient to test
            cmd = [
                'smbclient',
                f'//{host}/IPC$',
                '-U', f'{username}%{password}',
                '-c', 'quit'
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 5,
                text=True
            )

            if proc.returncode == 0:
                result['status'] = 'valid'
                result['message'] = 'Authentication successful'
            elif 'NT_STATUS_LOGON_FAILURE' in proc.stderr:
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            elif 'NT_STATUS_ACCOUNT_DISABLED' in proc.stderr:
                result['status'] = 'account_disabled'
                result['message'] = 'Account is disabled'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {proc.stderr[:100]}'

        except FileNotFoundError:
            result['status'] = 'error'
            result['message'] = 'smbclient not installed (apt install smbclient)'
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['message'] = 'Connection timeout'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_mysql(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test MySQL credentials."""
        result = {
            'host': host,
            'port': port,
            'service': 'mysql',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            cmd = [
                'mysql',
                '-h', host,
                '-P', str(port),
                '-u', username,
                f'-p{password}',
                '-e', 'SELECT 1;'
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 5,
                text=True
            )

            if proc.returncode == 0:
                result['status'] = 'valid'
                result['message'] = 'Authentication successful'
            elif 'Access denied' in proc.stderr:
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {proc.stderr[:100]}'

        except FileNotFoundError:
            result['status'] = 'error'
            result['message'] = 'mysql client not installed (apt install mysql-client)'
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['message'] = 'Connection timeout'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_postgresql(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test PostgreSQL credentials."""
        result = {
            'host': host,
            'port': port,
            'service': 'postgresql',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            # Set PGPASSWORD environment variable
            import os
            env = os.environ.copy()
            env['PGPASSWORD'] = password

            cmd = [
                'psql',
                '-h', host,
                '-p', str(port),
                '-U', username,
                '-d', 'postgres',
                '-c', 'SELECT 1;'
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 5,
                text=True,
                env=env
            )

            if proc.returncode == 0:
                result['status'] = 'valid'
                result['message'] = 'Authentication successful'
            elif 'authentication failed' in proc.stderr.lower():
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {proc.stderr[:100]}'

        except FileNotFoundError:
            result['status'] = 'error'
            result['message'] = 'psql not installed (apt install postgresql-client)'
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['message'] = 'Connection timeout'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_rdp(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test RDP credentials using xfreerdp."""
        result = {
            'host': host,
            'port': port,
            'service': 'rdp',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            cmd = [
                'xfreerdp',
                f'/v:{host}:{port}',
                f'/u:{username}',
                f'/p:{password}',
                '/cert:ignore',
                '+auth-only',
                '/timeout:5000'
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 5,
                text=True
            )

            # xfreerdp returns 0 on successful auth
            if proc.returncode == 0:
                result['status'] = 'valid'
                result['message'] = 'Authentication successful'
            elif 'Authentication failure' in proc.stderr or 'ERRCONNECT_LOGON_FAILURE' in proc.stderr:
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {proc.stderr[:100]}'

        except FileNotFoundError:
            result['status'] = 'error'
            result['message'] = 'xfreerdp not installed (apt install freerdp2-x11)'
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['message'] = 'Connection timeout'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_ftp(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test FTP credentials."""
        result = {
            'host': host,
            'port': port,
            'service': 'ftp',
            'username': username,
            'status': 'unknown',
            'message': ''
        }

        try:
            from ftplib import FTP

            ftp = FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()

            result['status'] = 'valid'
            result['message'] = 'Authentication successful'

        except Exception as e:
            error_str = str(e).lower()
            if '530' in error_str or 'login' in error_str:
                result['status'] = 'invalid'
                result['message'] = 'Invalid credentials'
            elif 'timeout' in error_str:
                result['status'] = 'timeout'
                result['message'] = 'Connection timeout'
            else:
                result['status'] = 'error'
                result['message'] = f'Error: {str(e)[:100]}'

        return result

    def _test_telnet(self, host: str, port: int, username: str, password: str) -> Dict:
        """Test Telnet credentials."""
        result = {
            'host': host,
            'port': port,
            'service': 'telnet',
            'username': username,
            'status': 'unsupported',
            'message': 'Telnet testing requires interactive session (not yet implemented)'
        }
        return result

    def batch_test(self, credentials: List[Dict], services: List[Dict], verbose: bool = False) -> List[Dict]:
        """
        Batch test credentials against multiple services.

        Args:
            credentials: List of credential dicts with username/password
            services: List of service dicts with host/port/service
            verbose: Print progress

        Returns:
            List of test results
        """
        results = []
        total = len(credentials) * len(services)
        current = 0

        for cred in credentials:
            username = cred.get('username')
            password = cred.get('password')

            if not username or not password:
                continue

            for svc in services:
                current += 1
                host = svc.get('host') or svc.get('ip_address')
                port = svc.get('port')
                service = svc.get('service') or svc.get('service_name')

                if not all([host, port, service]):
                    continue

                if verbose:
                    click.echo(f"[{current}/{total}] Testing {username} @ {host}:{port} ({service})")

                result = self.test_credential(host, port, service, username, password)
                results.append(result)

                if verbose and result['status'] == 'valid':
                    click.echo(click.style(f"  ✓ Valid: {username}:{password} @ {host}:{port}", fg='green'))

        return results
