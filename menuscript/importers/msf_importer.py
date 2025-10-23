#!/usr/bin/env python3
"""
menuscript.importers.msf_importer - Import data from Metasploit Framework exports
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional
import click


class MSFImporter:
    """Import Metasploit Framework XML export data into Menuscript."""

    def __init__(self, engagement_id: int):
        """Initialize importer with engagement ID."""
        self.engagement_id = engagement_id
        from menuscript.storage.hosts import HostManager
        from menuscript.storage.credentials import CredentialsManager
        from menuscript.storage.findings import FindingsManager

        self.hm = HostManager()
        self.cm = CredentialsManager()
        self.fm = FindingsManager()

        self.stats = {
            'hosts': 0,
            'services': 0,
            'credentials': 0,
            'vulnerabilities': 0,
            'skipped': 0
        }

    def import_xml(self, xml_file: str, verbose: bool = False) -> Dict:
        """
        Import Metasploit XML export file.

        Args:
            xml_file: Path to MSF XML export file
            verbose: Print detailed progress

        Returns:
            Dictionary with import statistics
        """
        if verbose:
            click.echo(f"Parsing XML file: {xml_file}")

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML file: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {xml_file}")

        if verbose:
            click.echo("XML parsed successfully")

        # Import hosts first
        hosts = root.findall('.//host')
        if verbose:
            click.echo(f"\nFound {len(hosts)} hosts")

        host_mapping = {}  # MSF address -> Menuscript host_id

        for host_elem in hosts:
            host_id = self._import_host(host_elem, verbose)
            if host_id:
                address = host_elem.find('address').text if host_elem.find('address') is not None else None
                if address:
                    host_mapping[address] = host_id

        # Import services
        if verbose:
            click.echo(f"\nImporting services...")

        for host_elem in hosts:
            address = host_elem.find('address').text if host_elem.find('address') is not None else None
            if address and address in host_mapping:
                services = host_elem.findall('.//service')
                for svc_elem in services:
                    self._import_service(svc_elem, host_mapping[address], verbose)

        # Import credentials
        creds = root.findall('.//cred')
        if verbose and creds:
            click.echo(f"\nFound {len(creds)} credentials")

        for cred_elem in creds:
            self._import_credential(cred_elem, host_mapping, verbose)

        # Import vulnerabilities/notes as findings
        vulns = root.findall('.//vuln')
        notes = root.findall('.//note')

        if verbose and (vulns or notes):
            click.echo(f"\nFound {len(vulns)} vulnerabilities and {len(notes)} notes")

        for vuln_elem in vulns:
            self._import_vulnerability(vuln_elem, host_mapping, verbose)

        return self.stats

    def _import_host(self, host_elem: ET.Element, verbose: bool = False) -> Optional[int]:
        """Import a single host."""
        address = host_elem.find('address')
        if address is None or not address.text:
            self.stats['skipped'] += 1
            return None

        ip_address = address.text
        mac = host_elem.find('mac')
        mac_address = mac.text if mac is not None and mac.text else None

        # Get OS info
        os_name_elem = host_elem.find('os-name')
        os_flavor_elem = host_elem.find('os-flavor')
        os_sp_elem = host_elem.find('os-sp')

        os_parts = []
        if os_name_elem is not None and os_name_elem.text:
            os_parts.append(os_name_elem.text)
        if os_flavor_elem is not None and os_flavor_elem.text:
            os_parts.append(os_flavor_elem.text)
        if os_sp_elem is not None and os_sp_elem.text:
            os_parts.append(os_sp_elem.text)

        os_name = ' '.join(os_parts) if os_parts else None

        # Get hostname
        name_elem = host_elem.find('name')
        hostname = name_elem.text if name_elem is not None and name_elem.text else None

        # Check host state
        state_elem = host_elem.find('state')
        state = state_elem.text if state_elem is not None else 'up'

        if verbose:
            click.echo(f"  Importing host: {ip_address} ({hostname or 'no hostname'})")

        # Add or update host
        host_data = {
            'ip': ip_address,
            'hostname': hostname,
            'os': os_name,
            'status': state
        }

        host_id = self.hm.add_or_update_host(self.engagement_id, host_data)

        self.stats['hosts'] += 1
        return host_id

    def _import_service(self, svc_elem: ET.Element, host_id: int, verbose: bool = False) -> Optional[int]:
        """Import a single service."""
        port_elem = svc_elem.find('port')
        if port_elem is None or not port_elem.text:
            return None

        try:
            port = int(port_elem.text)
        except ValueError:
            return None

        proto_elem = svc_elem.find('proto')
        protocol = proto_elem.text if proto_elem is not None and proto_elem.text else 'tcp'

        name_elem = svc_elem.find('name')
        service_name = name_elem.text if name_elem is not None and name_elem.text else 'unknown'

        # Get service info/version
        info_elem = svc_elem.find('info')
        service_version = info_elem.text if info_elem is not None and info_elem.text else None

        state_elem = svc_elem.find('state')
        state = state_elem.text if state_elem is not None else 'open'

        if verbose:
            click.echo(f"    Service: {port}/{protocol} ({service_name})")

        # Add service
        service_data = {
            'port': port,
            'protocol': protocol,
            'state': state,
            'service': service_name,
            'version': service_version
        }

        self.hm.add_service(host_id, service_data)

        self.stats['services'] += 1
        return port

    def _import_credential(self, cred_elem: ET.Element, host_mapping: Dict, verbose: bool = False):
        """Import a single credential."""
        # Get credential details
        user_elem = cred_elem.find('.//username')
        pass_elem = cred_elem.find('.//password')
        type_elem = cred_elem.find('.//type')

        username = user_elem.text if user_elem is not None and user_elem.text else None
        password = pass_elem.text if pass_elem is not None and pass_elem.text else None
        cred_type = type_elem.text if type_elem is not None and type_elem.text else 'password'

        if not username:
            return

        # Try to get associated service info
        service_elem = cred_elem.find('.//service')
        host_elem = cred_elem.find('.//host')

        ip_address = None
        service_name = None
        port = None

        if host_elem is not None:
            address_elem = host_elem.find('address')
            if address_elem is not None:
                ip_address = address_elem.text

        if service_elem is not None:
            name_elem = service_elem.find('name')
            port_elem = service_elem.find('port')

            if name_elem is not None:
                service_name = name_elem.text
            if port_elem is not None:
                try:
                    port = int(port_elem.text)
                except ValueError:
                    pass

        # Determine status - if we have a password, assume it's valid
        status = 'valid' if password else 'discovered'

        # Get host_id from IP
        host_id = None
        if ip_address:
            host_id = host_mapping.get(ip_address)

        if not host_id:
            # Skip credentials without a valid host
            return

        if verbose:
            cred_str = f"{username}"
            if password:
                cred_str += f":{password}"
            if ip_address:
                cred_str += f" @ {ip_address}"
            click.echo(f"  Credential: {cred_str}")

        # Add credential
        self.cm.add_credential(
            engagement_id=self.engagement_id,
            host_id=host_id,
            username=username,
            password=password,
            service=service_name,
            port=port,
            status=status,
            tool='msf_import'
        )

        self.stats['credentials'] += 1

    def _import_vulnerability(self, vuln_elem: ET.Element, host_mapping: Dict, verbose: bool = False):
        """Import a vulnerability as a finding."""
        name_elem = vuln_elem.find('name')
        if name_elem is None or not name_elem.text:
            return

        title = name_elem.text

        # Get host
        host_elem = vuln_elem.find('host')
        ip_address = None
        host_id = None

        if host_elem is not None:
            address_elem = host_elem.find('address')
            if address_elem is not None and address_elem.text:
                ip_address = address_elem.text
                host_id = host_mapping.get(ip_address)

        if not host_id:
            return

        # Get port
        port_elem = vuln_elem.find('port')
        port = None
        if port_elem is not None and port_elem.text:
            try:
                port = int(port_elem.text)
            except ValueError:
                pass

        # Get refs
        refs_elem = vuln_elem.find('refs')
        refs = []
        if refs_elem is not None:
            for ref_elem in refs_elem.findall('ref'):
                if ref_elem.text:
                    refs.append(ref_elem.text)

        refs_text = '\n'.join(refs) if refs else None

        # Get info/description
        info_elem = vuln_elem.find('info')
        description = info_elem.text if info_elem is not None and info_elem.text else f"Vulnerability: {title}"

        # Try to determine severity from name/refs
        severity = self._determine_severity(title, refs_text)

        if verbose:
            click.echo(f"  Vulnerability: {title} on {ip_address}")

        # Add as finding
        self.fm.add_finding(
            engagement_id=self.engagement_id,
            title=title,
            finding_type='vulnerability',
            severity=severity,
            description=description,
            host_id=host_id,
            port=port,
            tool='msf_import',
            refs=refs_text
        )

        self.stats['vulnerabilities'] += 1

    def _determine_severity(self, title: str, refs: Optional[str]) -> str:
        """Try to determine severity from vulnerability title and references."""
        title_lower = title.lower()
        refs_lower = refs.lower() if refs else ''

        # Critical indicators
        critical_keywords = ['rce', 'remote code execution', 'unauthenticated', 'critical']
        for keyword in critical_keywords:
            if keyword in title_lower:
                return 'critical'

        # High indicators
        high_keywords = ['exploit', 'overflow', 'injection', 'authentication bypass']
        for keyword in high_keywords:
            if keyword in title_lower:
                return 'high'

        # Check CVE scores (if available in refs)
        if 'cvss' in refs_lower:
            # Could parse CVSS scores here
            pass

        # Default to medium for vulnerabilities
        return 'medium'
