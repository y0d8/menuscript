#!/usr/bin/env python3
"""
menuscript.storage.hosts - Host and service management
"""
from typing import List, Dict, Any, Optional
from .database import get_db


class HostManager:
    def __init__(self):
        self.db = get_db()
    
    def add_or_update_host(self, workspace_id: int, host_data: Dict[str, Any]) -> int:
        """
        Add or update a host in the database.
        
        Args:
            workspace_id: Workspace ID
            host_data: Host data from parser (ip, hostname, status, os)
        
        Returns:
            host_id
        """
        ip = host_data.get('ip')
        if not ip:
            raise ValueError("Host must have an IP address")
        
        # Check if host already exists
        existing = self.db.execute_one(
            "SELECT id FROM hosts WHERE workspace_id = ? AND ip_address = ?",
            (workspace_id, ip)
        )
        
        if existing:
            # Update existing host
            host_id = existing['id']
            update_data = {
                'hostname': host_data.get('hostname'),
                'os_name': host_data.get('os'),
                'status': host_data.get('status', 'up')
            }
            
            updates = ', '.join([f"{k} = ?" for k in update_data.keys()])
            values = list(update_data.values()) + [host_id]
            
            self.db.execute(f"UPDATE hosts SET {updates} WHERE id = ?", tuple(values))
            
            return host_id
        else:
            # Insert new host
            host_id = self.db.insert('hosts', {
                'workspace_id': workspace_id,
                'ip_address': ip,
                'hostname': host_data.get('hostname'),
                'os_name': host_data.get('os'),
                'status': host_data.get('status', 'up')
            })
            
            return host_id
    
    def add_service(self, host_id: int, service_data: Dict[str, Any]) -> int:
        """
        Add or update a service for a host.
        
        Args:
            host_id: Host ID
            service_data: Service data (port, protocol, state, service, version)
        
        Returns:
            service_id
        """
        port = service_data.get('port')
        protocol = service_data.get('protocol', 'tcp')
        
        if not port:
            raise ValueError("Service must have a port")
        
        # Check if service already exists
        existing = self.db.execute_one(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol)
        )
        
        if existing:
            # Update existing service
            service_id = existing['id']
            update_data = {
                'state': service_data.get('state', 'open'),
                'service_name': service_data.get('service'),
                'service_version': service_data.get('version')
            }
            
            updates = ', '.join([f"{k} = ?" for k in update_data.keys()])
            values = list(update_data.values()) + [service_id]
            
            self.db.execute(f"UPDATE services SET {updates} WHERE id = ?", tuple(values))
            
            return service_id
        else:
            # Insert new service
            service_id = self.db.insert('services', {
                'host_id': host_id,
                'port': port,
                'protocol': protocol,
                'state': service_data.get('state', 'open'),
                'service_name': service_data.get('service'),
                'service_version': service_data.get('version')
            })
            
            return service_id
    
    def import_nmap_results(self, workspace_id: int, parsed_data: Dict[str, Any]) -> Dict[str, int]:
        """
        Import parsed nmap results into the database.

        Args:
            workspace_id: Workspace ID
            parsed_data: Output from nmap_parser.parse_nmap_text()

        Returns:
            {'hosts_added': N, 'services_added': M} - N is count of live hosts only (status='up')
        """
        hosts_added = 0
        services_added = 0
        
        for host_data in parsed_data.get('hosts', []):
            # Add/update host
            host_id = self.add_or_update_host(workspace_id, host_data)

            # Only count live hosts
            if host_data.get('status') == 'up':
                hosts_added += 1

            # Add services
            for service_data in host_data.get('services', []):
                self.add_service(host_id, service_data)
                services_added += 1
        
        return {
            'hosts_added': hosts_added,
            'services_added': services_added
        }
    
    def list_hosts(self, workspace_id: int) -> List[Dict[str, Any]]:
        """List all hosts in workspace."""
        return self.db.execute(
            "SELECT * FROM hosts WHERE workspace_id = ? ORDER BY ip_address",
            (workspace_id,)
        )
    
    def get_host_services(self, host_id: int) -> List[Dict[str, Any]]:
        """Get all services for a host."""
        return self.db.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port",
            (host_id,)
        )
    
    def get_host_by_ip(self, workspace_id: int, ip: str) -> Optional[Dict[str, Any]]:
        """Get host by IP address."""
        return self.db.execute_one(
            "SELECT * FROM hosts WHERE workspace_id = ? AND ip_address = ?",
            (workspace_id, ip)
        )
