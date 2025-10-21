#!/usr/bin/env python3
"""
menuscript.engine.result_handler - Auto-parse job results
"""
import os
from typing import Optional, Dict, Any


def handle_job_result(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process completed job and parse results into database.
    
    Args:
        job: Job dict from background system
        
    Returns:
        Parse results or None if not applicable
    """
    tool = job.get('tool', '').lower()
    log_path = job.get('log')
    status = job.get('status')
    
    # Only process successful jobs
    if status != 'done' or not log_path or not os.path.exists(log_path):
        return None
    
    # Get current workspace
    try:
        from menuscript.storage.workspaces import WorkspaceManager
        wm = WorkspaceManager()
        workspace = wm.get_current()
        
        if not workspace:
            return None
        
        workspace_id = workspace['id']
    except Exception:
        return None
    
    # Route to appropriate parser
    if tool == 'nmap':
        return parse_nmap_job(workspace_id, log_path)
    
    # Add more parsers here as we build them
    # elif tool == 'nikto':
    #     return parse_nikto_job(workspace_id, log_path)
    
    return None


def parse_nmap_job(workspace_id: int, log_path: str) -> Dict[str, Any]:
    """Parse nmap job results."""
    try:
        from menuscript.parsers.nmap_parser import parse_nmap_log
        from menuscript.storage.hosts import HostManager
        
        # Parse the log file
        parsed = parse_nmap_log(log_path)
        
        if 'error' in parsed:
            return {'error': parsed['error']}
        
        # Import into database
        hm = HostManager()
        result = hm.import_nmap_results(workspace_id, parsed)
        
        return {
            'tool': 'nmap',
            'hosts_added': result['hosts_added'],
            'services_added': result['services_added']
        }
    except Exception as e:
        return {'error': str(e)}
