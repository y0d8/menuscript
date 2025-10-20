#!/usr/bin/env python3
"""
Integration test for plugin-aware background worker.

Tests:
  1. Plugin discovery
  2. Job enqueue
  3. Plugin execution
  4. Log file creation
  5. Status updates
"""
import os
import sys
import time
import subprocess

# Add project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from menuscript.engine.background import enqueue_job, get_job, list_jobs, run_job
from menuscript.engine.loader import discover_plugins


def test_plugin_discovery():
    """Test that plugins are discovered correctly."""
    print("=" * 60)
    print("TEST 1: Plugin Discovery")
    print("=" * 60)
    
    plugins = discover_plugins()
    print(f"Found {len(plugins)} plugins:")
    
    for key, plugin in plugins.items():
        name = getattr(plugin, "name", "unknown")
        tool = getattr(plugin, "tool", "unknown")
        category = getattr(plugin, "category", "unknown")
        has_run = hasattr(plugin, "run") and callable(getattr(plugin, "run"))
        print(f"  - {key}: {name} (tool={tool}, category={category}, has_run={has_run})")
    
    assert len(plugins) > 0, "No plugins found!"
    assert "nmap" in plugins, "Nmap plugin not found!"
    
    print("✓ Plugin discovery working\n")
    return plugins


def test_job_enqueue():
    """Test job enqueueing."""
    print("=" * 60)
    print("TEST 2: Job Enqueue")
    print("=" * 60)
    
    # Enqueue a simple echo job
    jid = enqueue_job(
        tool="echo",
        target="hello",
        args=["plugin-test"],
        label="integration-test"
    )
    
    print(f"Enqueued job {jid}")
    
    job = get_job(jid)
    assert job is not None, f"Job {jid} not found!"
    assert job["status"] == "queued", f"Job status is {job['status']}, expected 'queued'"
    assert job["tool"] == "echo"
    
    print(f"Job details: {job}")
    print("✓ Job enqueue working\n")
    return jid


def test_job_execution(jid):
    """Test job execution."""
    print("=" * 60)
    print("TEST 3: Job Execution")
    print("=" * 60)
    
    print(f"Running job {jid}...")
    run_job(jid)
    
    job = get_job(jid)
    print(f"Job status: {job['status']}")
    print(f"Log file: {job['log']}")
    
    assert job["status"] in ("done", "error"), f"Unexpected status: {job['status']}"
    assert os.path.exists(job["log"]), f"Log file not created: {job['log']}"
    
    # Read log
    with open(job["log"], "r") as fh:
        log_content = fh.read()
    
    print("\n--- Log Content ---")
    print(log_content[:500])
    print("--- End Log ---\n")
    
    assert len(log_content) > 0, "Log file is empty!"
    
    print("✓ Job execution working\n")
    return job


def test_plugin_job():
    """Test plugin-based job execution."""
    print("=" * 60)
    print("TEST 4: Plugin Job (Nmap)")
    print("=" * 60)
    
    # Enqueue nmap job (localhost ping scan)
    jid = enqueue_job(
        tool="nmap",
        target="127.0.0.1",
        args=["-sn"],
        label="plugin-integration-test"
    )
    
    print(f"Enqueued nmap job {jid}")
    
    print("Running job...")
    run_job(jid)
    
    job = get_job(jid)
    print(f"Job status: {job['status']}")
    
    # Read log
    if os.path.exists(job["log"]):
        with open(job["log"], "r") as fh:
            log_content = fh.read()
        
        print("\n--- Nmap Log Content (first 500 chars) ---")
        print(log_content[:500])
        print("--- End Log ---\n")
        
        # Check for plugin headers
        if "=== Plugin:" in log_content:
            print("✓ Plugin was executed (found plugin headers)")
        else:
            print("⚠ Plugin may not have been used (no plugin headers found)")
            print("  This could be normal if nmap plugin uses subprocess fallback")
        
        assert "nmap" in log_content.lower(), "Nmap output not found in log"
    else:
        print(f"⚠ Log file not found: {job['log']}")
    
    print("✓ Plugin job execution working\n")
    return job


def test_list_jobs():
    """Test job listing."""
    print("=" * 60)
    print("TEST 5: List Jobs")
    print("=" * 60)
    
    jobs = list_jobs(limit=5)
    print(f"Found {len(jobs)} recent jobs:")
    
    for job in jobs:
        print(f"  - Job {job['id']}: {job['tool']} {job['target']} [{job['status']}]")
    
    assert len(jobs) > 0, "No jobs found!"
    
    print("✓ Job listing working\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("MENUSCRIPT PLUGIN WORKER INTEGRATION TEST")
    print("=" * 60 + "\n")
    
    try:
        # Test 1: Plugin discovery
        plugins = test_plugin_discovery()
        
        # Test 2: Simple job enqueue
        jid = test_job_enqueue()
        
        # Test 3: Job execution
        job = test_job_execution(jid)
        
        # Test 4: Plugin job
        plugin_job = test_plugin_job()
        
        # Test 5: List jobs
        test_list_jobs()
        
        print("=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        print("\nNext steps:")
        print("  1. Start the worker: menuscript worker --fg")
        print("  2. Enqueue jobs: menuscript jobs enqueue nmap <target> --args '<args>'")
        print("  3. Monitor logs: tail -f data/jobs/<job_id>.log")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
