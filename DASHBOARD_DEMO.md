# Live Dashboard Demo

## Launch Dashboard

```bash
# Basic dashboard (refreshes every 2 seconds)
menuscript dashboard

# Follow a specific job's output
menuscript dashboard --follow 24

# Custom refresh interval (5 seconds)
menuscript dashboard --refresh 5
```

## Dashboard Layout

```
======================================================================
                    MENUSCRIPT LIVE DASHBOARD
                        Workspace: demo
                    2025-10-21 16:45:32
======================================================================

WORKSPACE STATS
----------------------------------------------------------------------
Hosts:    1 | Services:    3 | Findings:    7


ACTIVE JOBS
----------------------------------------------------------------------
  [ 25] nmap       10.0.0.0/24                    running    2m15s
  [ 26] nikto      http://10.0.0.82               running    0m45s
  [ 27] gobuster   http://10.0.0.82               pending


RECENT COMPLETIONS
----------------------------------------------------------------------
  [ 24] nmap       10.0.0.82                      ✓ done
  [ 23] enum4linu  10.0.0.82                      ✓ done
  [ 22] theharves  vulnweb.com                    ✓ done
  [ 21] nikto      http://10.0.0.1                ✗ fail
  [ 20] sqlmap     http://10.0.0.82               ✓ done


RECENT FINDINGS
----------------------------------------------------------------------
  [  7] INFO SMB Share: print$ (Disk)
  [  6] LOW  SMB Share: IPC$ (IPC)
  [  5] MED  Possible SQLi in 'id' parameter
  [  4] MED  Config file accessible
  [  3] MED  Admin section found: /admin/


----------------------------------------------------------------------
            Press Ctrl+C to exit | Refresh: 2s
```

## Dashboard with Live Log

When following a specific job (`--follow 24`):

```
======================================================================
                    MENUSCRIPT LIVE DASHBOARD
                        Workspace: demo
                    2025-10-21 16:45:32
======================================================================

WORKSPACE STATS
----------------------------------------------------------------------
Hosts:    5 | Services:   28 | Findings:   15


ACTIVE JOBS
----------------------------------------------------------------------
  [ 24] nmap       10.0.0.0/24                    running    5m30s


RECENT COMPLETIONS
----------------------------------------------------------------------
  [ 23] nikto      http://10.0.0.82               ✓ done
  [ 22] gobuster   http://10.0.0.82               ✓ done


RECENT FINDINGS
----------------------------------------------------------------------
  [ 15] HIGH Missing X-Frame-Options header
  [ 14] MED  Admin section found: /admin/


LIVE LOG - Job #24 (nmap)
----------------------------------------------------------------------
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 09:40 PDT
Nmap scan report for 10.0.0.1
Host is up (0.0012s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http

Nmap scan report for 10.0.0.50
Host is up (0.0008s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.0.82
Host is up (0.00082s latency).
Not shown: 965 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
...


----------------------------------------------------------------------
            Press Ctrl+C to exit | Refresh: 2s
```

## Features

### Real-Time Updates
- **Auto-refresh**: Dashboard updates every 2 seconds (configurable)
- **Live job status**: See running jobs with elapsed time
- **Progress tracking**: Watch jobs move from pending → running → done
- **Instant findings**: New vulnerabilities appear immediately after parsing

### Panels

#### 1. Workspace Stats
- Total hosts discovered
- Total services found
- Total findings/vulnerabilities
- Updates live as scans complete

#### 2. Active Jobs
- Shows up to 5 running/pending jobs
- Displays:
  - Job ID
  - Tool name
  - Target
  - Status (color-coded)
  - Elapsed time (for running jobs)
- Color coding:
  - Yellow = running
  - White = pending

#### 3. Recent Completions
- Last 5 completed jobs
- Color coding:
  - ✓ Green = success
  - ✗ Red = failed

#### 4. Recent Findings
- Last 5 vulnerabilities discovered
- Severity color-coded:
  - CRIT/HIGH = Red
  - MED = Yellow
  - LOW = Blue
  - INFO = White

#### 5. Live Log (optional)
- Follow specific job output in real-time
- Automatically scrolls to show latest output
- Great for watching long-running scans (nmap, gobuster, etc.)

### Usage Scenarios

#### Scenario 1: Monitor Multiple Scans
```bash
# Launch several scans
menuscript jobs enqueue nmap 10.0.0.0/24 --args "-sV"
menuscript jobs enqueue nikto http://10.0.0.82
menuscript jobs enqueue gobuster http://10.0.0.82

# Watch them all in the dashboard
menuscript dashboard
```

#### Scenario 2: Debug a Specific Scan
```bash
# Launch a scan
menuscript jobs enqueue nmap 10.0.0.0/16 --args "-sV -O"

# Get the job ID (e.g., 42)
# Follow its output live
menuscript dashboard --follow 42
```

#### Scenario 3: Slower Network Connection
```bash
# Reduce refresh frequency to save bandwidth
menuscript dashboard --refresh 5
```

### Keyboard Controls
- **Ctrl+C**: Exit dashboard cleanly
- Dashboard auto-refreshes, no manual interaction needed

### Tips

💡 **Run in tmux/screen**: Keep dashboard running in one pane while working in another
💡 **Multiple terminals**: Dashboard in one, interactive menu in another
💡 **Background worker**: Make sure worker is running for real-time parsing
💡 **Watch findings**: Leave dashboard open to catch critical findings immediately

## Example Workflow

1. **Terminal 1**: Start background worker
   ```bash
   menuscript worker start --fg
   ```

2. **Terminal 2**: Launch dashboard
   ```bash
   menuscript dashboard
   ```

3. **Terminal 3**: Launch scans via interactive menu
   ```bash
   menuscript interactive
   ```

Now you can launch scans from Terminal 3, and watch them execute in real-time on Terminal 2!
