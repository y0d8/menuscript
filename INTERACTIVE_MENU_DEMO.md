# Interactive Menu Demo

## Launch the Menu

```bash
menuscript interactive
```

## Main Menu Screen

```
======================================================================
MENUSCRIPT - Interactive Tool Launcher
======================================================================

Workspace: demo

NETWORK
----------------------------------------------------------------------
   1. enum4linux          - SMB enumeration tool for Windows/Samba systems
   2. nmap                - Nmap network scanner (wrapped for help/presets).

OSINT
----------------------------------------------------------------------
   3. theharvester        - theHarvester OSINT tool for emails/subdomains

WEB
----------------------------------------------------------------------
   4. gobuster            - Gobuster directory/file bruteforcer
   5. nikto               - Nikto web vulnerability scanner
   6. sqlmap              - SQLMap - automatic SQL injection detection and exploitation tool

  0. Exit

Select a tool: _
```

## Tool Configuration Menu (Example: Nmap)

```
======================================================================
Nmap (core)
======================================================================
Nmap network scanner (wrapped for help/presets).

PRESETS:
  1. Discovery             - Ping sweep
     Args: -sn
  2. Fast                  - Fast probes
     Args: -v -PS -F
  3. Full                  - Service+OS, full ports
     Args: -sV -O -p1-65535

COMMON FLAGS:
  -sn                  - Ping scan
  -sV                  - Service detection
  -O                   - OS detection

EXAMPLES:
  menuscript jobs enqueue nmap 10.0.0.0/24 --args "-sn"

----------------------------------------------------------------------

Target (IP, hostname, URL, or CIDR): 10.0.0.0/24

Select preset or enter custom args:
  1. Discovery
  2. Fast
  3. Full
  4. Custom args

Choice [1]: 1
Using preset: Discovery

Job label (optional): network-scan

======================================================================
CONFIRM JOB
======================================================================
Tool:   nmap
Target: 10.0.0.0/24
Args:   -sn
Label:  network-scan

Launch this job? [Y/n]: y

✓ Job enqueued successfully!
Job ID: 7
Tool: nmap
Target: 10.0.0.0/24
Args: -sn

Tip: Check job status with: menuscript jobs list
      View job output with: menuscript jobs show <id>

Launch another job? [Y/n]: _
```

## Available Tools & Presets

### Network Tools

**Nmap**
- Discovery: Ping sweep (-sn)
- Fast: Fast probes (-v -PS -F)
- Full: Service+OS, full ports (-sV -O -p1-65535)

**enum4linux**
- Full Enum: All enumeration (users, shares, groups, etc.)
- Shares Only: Enumerate shares only
- Users & Shares: Enumerate users and shares

### Web Tools

**Nikto**
- Quick Scan: Basic vulnerability scan
- SSL Scan: HTTPS vulnerability scan
- Full Scan: Comprehensive scan (all tests)

**Gobuster**
- Dir Quick: Common wordlist quick
- Dir Deep: Large wordlist deep scan

**SQLMap**
- Quick Test: Quick SQL injection test (safe)
- Deep Test: Thorough SQL injection test
- Forms Test: Test forms and crawl 2 levels
- Enumerate DBs: Detect SQLi and enumerate databases

### OSINT Tools

**theHarvester**
- Google Search: Search Google for emails/subdomains
- All Sources: Search all available sources
- Quick Scan: Quick scan (Google + Bing)

## Features

✓ **Tool Categorization** - Tools organized by category (Network, Web, OSINT)
✓ **Workspace Display** - Shows current workspace at top
✓ **Preset Selection** - Easy selection from pre-configured presets
✓ **Custom Arguments** - Option to enter custom args for advanced users
✓ **Job Confirmation** - Review job before launching
✓ **Batch Operations** - Launch multiple jobs in sequence
✓ **Color-Coded** - Categories and status messages use colors
✓ **Help Integration** - Shows examples and common flags for each tool
