# Menuscript Installation Guide

## Prerequisites
- Kali Linux (or any Debian-based Linux distro)
- Python 3.8 or higher
- Git
- sudo access

## Quick Start (5 minutes)

### 1. Clone the Repository
```bash
cd ~
git clone https://github.com/y0d8/menuscript.git
cd menuscript
```

### 2. Run the Installation Script
```bash
chmod +x install.sh
./install.sh
```

The install script will:
- Check for Python 3
- Create a virtual environment
- Install all dependencies
- Set up the CLI tool
- Initialize the database
- Start the background worker

### 3. Verify Installation
```bash
menuscript --version
menuscript worker status
```

You should see the worker running.

### 4. Create Your First Engagement
```bash
menuscript interactive
```

Follow the prompts to:
1. Create a workspace/engagement
2. Set it as active
3. Start scanning!

---

## Manual Installation (if install.sh doesn't work)

### Step 1: Install System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

### Step 2: Clone and Enter Directory
```bash
cd ~
git clone https://github.com/y0d8/menuscript.git
cd menuscript
```

### Step 3: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 4: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -e .
```

### Step 5: Initialize Database
```bash
# Database is automatically created on first run
menuscript interactive
# Press 'q' to exit after you see the menu
```

### Step 6: Start Background Worker
```bash
menuscript worker start
```

### Step 7: Verify Everything Works
```bash
menuscript worker status
menuscript --help
```

---

## Required Security Tools

Menuscript orchestrates these tools. Install what you need:

### Network Scanning
```bash
sudo apt install -y nmap
```

### Web Scanning
```bash
sudo apt install -y nikto gobuster
```

### SMB Enumeration
```bash
sudo apt install -y enum4linux smbmap smbclient
```

### SQL Injection Testing
```bash
sudo apt install -y sqlmap
```

### OSINT
```bash
sudo apt install -y theharvester
```

### Metasploit (if not already installed)
```bash
sudo apt install -y metasploit-framework
```

**Note**: Most of these come pre-installed on Kali Linux!

---

## Usage Examples

### Interactive Mode (Recommended for beginners)
```bash
menuscript interactive
```
Navigate with arrow keys, select tools, configure scans.

### Dashboard Mode (Live monitoring)
```bash
menuscript dashboard
```
Watch scans in real-time, see results as they complete.

### CLI Mode (Advanced users)
```bash
# Create engagement
menuscript engagement create "Client Pentest"
menuscript engagement use "Client Pentest"

# Run scans
menuscript jobs enqueue nmap 10.0.0.0/24 -a "-sn" -l "Discovery Scan"
menuscript jobs enqueue nmap 10.0.0.1 -a "-sV -p-" -l "Full Scan"

# View results
menuscript jobs list
menuscript hosts list
menuscript findings list

# Generate report
menuscript report generate "Client Pentest Report"
```

---

## Troubleshooting

### Worker won't start
```bash
# Check if another worker is running
ps aux | grep worker_loop

# Kill old workers
pkill -f worker_loop

# Start fresh
menuscript worker start
```

### Permission errors
```bash
# Make sure you're in the virtual environment
source venv/bin/activate

# Reinstall
pip install -e .
```

### Database errors
```bash
# Database file location
ls -la data/menuscript.db

# If corrupt, backup and recreate
mv data/menuscript.db data/menuscript.db.backup
menuscript interactive  # Will create new DB
```

### Import errors
```bash
# Make sure you're in the virtual environment
which python
# Should show: /path/to/menuscript/venv/bin/python

# Reinstall dependencies
pip install -e .
```

---

## Configuration

### Data Directory
All data is stored in: `~/menuscript/data/`
- `menuscript.db` - SQLite database
- `jobs/` - Job logs
- `logs/` - Worker logs
- `reports/` - Generated reports

### Worker Configuration
Worker runs in background and processes job queue.
- Auto-starts on first run
- Restart: `menuscript worker start`
- Status: `menuscript worker status`
- Logs: `tail -f data/logs/worker.log`

---

## Quick Reference

### Common Commands
```bash
# Interactive menu
menuscript interactive

# Live dashboard
menuscript dashboard

# View engagements
menuscript engagement list

# View jobs
menuscript jobs list

# View hosts
menuscript hosts list

# View findings
menuscript findings list

# Generate report
menuscript report generate "Report Name"
```

### Keyboard Shortcuts (Interactive Mode)
- Arrow keys: Navigate
- Enter: Select
- `q`: Quit/Back
- `h`: View hosts
- `s`: View services
- `f`: View findings
- `j`: View jobs
- `c`: View credentials

---

## Getting Help

### Built-in Help
```bash
menuscript --help
menuscript jobs --help
menuscript engagement --help
```

### Tool-Specific Help
When selecting a tool in interactive mode, detailed help and presets are shown.

### Logs
```bash
# Worker log
tail -f data/logs/worker.log

# Job logs
cat data/jobs/<job_id>.log
```

---

## Updating Menuscript

```bash
cd ~/menuscript
git pull origin master
source venv/bin/activate
pip install -e .

# Restart worker to load new code
pkill -f worker_loop
menuscript worker start
```

---

## Uninstall

```bash
cd ~/menuscript
pkill -f worker_loop  # Stop worker
deactivate  # Exit virtual environment
cd ..
rm -rf menuscript  # Remove everything
```

---

## Security Notes

⚠️ **Important**: 
- Always get written authorization before scanning targets
- Use responsibly and legally
- Follow rules of engagement
- Some tools are noisy and will trigger IDS/IPS
- This tool is for authorized penetration testing only

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│          menuscript CLI                     │
│  (Interactive, Dashboard, Direct commands)  │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│          Background Worker                  │
│  (Processes job queue, runs tools)          │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│       Security Tools (nmap, etc.)           │
│  Logs → Parsers → Database → Reports        │
└─────────────────────────────────────────────┘
```

---

## What's Next?

1. **Create an engagement**: `menuscript engagement create "My First Test"`
2. **Run a discovery scan**: Use interactive mode to scan your network
3. **View the dashboard**: `menuscript dashboard` to watch in real-time
4. **Generate a report**: Convert findings to professional reports

Happy hacking! 🎯
