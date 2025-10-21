# Interactive Menu V2 - Job & Results Viewing

## New Features

The interactive menu now includes comprehensive viewing capabilities:
- ✅ View job queue and status
- ✅ View individual job details with logs
- ✅ View scan results (hosts, services, findings, OSINT, web paths)
- ✅ Navigate between launch and view modes

## Main Menu (Enhanced)

```
======================================================================
MENUSCRIPT - Interactive Menu
======================================================================

Workspace: demo
Data: 1 hosts | 3 services | 7 findings

LAUNCH TOOLS
----------------------------------------------------------------------
  NETWORK
     1. enum4linux
     2. nmap
  OSINT
     3. theharvester
  WEB
     4. gobuster
     5. nikto
     6. sqlmap

VIEW DATA
----------------------------------------------------------------------
   7. View Jobs
   8. View Scan Results

   0. Exit

Select an option: _
```

## Job Queue Viewer

Select option "View Jobs" to see all jobs:

```
======================================================================
JOB QUEUE
======================================================================

ID    Status     Tool         Target                    Created
----------------------------------------------------------------------
5     done       nikto        http://10.0.0.82          2025-01-21 15:30:22
4     done       nmap         10.0.0.0/24               2025-01-21 15:25:10
3     running    gobuster     http://example.com        2025-01-21 15:28:45
2     failed     theharvester example.com               2025-01-21 15:20:15
1     done       enum4linux   10.0.0.82                 2025-01-21 15:15:00

Enter job ID to view details, or 0 to return
Job ID: _
```

## Job Detail Viewer

Enter a job ID to see full details and logs:

```
======================================================================
JOB #5 DETAILS
======================================================================

Tool:    nikto
Target:  http://10.0.0.82
Status:  done
Created: 2025-01-21 15:30:22
Args:    -h http://10.0.0.82 -Tuning 123bde
Label:   web-scan

LOG OUTPUT:
----------------------------------------------------------------------
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.0.82
+ Target Hostname:    10.0.0.82
+ Target Port:        80
+ Start Time:         2025-01-21 15:30:25
---------------------------------------------------------------------------
+ Server: Apache/2.4.41
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /admin/: This might be interesting...
+ /config.php: PHP Config file may contain database credentials.
+ /login.php: Admin login page/section found.
---------------------------------------------------------------------------
+ End Time:   2025-01-21 15:32:15 (110 seconds)
---------------------------------------------------------------------------

Press any key to return...
```

## Scan Results Menu

Select option "View Scan Results" to see data menu:

```
======================================================================
SCAN RESULTS - Workspace: demo
======================================================================

  1. Hosts        (  1 total)
  2. Services     (  3 total)
  3. Findings     (  7 total)
  4. OSINT Data   ( 13 total)
  5. Web Paths    (  5 total)

  0. Back to Main Menu

Select data type: _
```

## Hosts View

```
======================================================================
HOSTS
======================================================================

ID    IP Address         Hostname                  Status
----------------------------------------------------------------------
1     10.0.0.82          -                         up         (3 services)

Press any key to return...
```

## Services View

```
======================================================================
SERVICES
======================================================================

Host IP            Port    Protocol   Service         Version
----------------------------------------------------------------------
10.0.0.82          22      tcp        ssh             OpenSSH 8.2p1
10.0.0.82          80      tcp        http            Apache/2.4.41
10.0.0.82          445     tcp        microsoft-ds    Samba 4.11.2

Press any key to return...
```

## Findings View

```
======================================================================
FINDINGS
======================================================================

Summary by severity:
  Critical  : 0
  High      : 2
  Medium    : 3
  Low       : 1
  Info      : 1

ID    Severity   Type                 Title
----------------------------------------------------------------------
1     high       web_vulnerability    Missing X-Frame-Options header
2     high       web_vulnerability    Missing X-Content-Type-Options
3     medium     web_vulnerability    Admin section found: /admin/
4     medium     web_vulnerability    Config file accessible
5     medium     sql_injection        Possible SQLi in 'id' parameter
6     low        smb_share            SMB Share: IPC$ (IPC)
7     info       smb_share            SMB Share: print$ (Disk)

Press any key to return...
```

## OSINT Data View

```
======================================================================
OSINT DATA
======================================================================

EMAIL (3)
----------------------------------------------------------------------
  admin@vulnweb.com                                  (from theHarvester)
  info@vulnweb.com                                   (from theHarvester)
  support@vulnweb.com                                (from theHarvester)

HOST (5)
----------------------------------------------------------------------
  www.vulnweb.com                                    (from theHarvester)
  mail.vulnweb.com                                   (from theHarvester)
  ftp.vulnweb.com                                    (from theHarvester)
  api.vulnweb.com                                    (from theHarvester)
  cdn.vulnweb.com                                    (from theHarvester)

IP (3)
----------------------------------------------------------------------
  44.228.249.3                                       (from theHarvester)
  44.228.249.102                                     (from theHarvester)
  44.228.249.153                                     (from theHarvester)

Press any key to return...
```

## Web Paths View

```
======================================================================
WEB PATHS
======================================================================

Host: 10.0.0.82
----------------------------------------------------------------------
  200        /admin                                        (4532 bytes)
  200        /login.php                                    (2341 bytes)
  200        /config.php                                   (156 bytes)
  403        /server-status                                (276 bytes)
  301        /images                                       (312 bytes)

Press any key to return...
```

## Navigation Flow

```
Main Menu
├── Launch Tools (1-6)
│   ├── Select Tool
│   ├── Configure Target & Preset
│   ├── Confirm Job
│   └── Return to Main Menu
│
├── View Jobs (7)
│   ├── List All Jobs
│   ├── Select Job ID
│   ├── View Job Details + Logs
│   └── Return to Jobs List → Main Menu
│
└── View Scan Results (8)
    ├── Select Data Type
    │   ├── Hosts (with service counts)
    │   ├── Services (with versions)
    │   ├── Findings (with severity summary)
    │   ├── OSINT Data (grouped by type)
    │   └── Web Paths (with status codes)
    └── Return to Results Menu → Main Menu
```

## Key Features

### Job Management
- **Color-coded status**: Green (done), Yellow (running), Red (failed)
- **Full log viewing**: Shows last 50 lines of job output
- **Quick navigation**: Jump directly to any job by ID

### Results Viewing
- **Live counts**: Shows current data counts in each category
- **Severity summaries**: Findings grouped by severity with color coding
- **Pagination**: Large result sets truncated with "and X more" indicators
- **Organized display**: Data grouped logically (by host, by type, etc.)

### User Experience
- **Consistent navigation**: Always clear how to return to previous menu
- **Pause prompts**: "Press any key" prevents screen flickering
- **Clear screen**: Each menu clears for clean presentation
- **Workspace context**: Always shows current workspace and stats
