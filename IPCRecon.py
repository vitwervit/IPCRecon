#!/usr/bin/env python3
"""
IPCRecon.py — Enumerate named pipes on a remote Windows host via IPC$,
identify software by pipe signatures and display structured results.

Default output hides only base Windows pipes. Everything else is shown,
grouped by category: Security, Remote Access, Offensive, Databases, etc.

Requires: impacket

Usage:
    python3 IPCRecon.py domain/user:password@target
    python3 IPCRecon.py domain/user:password@target -show-windows
    python3 IPCRecon.py domain/user:password@target -hide noise
    python3 IPCRecon.py domain/user@target -hashes :NTHASH -json
    python3 IPCRecon.py domain/user@target -k -dc-ip 10.0.0.1
"""

from __future__ import print_function
import sys, re, json, argparse, logging
from collections import OrderedDict

from impacket.smbconnection import SMBConnection
from impacket.examples import logger
from impacket.examples.utils import parse_target


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════
#
#  "windows"    — базовые сервисы ОС (скрыты по умолчанию)
#  "security"   — EDR / AV / endpoint protection
#  "remote"     — удалённый доступ / VPN
#  "c2"         — offensive tools / lateral movement
#  "attack"     — attack surface: coercion, relay, privesc vectors
#  "database"   — СУБД
#  "monitoring" — мониторинг / логирование
#  "noise"      — Chromium IPC, .NET diag, драйверы, принтеры…
#  "other"      — прочее идентифицированное ПО
#  "unknown"    — не идентифицировано (может быть интересным!)

CAT_LABELS = OrderedDict([
    ("c2",         "🔴 Offensive Tools"),
    ("unknown",    "🟡 Unidentified (investigate!)"),
    ("attack",     "⚔  Attack Surface (coercion/relay/privesc)"),
    ("security",   "🛡  Security / EDR / AV"),
    ("remote",     "🖥  Remote Access / VPN"),
    ("database",   "🗄  Databases"),
    ("monitoring", "📊 Monitoring / Logging"),
    ("other",      "📦 Other Software"),
    ("noise",      "⚙  Runtime / Drivers / Noise"),
    ("windows",    "🪟 Windows System (default)"),
])


# It is added to hidden set only when -show-windows is NOT specified (see main()).
DEFAULT_HIDDEN = set()


# ══════════════════════════════════════════════════════════════════════════════
#  KNOWN PIPES DATABASE — (pattern, software, category, match_type)
# ══════════════════════════════════════════════════════════════════════════════

def _build_db():
    db = []

    def exact(name, software, cat):
        db.append((name.lower(), software, cat, "exact"))

    def rx(pattern, software, cat):
        db.append((re.compile(pattern, re.IGNORECASE), software, cat, "regex"))

    # ═══════════════════════════════════════════════════════════════════
    #  WINDOWS CORE  (hidden by default)
    # ═══════════════════════════════════════════════════════════════════
    _win = [
        "srvsvc", "wkssvc", "svcctl", "winreg", "ntsvcs", "lsarpc",
        "samr", "atsvc", "eventlog",
        "InitShutdown", "LSM_API_service", "plugplay", "scerpc",
        "browser", "epmapper", "ITaskSchedulerService", "W32TIME_ALT",
        "dns", "DNSSERVER", "dhcpserver", "protected_storage",
        "lsass", "trkwks", "tapsrv", "wuauserv",
        "comnode", "FssagentRpc", "Frs-API", "SearchTextHarvester",
        "MsFteWds",
        "TermSrv_API_service", "Ctx_WinStation_API_service",
        "SessEnvPublicRpc", "WiFiNetworkManagerTask", "WidgetsCommandPipe",
        "SLListenerPipe", "WwanSvcTask", "WsusHealthMonitoringPort",
        "newtstop", "ROUTER",
    ]
    for p in _win:
        exact(p, "Windows", "windows")

    rx(r"^PIPE_EVENTROOT",  "Windows WMI",             "windows")
    rx(r"^Winsock2\\CatalogChangeListener", "Windows Winsock", "windows")
    rx(r"^PSHost\.",        "PowerShell",               "windows")
    rx(r"^TSVCPIPE",        "Windows TermSrv",          "windows")
    rx(r"^LRPC-",           "Windows RPC",              "windows")
    rx(r"^PIPE_LANMAN$",    "Windows LanMan",           "windows")
    rx(r"^PIPE_WSMAN$",     "Windows WinRM",            "windows")
    rx(r"^AppContracts_",   "Windows UWP",              "windows")
    rx(r"^DumpWriter[A-F0-9]+$", "Windows WER",        "windows")
    rx(r"^Global\\[a-f0-9]+-\{", "Windows WER",        "windows")
    rx(r"^UIA_PIPE_",       "Windows UI Automation",    "windows")
    rx(r"^Spooler\\",       "Windows Print Spooler",    "windows")
    rx(r"^RpcProxy\\",      "Windows RPC HTTP Proxy",   "windows")
    rx(r"^ProtectedPrefix\\LocalService\\FTHPIPE", "Windows Full-Text Host", "windows")
    # Windows dynamic RPC endpoints (standard GUID format)
    rx(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(_\d+)?$",
                            "Windows RPC (dynamic endpoint)", "windows")
    rx(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$",
                            "Windows RPC (dynamic endpoint)", "windows")
    # Exchange parent-child IPC
    rx(r"^ExchangeToParentPipe\d+$", "Windows Process IPC", "windows")
    rx(r"^ParentToExchangePipe\d+$", "Windows Process IPC", "windows")

    # ═══════════════════════════════════════════════════════════════════
    #  ATTACK SURFACE — Windows services interesting for pentesting
    #  Shown by default! These indicate coercion/relay/privesc vectors.
    # ═══════════════════════════════════════════════════════════════════

    exact("cert",  "ADCS (Certificate Services) → ESC", "attack")
    exact("spoolss", "Print Spooler → SpoolSample coercion, PrintNightmare", "attack")
    exact("DAV RPC SERVICE", "WebClient → HTTP coercion, NTLM relay (no SMB signing)", "attack")
    exact("efsrpc", "EFS RPC → PetitPotam coercion", "attack")
    exact("efsr",   "EFS RPC → PetitPotam coercion", "attack")
    exact("netlogon", "Netlogon → ZeroLogon (CVE-2020-1472)", "attack")
    exact("netdfs", "DFS → DFSCoerce coercion", "attack")

    # ═══════════════════════════════════════════════════════════════════
    #  SECURITY / EDR / AV
    # ═══════════════════════════════════════════════════════════════════

    rx(r"^MsMpCom",      "Windows Defender",            "security")

    # Kaspersky
    rx(r"^kscipc\\",     "Kaspersky Security Center (KSC)", "security")
    rx(r"^[A-F0-9]{32}(_[A-Z]{2,3}_[A-F0-9]+|_[A-F0-9]+)*$",
                         "Kaspersky Endpoint Security",     "security")
    rx(r"^kprometheus\.", "Kaspersky (metrics)",             "security")
    exact("_KCOPILOT_SERVER_IPC_", "Kaspersky Copilot",     "security")
    rx(r"^ExtEventPipe_Service$", "Kaspersky KES (events)", "security")
    rx(r"^ShellEx_\d+$",          "Kaspersky KES (shell extension)", "security")
    rx(r"^ShortcutNotifier_\d+$", "Kaspersky KES (shell extension)", "security")
    rx(r"^FTA_\d+$",              "Kaspersky KES (file type assoc)", "security")

    # Bitdefender
    rx(r"^local\\msgbus\\", "Bitdefender",              "security")
    rx(r"^bdagent",         "Bitdefender",               "security")

    # CrowdStrike
    rx(r"^CrowdStrike\\",  "CrowdStrike Falcon",        "security")

    # SentinelOne
    rx(r"^SentinelAgentWorkerCert\.", "SentinelOne",     "security")
    rx(r"^DFIScanner\.",              "SentinelOne",     "security")

    # ESET
    exact("nod_scriptmon_pipe", "ESET NOD32",            "security")
    rx(r"^nod_",                "ESET NOD32",            "security")
    exact("Exploit_Blocker",    "ESET (Exploit Blocker)", "security")

    # Cybereason
    rx(r"^CybereasonAP",  "Cybereason",                 "security")

    # Sophos
    rx(r"^sophos",         "Sophos Intercept X",         "security")
    rx(r"^SophosUI",       "Sophos Intercept X",         "security")
    rx(r"^SophosEventStore", "Sophos Intercept X",       "security")

    # Carbon Black
    rx(r"^cbnamedpipe",    "Carbon Black",               "security")
    rx(r"^cbapi",          "Carbon Black",               "security")

    # Cylance
    rx(r"^CyMemDef",      "Cylance",                    "security")
    rx(r"^CylanceSvc",    "Cylance",                    "security")

    # Cortex XDR / Palo Alto
    rx(r"^cyvera_",       "Cortex XDR (Palo Alto)",     "security")
    rx(r"^cyserver",      "Cortex XDR (Palo Alto)",     "security")
    rx(r"^Traps",         "Cortex XDR (Palo Alto)",     "security")

    # Trend Micro
    rx(r"^TMSYSEVT",      "Trend Micro Apex One",       "security")
    rx(r"^iaccess_event_pipe", "Trend Micro",            "security")

    # McAfee / Trellix
    rx(r"^mclogevent",    "McAfee/Trellix",              "security")
    rx(r"^McEPPipe",      "McAfee/Trellix",              "security")

    # Symantec / Broadcom
    rx(r"^ccSvcHst",      "Symantec Endpoint Protection","security")

    # F-Secure / WithSecure
    rx(r"^fssvc",         "F-Secure/WithSecure",         "security")

    # Elastic Endpoint
    rx(r"^elastic-endpoint", "Elastic Endpoint Security","security")

    # Malwarebytes
    rx(r"^MBAMService",   "Malwarebytes",                "security")
    rx(r"^MBAM",          "Malwarebytes",                "security")

    # Avast / AVG
    rx(r"^AvastSvc",      "Avast Antivirus",             "security")
    rx(r"^avgsvc",        "AVG Antivirus",               "security")

    # Dr.Web
    rx(r"^drweb",         "Dr.Web",                      "security")

    # Positive Technologies (MaxPatrol, PT NAD, XDR)
    rx(r"^PTAgentPipe_",  "Positive Technologies (MaxPatrol)", "security")

    # SafeNet Sentinel (HASP hardware key licensing)
    rx(r"^SafeNet-SentinelPIPE-", "SafeNet Sentinel (HASP)", "security")

    # ═══════════════════════════════════════════════════════════════════
    #  MONITORING / LOGGING
    # ═══════════════════════════════════════════════════════════════════

    rx(r"^Sysmon",         "Microsoft Sysmon",            "monitoring")
    rx(r"^Tanium",         "Tanium",                      "monitoring")
    rx(r"^ZabbixAgentPipe","Zabbix Agent",                "monitoring")
    rx(r"^Splunk",         "Splunk Forwarder",            "monitoring")
    rx(r"^ossec",          "OSSEC/Wazuh Agent",           "monitoring")
    rx(r"^wazuh",          "Wazuh Agent",                 "monitoring")
    rx(r"^nagios",         "Nagios Agent",                "monitoring")
    rx(r"^grafana",        "Grafana",                     "monitoring")

    # ═══════════════════════════════════════════════════════════════════
    #  REMOTE ACCESS / VPN
    # ═══════════════════════════════════════════════════════════════════

    exact("TightVNC_Service_Control",  "TightVNC",       "remote")
    exact("TVN_log_pipe_public_name",  "TightVNC",       "remote")
    rx(r"^ultravnc",       "UltraVNC",                   "remote")
    rx(r"^vncserver",      "RealVNC",                    "remote")
    rx(r"^AnyDesk",        "AnyDesk",                    "remote")
    rx(r"^adpipe",         "AnyDesk",                    "remote")
    rx(r"^TeamViewer",     "TeamViewer",                 "remote")
    rx(r"^rustdesk",       "RustDesk",                   "remote")
    rx(r"^RuDesktop\\",    "RuDesktop",                  "remote")
    exact("OutlineServicePipe", "Outline VPN",            "remote")
    rx(r"^WireGuard",      "WireGuard VPN",              "remote")
    rx(r"^OpenVPN",        "OpenVPN",                    "remote")
    rx(r"^RadminPipe",     "Radmin",                     "remote")
    rx(r"^DameWare",       "DameWare MRC",               "remote")
    rx(r"^DNTUS\d+$",      "DameWare MRC",               "remote")
    rx(r"^DNTU\d+In$",     "DameWare MRC",               "remote")
    rx(r"^BomgarPipe",     "BeyondTrust (Bomgar)",       "remote")
    rx(r"amneziavpn",      "AmneziaVPN",                 "remote")
    rx(r"AmneziaVPN",      "AmneziaVPN",                 "remote")
    rx(r"^local:AmneziaVpnIpcInterface$", "AmneziaVPN",  "remote")
    rx(r"ProtectedPrefix\\Administrators\\AmneziaWG", "AmneziaVPN", "remote")
    rx(r"^ROMFUS",         "ROMFUS (remote monitoring)", "remote")
    rx(r"^ROMViewer",      "ROMFUS (remote monitoring)", "remote")

    # ═══════════════════════════════════════════════════════════════════
    #  C2 / OFFENSIVE TOOLS
    # ═══════════════════════════════════════════════════════════════════

    exact("PSEXESVC",          "Sysinternals PsExec",        "c2")
    exact("csexecsvc",         "CSEXEC",                     "c2")
    exact("paexec",            "PAExec",                     "c2")
    exact("remcom",            "RemCom",                     "c2")
    rx(r"^msagent_",           "Impacket PsExec",            "c2")
    exact("gruntsvc",          "Covenant C2",                "c2")
    exact("jaccdpqnvbrrxlaf",  "PoshC2 (default pipe)",      "c2")
    exact("WCEServicePipe",    "Windows Credential Editor",  "c2")
    exact("SigmaPotato",       "SigmaPotato PrivEsc",        "c2")
    rx(r"^msse-\d+-server$",   "Cobalt Strike",              "c2")
    rx(r"^MSSE-\d+-server$",   "Cobalt Strike",              "c2")
    rx(r"^postex_",            "Cobalt Strike (post-ex)",    "c2")
    rx(r"^status_\d+$",        "Cobalt Strike",              "c2")
    rx(r"^DserNamePipe",       "Cobalt Strike",              "c2")
    rx(r"^f4c3[a-f0-9]",       "Cobalt Strike",              "c2")
    rx(r"^f53f[a-f0-9]",       "Cobalt Strike",              "c2")
    rx(r"^isapi_http$",        "Uroburos/Turla APT",         "c2")
    rx(r"^isapi_dg",           "Uroburos/Turla APT",         "c2")
    rx(r"^adschemerpc$",       "Turla HyperStack",           "c2")
    rx(r"^sdlrpc$",            "Cobra Trojan",               "c2")
    rx(r"^winsession$",        "Wild Neutron APT",           "c2")
    rx(r"^lsassw$",            "Wild Neutron APT",           "c2")
    rx(r"^ahexec$",            "Sofacy APT",                 "c2")
    rx(r"^bizkaz$",            "Snatch Ransomware",          "c2")
    rx(r"^dce_3d$",            "Qbot",                       "c2")
    rx(r"^AnonymousPipe$",     "Hidden Cobra (Hoplight)",    "c2")
    rx(r"^583da945-62af-10e8-4902-a8f205c72b2e$", "SolarWinds SUNBURST", "c2")
    rx(r"^6e7645c4-32c5-4fe3-aabf-e94c2f4370e7$", "LiquidSnake",        "c2")

    # ═══════════════════════════════════════════════════════════════════
    #  DATABASES
    # ═══════════════════════════════════════════════════════════════════

    rx(r"^SQLLocal\\",     "MS SQL Server",               "database")
    rx(r"^MSSQL\$",        "MS SQL Server",               "database")
    rx(r"\\sql\\query$",   "MS SQL Server",               "database")
    exact("sql\\query",    "MS SQL Server",               "database")
    rx(r"^msfte\\",        "MS SQL Server (Full-Text)",   "database")
    rx(r"^sqlsatellitelaunch", "MS SQL Server",           "database")
    rx(r"MICROSOFT##WID",  "Windows Internal Database",   "database")
    rx(r"^pgsignal_\d+$",  "PostgreSQL",                  "database")
    rx(r"^\.s\.PGSQL\.",   "PostgreSQL",                  "database")
    rx(r"^MySQL",          "MySQL Server",                "database")
    rx(r"^ORA_",           "Oracle Database",             "database")
    rx(r"^cubrid",         "CUBRID Database",             "database")
    rx(r"^interbas\\",     "InterBase/Firebird",          "database")

    # ═══════════════════════════════════════════════════════════════════
    #  NOISE (runtime, drivers, printers…)
    # ═══════════════════════════════════════════════════════════════════

    # Chromium / Electron
    rx(r"^crashpad_\d+_",          "Chromium (crashpad)",     "noise")
    rx(r"LOCAL\\crashpad_",        "Chromium (crashpad)",     "noise")
    rx(r"^mojo\.\d+\.\d+\.\d+",   "Chromium (mojo IPC)",    "noise")
    rx(r"LOCAL\\mojo\.",           "Chromium (mojo IPC)",     "noise")
    rx(r"LOCAL\\mojo\.external_task_manager", "Chromium",     "noise")
    rx(r"Sessions\\.*\\mojo\.",    "Chromium (AppContainer)", "noise")
    rx(r"Sessions\\.*\\crashpad_", "Chromium (AppContainer)", "noise")
    rx(r"^chromium\.",             "Chromium",                "noise")
    rx(r"^chrome\.",               "Google Chrome",           "noise")
    rx(r"^gc_pipe_",               "Google Chrome IPC",       "noise")

    # Firefox / Gecko
    rx(r"^gecko\.\d+\.\d+\.",      "Mozilla Firefox (IPC)",  "noise")
    rx(r"^gecko-crash",            "Mozilla Firefox (crash)", "noise")
    rx(r"LOCAL\\cubeb-pipe-",      "Mozilla Firefox (audio)", "noise")

    # Microsoft Edge
    rx(r"LOCAL\\edge\.sync\.",     "Microsoft Edge (sync)",   "noise")

    # Microsoft Teams
    rx(r"LOCAL\\maglev\.",         "Microsoft Teams",         "noise")
    rx(r"Teams-Tfw-instance-pipe$","Microsoft Teams",         "noise")

    # Yandex Browser
    rx(r"^browser\.[a-f0-9]+\.\d+\.", "Yandex Browser",      "noise")
    rx(r"^YandexServiceUpdatePipe",   "Yandex Browser",      "noise")
    rx(r"^logging-control-\d+$",      "Yandex Browser",      "noise")

    # Microsoft Office
    rx(r"^OfficeUser_",            "Microsoft Office",        "noise")

    # .NET
    rx(r"^dotnet-diagnostic-\d+",  ".NET Runtime Diagnostics","noise")
    rx(r"^clr_",                   ".NET CLR",                "noise")
    rx(r"^CPFATP_",                ".NET ClickOnce",          "noise")

    # Intel
    rx(r"^Intel\.",                "Intel Graphics Driver",    "noise")
    rx(r"^IGESystrayPipe$",        "Intel Graphics (systray)", "noise")

    # NVIDIA
    rx(r"^Nv[A-Z]",               "NVIDIA Driver",           "noise")
    rx(r"^nvcs$",                  "NVIDIA Driver",           "noise")
    rx(r"^stereosvrpipe$",         "NVIDIA 3D Vision",        "noise")

    # VMware
    for p in ["vgauth-service", "VMware-UsbArbitrationPipe",
              "vmware-authdpipe", "VGAuthService"]:
        exact(p, "VMware Guest Tools", "noise")
    rx(r"^vmware",                 "VMware Guest Tools",      "noise")
    rx(r"^VGAuth",                 "VMware Guest Tools",      "noise")
    rx(r"^vmx[0-9a-f]{16}$",      "VMware VM process",       "noise")
    rx(r"\.vmx$",                  "VMware VM pipe",          "noise")

    # VirtualBox
    rx(r"^VBoxTrayIPC",            "VirtualBox Guest",        "noise")
    rx(r"^VBoxMiniRdDN",           "VirtualBox Guest",        "noise")

    # Printers — virtual, fax
    rx(r"^PDFPrint",               "PDF Virtual Printer",     "noise")
    rx(r"^FaxPrint",               "Fax Virtual Printer",     "noise")

    # HP
    rx(r"^HP\.Omen\.",             "HP Omen Software",        "noise")
    rx(r"^hpmon$",                 "HP Printer Monitor",      "noise")
    rx(r"^HPUPDMon$",              "HP Printer Driver",       "noise")

    # Xerox
    rx(r"^Xerox ",                 "Xerox Printer/Fax",       "noise")

    # Kyocera
    rx(r"^kyoceradocumentsolutions\\", "Kyocera Printer",     "noise")
    rx(r"^kds\\",                  "Kyocera Printer",         "noise")
    rx(r"^KmInst32$",              "Kyocera Printer Installer","noise")

    # PM2 (Node.js)
    rx(r"^pm2_",                   "PM2 (Node.js)",           "noise")
    rx(r"^shared-pm2-",            "PM2 (Node.js)",           "noise")

    # libuv (Node.js runtime)
    rx(r"^uv\\",                   "libuv (Node.js runtime)", "noise")

    # Qt framework
    rx(r"^qt-[A-F0-9]+-",         "Qt Framework (app IPC)",  "noise")
    rx(r"^qtsingleapp-",          "Qt Framework (single instance)", "noise")

    rx(r"^SapiPipeTransport$",     "Windows Speech API",      "noise")

    # IIS
    rx(r"^iisipm",                 "IIS Worker Process",      "noise")
    rx(r"^iislogpipe$",            "IIS Logging",             "noise")
    rx(r"^wbhstipm$",              "IIS Web Host Service",    "noise")

    # FlexNet / Flexera licensing
    rx(r"FlexNet Licensing",       "FlexNet Licensing",       "noise")
    rx(r"FLEXnet Licensing",       "FlexNet Licensing",       "noise")

    # ═══════════════════════════════════════════════════════════════════
    #  OTHER SOFTWARE
    # ═══════════════════════════════════════════════════════════════════

    # Autodesk (AutoCAD, Revit)
    rx(r"^AcIpcIn-",       "Autodesk AutoCAD",         "other")
    rx(r"^AcIpcOut-",      "Autodesk AutoCAD",         "other")
    rx(r"^Autodesk\.",     "Autodesk",                 "other")

    # Adobe
    rx(r"^com\.adobe\.",   "Adobe Creative Cloud",     "other")

    # Acronis
    rx(r"^Acronis",        "Acronis Backup",           "other")
    rx(r"^aakore",         "Acronis Active Protection","other")

    # WPS Office / Kingsoft
    rx(r"^QingBanGong",    "WPS Office (Kingsoft)",    "other")
    rx(r"QingBanGong",     "WPS Office (Kingsoft)",    "other")
    rx(r"^_Thrift_Qing_IPC_", "WPS Office (Kingsoft)", "other")
    rx(r"^WPSCloudSvr\\",  "WPS Office (Kingsoft)",    "other")
    rx(r"^recentfile_server", "WPS Office (Kingsoft)", "other")
    rx(r"^ELiveClient_",  "WPS Office (Kingsoft)",     "other")

    # Viber
    rx(r"^Viber-",         "Viber Messenger",          "other")

    # Sublime Text
    rx(r"^Sublime Text\.", "Sublime Text Editor",      "other")

    # DAEMON Tools
    rx(r"^DTShellHelper-", "DAEMON Tools",             "other")

    # SKB Kontur (accounting/EDI)
    rx(r"^kontur\.",       "SKB Kontur",               "other")

    # MegaFon modem
    rx(r"MegaFon Modem",   "MegaFon Modem",            "other")

    # Docker
    rx(r"^docker_engine",  "Docker Desktop",            "other")
    rx(r"^docker_cli",     "Docker Desktop",            "other")

    # 1C Enterprise
    rx(r"^1CV8",           "1C Enterprise",             "other")

    # Veeam
    rx(r"^Veeam",          "Veeam Backup",              "other")

    # Microsoft SCCM
    rx(r"^CcmExec",        "Microsoft SCCM",            "other")

    # Ext2/3/4 volume manager (Ext2Fsd)
    exact("EXT2MGR_PSRV",  "Ext2Fsd Volume Manager",   "other")

    # ASE (Sybase/SAP)
    rx(r"^ASE_VC_PIPE",    "Sybase/SAP ASE",            "other")

    # FDSVC (file detection — various products)
    rx(r"^FDSVC_PIPE_",    "File Detection Service",    "other")

    return db


def _deduplicate_db(db):
    seen_exact = set()
    seen_regex = set()
    deduped = []
    for entry in db:
        pattern, software, cat, ptype = entry
        if ptype == "exact":
            key = pattern  # already lowercased string
            if key in seen_exact:
                logging.debug(f"Duplicate exact pipe pattern skipped: '{pattern}'")
                continue
            seen_exact.add(key)
        elif ptype == "regex":
            key = pattern.pattern  # compiled regex → its source string
            if key in seen_regex:
                logging.debug(f"Duplicate regex pattern skipped: '{key}'")
                continue
            seen_regex.add(key)
        deduped.append(entry)
    return deduped


# ══════════════════════════════════════════════════════════════════════════════
#  PIPE FILTER
# ══════════════════════════════════════════════════════════════════════════════

class PipeFilter:
    def __init__(self, extra_db_path=None):
        raw_db = _build_db()
        self.db = _deduplicate_db(raw_db)
        if extra_db_path:
            self._load_extra(extra_db_path)

    def _load_extra(self, path):
        """
        JSON: {"pipes": [
            {"pattern":"...", "software":"...", "category":"...", "type":"exact|regex"}
        ]}
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logging.error(f"Failed to load extra pipe database '{path}': {e}")
            return

        for i, e in enumerate(data.get("pipes", [])):
            if "pattern" not in e or "software" not in e:
                logging.warning(
                    f"Entry #{i} in '{path}' is missing required key(s) "
                    f"('pattern' and/or 'software') — skipped."
                )
                continue
            cat = e.get("category", "other")
            if cat not in CAT_LABELS:
                logging.warning(
                    f"Entry #{i} in '{path}' has unknown category '{cat}' — "
                    f"falling back to 'other'."
                )
                cat = "other"
            if e.get("type") == "regex":
                try:
                    compiled = re.compile(e["pattern"], re.IGNORECASE)
                except re.error as err:
                    logging.warning(
                        f"Entry #{i} in '{path}' has invalid regex "
                        f"'{e['pattern']}': {err} — skipped."
                    )
                    continue
                self.db.append((compiled, e["software"], cat, "regex"))
            else:
                self.db.append((e["pattern"].lower(), e["software"], cat, "exact"))

    def identify(self, pipe_name):
        """Returns (software, category) or (None, 'unknown')."""
        name = pipe_name.strip()
        name_lower = name.lower()
        for pattern, software, cat, ptype in self.db:
            if ptype == "exact":
                if name_lower == pattern:
                    return software, cat
            elif ptype == "regex":
                if pattern.search(name):
                    return software, cat
        return None, "unknown"

    def list_pipes(self, smb_conn):
        pipes = []
        for f in smb_conn.listPath("IPC$", "\\*"):
            name = f.get_longname()
            if name in (".", ".."):
                continue
            pipes.append(name)
        return sorted(pipes)

    def classify(self, all_pipes):
        """Returns dict: {category: [(pipe_name, software), ...]}"""
        result = {}
        for p in all_pipes:
            sw, cat = self.identify(p)
            result.setdefault(cat, []).append((p, sw))
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT — CONSOLE
# ══════════════════════════════════════════════════════════════════════════════

class C:
    R  = "\033[91m";  G  = "\033[92m";  Y  = "\033[93m"
    CN = "\033[96m";  P  = "\033[95m";  W  = "\033[97m"
    B  = "\033[1m";   D  = "\033[2m";   E  = "\033[0m"

CAT_COLORS = {
    "c2":         C.R,
    "unknown":    C.Y,
    "attack":     C.R,
    "security":   C.CN,
    "remote":     C.P,
    "database":   C.G,
    "monitoring": C.G,
    "other":      C.W,
    "noise":      C.D,
    "windows":    C.D,
}


def print_results(classified, remote, hidden_cats, auth_method=None):
    total = sum(len(v) for v in classified.values())
    shown = sum(len(v) for cat, v in classified.items() if cat not in hidden_cats)
    hidden_n = total - shown

    print(f"\n{C.B}[*] Host: {remote}{C.E}"
          + (f"  {C.D}(auth: {auth_method}){C.E}" if auth_method else ""))
    print(f"    Total pipes: {total}  |  Shown: {shown}  |  "
          f"{C.D}Hidden: {hidden_n}{C.E}\n")

    found_anything = False

    for cat, label in CAT_LABELS.items():
        if cat in hidden_cats:
            continue
        items = classified.get(cat, [])
        if not items:
            continue

        found_anything = True
        color = CAT_COLORS.get(cat, "")
        print(f"  {color}{C.B}{label}{C.E}  ({len(items)})")

        if cat == "unknown":
            for pipe_name, _ in items:
                print(f"    {C.Y}●{C.E} {pipe_name}")
        elif cat in ("c2", "attack"):
            for pipe_name, sw in items:
                if sw:
                    print(f"    {C.R}▸{C.E} {pipe_name}  {C.R}← {sw}{C.E}")
                else:
                    print(f"    {C.R}▸{C.E} {pipe_name}")
        else:
            by_sw = {}
            for pipe_name, sw in items:
                by_sw.setdefault(sw or "?", []).append(pipe_name)
            for sw in sorted(by_sw.keys()):
                pipes = by_sw[sw]
                if len(pipes) <= 3:
                    for p in pipes:
                        print(f"    {color}○{C.E} {p}  {C.D}[{sw}]{C.E}")
                else:
                    print(f"    {color}○{C.E} {sw}  {C.D}({len(pipes)} pipes){C.E}")
        print()

    if not found_anything:
        print(f"  {C.D}Nothing to show (all pipes are default Windows).{C.E}\n")

    hidden_summary = []
    for cat in hidden_cats:
        n = len(classified.get(cat, []))
        if n > 0:
            hidden_summary.append(f"{CAT_LABELS.get(cat, cat)}: {n}")
    if hidden_summary:
        print(f"  {C.D}Hidden: {', '.join(hidden_summary)}{C.E}")
        print(f"  {C.D}Use -show-windows to show Windows pipes, "
              f"-show-noise to show runtime/drivers{C.E}\n")


def output_json(classified, remote, hidden_cats):
    result = {
        "host": remote,
        "total": sum(len(v) for v in classified.values()),
    }
    for cat, label in CAT_LABELS.items():
        items = classified.get(cat, [])
        if not items:
            continue
        cat_data = {}
        for pipe_name, sw in items:
            key = sw or "unidentified"
            cat_data.setdefault(key, []).append(pipe_name)
        result[cat] = {
            "label": label,
            "count": len(items),
            "hidden": cat in hidden_cats,
            "software": cat_data,
        }
    print(json.dumps(result, indent=2, ensure_ascii=False))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Enumerate IPC$ named pipes, identify software, "
                    "display results grouped by category.")
    parser.add_argument("target",
                        help="[[domain/]username[:password]@]<host>")
    parser.add_argument("-show-windows", action="store_true",
                        help="Show default Windows system pipes")
    parser.add_argument("-show-noise", action="store_true",
                        help="Show runtime/driver noise (Chromium, .NET…)")
    parser.add_argument("-hide", metavar="CAT", nargs="+",
                        help="Hide categories: security, remote, c2, "
                             "database, monitoring, noise, other, unknown")
    parser.add_argument("-only", metavar="CAT", nargs="+",
                        help="Show ONLY these categories")
    parser.add_argument("-known-db", metavar="FILE",
                        help="Additional JSON database of known pipes")
    parser.add_argument("-json", action="store_true",
                        help="JSON output")
    parser.add_argument("-debug", action="store_true")

    g = parser.add_argument_group("authentication")
    g.add_argument("-hashes", metavar="LMHASH:NTHASH")
    g.add_argument("-no-pass", action="store_true")
    g.add_argument("-k", action="store_true", help="Kerberos auth")
    g.add_argument("-aesKey", metavar="hex key")
    g.add_argument("-dc-ip", metavar="ip")
    g.add_argument("-target-ip", metavar="ip")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    o = parser.parse_args()
    logger.init()
    logging.getLogger().setLevel(logging.DEBUG if o.debug else logging.INFO)

    valid_cats = set(CAT_LABELS.keys())
    if o.hide:
        bad = [c for c in o.hide if c not in valid_cats]
        if bad:
            logging.warning(
                f"Unknown category name(s) in -hide: {bad}. "
                f"Valid categories: {sorted(valid_cats)}"
            )
    if o.only:
        bad = [c for c in o.only if c not in valid_cats]
        if bad:
            logging.warning(
                f"Unknown category name(s) in -only: {bad}. "
                f"Valid categories: {sorted(valid_cats)}"
            )

    domain, username, password, remoteName = parse_target(o.target)
    lmhash, nthash = o.hashes.split(":") if o.hashes else ("", "")
    target_ip = o.target_ip or remoteName
    domain = domain or ""

    if (password == "" and username != "" and o.hashes is None
            and not o.no_pass and o.aesKey is None):
        from getpass import getpass
        password = getpass("Password: ")

    # ── Подключение ──
    def try_connect(user, passwd, dom, lm, nt, method_name):
        """Attempt SMB connect + IPC$ access. Returns (SMBConnection, method_str) or raises."""
        conn = SMBConnection(remoteName, target_ip)
        if o.k:
            conn.kerberosLogin(user, passwd, dom, lm, nt, o.aesKey, o.dc_ip)
        else:
            conn.login(user, passwd, dom, lm, nt)
        # Verify we can actually list IPC$ (auth may succeed but access denied)
        conn.listPath("IPC$", "\\*")
        return conn, method_name

    smb = None
    auth_method = None

    if username:
        method_label = "kerberos" if o.k else "credentials"
        try:
            smb, auth_method = try_connect(
                username, password, domain, lmhash, nthash, method_label
            )
        except Exception as e:
            logging.error(f"Authentication failed: {e}")
            sys.exit(1)
    else:
        strategies = [
            ("",      "",  "",     "", "", "null session (anonymous)"),
            ("Guest", "",  "",     "", "", "Guest account"),
            ("",      "",  domain, "", "", "null session (domain context)"),
        ]

        last_error = None
        for s_user, s_pass, s_dom, s_lm, s_nt, s_desc in strategies:
            try:
                logging.debug(f"Trying {s_desc}...")
                smb, auth_method = try_connect(s_user, s_pass, s_dom, s_lm, s_nt, s_desc)
                logging.info(f"Connected via {s_desc}")
                break
            except Exception as e:
                last_error = e
                logging.debug(f"{s_desc} failed: {e}")
                continue

        if smb is None:
            logging.error(
                f"All anonymous/guest auth methods failed on {remoteName}.\n"
                f"Last error: {last_error}\n\n"
                f"  This is expected on modern Windows (10 1709+, Server 2019+)\n"
                f"  which block null sessions to IPC$ by default.\n\n"
                f"  Solutions:\n"
                f"    1. Use domain credentials:  IPCRecon.py domain/user:pass@{remoteName}\n"
                f"    2. Use NTLM hash:            IPCRecon.py domain/user@{remoteName} -hashes :NTHASH\n"
                f"    3. Use Kerberos:             IPCRecon.py domain/user@{remoteName} -k -no-pass\n\n"
                f"  Note: any valid domain user works, no admin rights needed."
            )
            sys.exit(1)

    # ── Получение pipes ──
    pf = PipeFilter(extra_db_path=o.known_db)
    try:
        all_pipes = pf.list_pipes(smb)
    except Exception as e:
        logging.error(f"Failed to list IPC$: {e}")
        sys.exit(1)
    finally:
        try:
            smb.logoff()
        except Exception:
            pass

    classified = pf.classify(all_pipes)

    # ── Определение скрытых категорий ──
    if o.only:
        hidden = {cat for cat in CAT_LABELS if cat not in o.only}
    else:
        hidden = set(DEFAULT_HIDDEN)
        if not o.show_windows:
            hidden.add("windows")
        if not o.show_noise:
            hidden.add("noise")
        if o.hide:
            hidden.update(c for c in o.hide if c in valid_cats)

    # ── Вывод ──
    if o.json:
        output_json(classified, remoteName, hidden)
    else:
        print_results(classified, remoteName, hidden, auth_method=auth_method)


if __name__ == "__main__":
    main()
