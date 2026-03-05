 #!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NMAP_PRO_OSS_ENTERPRISE
Hybrid IT/OT Enterprise Network Assessment Suite (Single-File Open Source)

License: MIT (suggested)
Purpose:
  - Authorized security assessment and asset discovery in hybrid enterprise environments
  - OT/IoT-safe by default (rate limiting, retries, batching, script-blocking on PLC/ICS)
  - Real-time output streaming, scheduling, reporting, dashboards, graphs

DISCLAIMER
  - Use ONLY with explicit authorization.
  - This tool intentionally avoids automated exploit/vulnerability frameworks (e.g., NSE vuln/exploit/unsafe).
  - "Vulnerability Scan" in this tool = Exposure Assessment (attack-surface discovery + safe enumeration + ranking).

FEATURES
  - Banner + interactive menu
  - Scan options:
      1) Vulnerability Scan (Exposure Assessment - SAFE)
      2) Full TCP + UDP Port Scan (UDP confirm in OT_SAFE)
      3) OS Detection + SMB Fingerprinting (SAFE; OT confirm)
      4) Malware Indicator + Active Directory Enumeration (opt-in scripts; safe allowlist)
      6) Full Combo Scan (SAFE)
      7) SSL/TLS Certificate Scan
      8) SMB Deep Scan (SAFE allowlist)
      9) Exit
  - Per prompt: shows examples + recommended best choice
  - Target types: Single IP / CIDR / Hostname
  - Auto network discovery for CIDR (ping sweep)
  - Asset inventory CSV
  - Asset classification: Windows/Linux/Network Device/IoT/Printer/PLC-ICS/Unknown
  - Fragile IoT/OT pre-detection (light fingerprint sample)
  - Adaptive safe scanning:
      - Default batching: 50 hosts per wave
      - Re-measures network metrics between waves (packet loss, latency)
      - Heuristics for firewall drops/filtering
      - Adjusts max-rate and concurrency mid-run
      - Device-type-aware throttling
  - Auto-disable scripts on PLC/ICS unless explicit override
  - Skip hosts scanned within N minutes; skip after 5 failures
  - Reports per run:
      - TXT per host
      - CSV tables (hosts.csv, findings.csv, subnet_scores.csv)
      - HTML dashboard
      - Topology graph PNG
      - Risk heatmap PNG
      - Attack-graph PNG + GraphML export
      - ZIP bundle of run artifacts
  - Optional web dashboard (Flask) serving run artifacts
  - Scheduling:
      - run now
      - run once at date/time
      - daily/weekly/monthly at time

"""

import os
import re
import sys
import csv
import json
import time
import math
import shutil
import socket
import zipfile
import ipaddress
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------- Dependency bootstrap -------------------------

REQUIRED_PY_PKGS = [
    ("rich", "rich"),
    ("jinja2", "jinja2"),
    ("flask", "flask"),
    ("networkx", "networkx"),
    ("matplotlib", "matplotlib"),
]

def _pip_install(pkgs):
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + pkgs
    print(f"[+] Installing: {', '.join(pkgs)}")
    subprocess.check_call(cmd)

def ensure_deps():
    missing = []
    for mod, pipname in REQUIRED_PY_PKGS:
        try:
            __import__(mod)
        except Exception:
            missing.append(pipname)

    if not missing:
        return True

    print("\n[!] Missing Python packages:", ", ".join(missing))
    ans = input("Install missing dependencies now via pip? (Y/n): ").strip().lower()
    if ans in ("", "y", "yes"):
        try:
            _pip_install(missing)
            return True
        except Exception as e:
            print(f"[!] Install failed: {e}")
            print("[!] Continuing in degraded mode (no HTML/web UI/visuals).")
            return False
    return False

HAS_DEPS = ensure_deps()

# Optional imports (degraded mode support)
console = None
Template = None
nx = None
plt = None
Flask = None
render_template_string = None
send_from_directory = None

if HAS_DEPS:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        console = Console()
    except Exception:
        console = None

if HAS_DEPS:
    try:
        from jinja2 import Template
    except Exception:
        Template = None

if HAS_DEPS:
    try:
        import networkx as nx
    except Exception:
        nx = None

if HAS_DEPS:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        plt = None

if HAS_DEPS:
    try:
        from flask import Flask, render_template_string, send_from_directory
    except Exception:
        Flask = None
        render_template_string = None
        send_from_directory = None


# ------------------------- Directories & constants -------------------------

BASE_DIR = Path.cwd()
DATA_DIR = BASE_DIR / "nmap_pro_data"
SCANS_DIR = DATA_DIR / "nmap_scans"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
STATE_DIR = DATA_DIR / "state"

for d in (DATA_DIR, SCANS_DIR, REPORTS_DIR, LOGS_DIR, STATE_DIR):
    d.mkdir(parents=True, exist_ok=True)

DEFAULT_BATCH_SIZE = 50
DEFAULT_CONCURRENCY = 4
DEFAULT_SKIP_MINUTES = 60
MAX_FAILURES_PER_HOST = 5

# Classification hints
ICS_PORTS = {502, 102, 20000, 44818, 2222, 1911, 1962, 9600, 47808}  # include BACnet
PRINTER_PORTS = {9100, 631, 515, 161}
WINDOWS_HINT_PORTS = {135, 139, 445, 3389, 5985, 5986}
LINUX_HINT_PORTS = {22, 111, 2049}
NETWORK_DEVICE_HINT_PORTS = {23, 161, 162, 179}

# Risk weights
RISK_WEIGHTS = {
    23: 6,     # Telnet
    445: 5,    # SMB
    3389: 4,   # RDP
    22: 3,     # SSH
    21: 3,     # FTP
    80: 2,     # HTTP
    443: 1,    # HTTPS
    161: 3,    # SNMP
}

# Safe NSE allowlist (NO vuln/exploit/unsafe categories)
SAFE_NSE = {
    "baseline": ["default", "safe", "discovery"],
    "ssl": ["ssl-cert", "ssl-enum-ciphers"],
    "smb": ["smb-os-discovery", "smb-security-mode", "smb-protocols", "smb2-security-mode", "smb2-capabilities"],
    "ad": ["ldap-rootdse", "ldap-search"],
    "web": ["http-title", "http-server-header"],
}

PORT_OPEN_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\b", re.IGNORECASE)

# ------------------------- State -------------------------

FAIL_STATE_FILE = STATE_DIR / "failures.json"
RECENT_STATE_FILE = STATE_DIR / "recent_scans.json"

def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def failures_for(host):
    st = _load_json(FAIL_STATE_FILE, {})
    return int(st.get(host, 0))

def record_failure(host):
    st = _load_json(FAIL_STATE_FILE, {})
    st[host] = int(st.get(host, 0)) + 1
    _save_json(FAIL_STATE_FILE, st)

def clear_failure(host):
    st = _load_json(FAIL_STATE_FILE, {})
    if host in st:
        st.pop(host)
        _save_json(FAIL_STATE_FILE, st)

def record_scan_time(host):
    st = _load_json(RECENT_STATE_FILE, {})
    st[host] = time.time()
    _save_json(RECENT_STATE_FILE, st)

def scanned_recently(host, minutes):
    if minutes <= 0:
        return False
    st = _load_json(RECENT_STATE_FILE, {})
    ts = st.get(host)
    if not ts:
        return False
    return (time.time() - float(ts)) < (minutes * 60)

# ------------------------- Models -------------------------

@dataclass
class HostResult:
    host: str
    timestamp: str
    scan_type: str
    ports_open: list
    os_lines: list
    service_lines: list
    asset_type: str
    risk_score: int
    risk_level: str
    findings: list
    out_base: str
    notes: list
    filtered_ratio_hint: float
    subnet: str

# ------------------------- UI helpers -------------------------

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    art = r"""
 ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ██████╗ ██████╗  ██████╗ 
 ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗
 ██╔██╗ ██║██╔████╔██║███████║██████╔╝    ██████╔╝██████╔╝██║   ██║
 ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ██╔═══╝ ██╔══██╗██║   ██║
 ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ██║     ██║  ██║╚██████╔╝
 ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

    NMAP_PRO_OSS_ENTERPRISE - Hybrid IT/OT Assessment Suite (SAFE)
-------------------------------------------------------------------
- Inventory, classification, adaptive safe scanning (batch+telemetry)
- Topology & attack-graph modeling, heatmaps, HTML/TXT/CSV reports
- Scheduling + ZIP bundles + optional web dashboard UI
-------------------------------------------------------------------
"""
    if console:
        console.print(Panel.fit(art, box=box.DOUBLE))
    else:
        print(art)

def prompt_yes_no(msg, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        v = input(msg + suffix).strip().lower()
        if v == "" and default is not None:
            return default
        if v in ("y", "yes"):
            return True
        if v in ("n", "no"):
            return False
        print("Please enter y or n.")

# ------------------------- Authorization gate -------------------------

def require_authorization():
    print("\n[!] Authorization Required")
    ok = prompt_yes_no("Do you confirm you are authorized to scan these targets?", default=False)
    if not ok:
        print("Exiting (authorization not confirmed).")
        sys.exit(1)

# ------------------------- Target & option prompts (with samples + best choice) -------------------------

def get_target_type():
    print("\nTarget Type:")
    print(" 1 - Single IP       (example: 192.168.1.10)        [Best for: 1 host]")
    print(" 2 - CIDR Range      (example: 192.168.1.0/24)      [Best for: subnet discovery]")
    print(" 3 - Hostname/Domain (example: scanme.nmap.org)     [Best for: known hostnames]")
    while True:
        choice = input("Choose target type (1/2/3): ").strip()
        if choice == "1":
            ip = input("Enter IP (example: 192.168.1.10): ").strip()
            try:
                ipaddress.ip_address(ip)
                return [ip], "single", ip
            except Exception:
                print("[-] Invalid IP.")
        elif choice == "2":
            cidr = input("Enter CIDR (example: 10.10.10.0/24): ").strip()
            try:
                ipaddress.ip_network(cidr, strict=False)
                return [cidr], "cidr", cidr
            except Exception:
                print("[-] Invalid CIDR.")
        elif choice == "3":
            domain = input("Enter hostname (example: server01.corp.local): ").strip()
            try:
                socket.gethostbyname(domain)
                return [domain], "host", domain
            except Exception:
                print("[-] Domain cannot be resolved.")
        else:
            print("[-] Invalid selection.")

def get_timing():
    print("\nTiming Template:")
    print(" 1 - T1 Paranoid     (example: -T1)  [Best for: fragile/OT]")
    print(" 2 - T2 Polite       (example: -T2)  [Best for: OT_SAFE]")
    print(" 3 - T3 Normal       (example: -T3)  [Best for: most IT]")
    print(" 4 - T4 Aggressive   (example: -T4)  [Best for: small IT scopes]")
    print(" 5 - T5 Insane       (example: -T5)  [Not recommended]")
    choice = input("Select timing (default=T3): ").strip()
    timing_map = {"1": "-T1", "2": "-T2", "3": "-T3", "4": "-T4", "5": "-T5"}
    return timing_map.get(choice, "-T3")

def get_port_selection():
    print("\nPort Selection:")
    print(" 1 - Top 1000 Ports  (example: --top-ports 1000) [Best choice]")
    print(" 2 - All Ports       (example: -p-)              [High impact]")
    print(" 3 - Custom Ports    (example: -p 22,80,443)")
    choice = input("Select (default=1): ").strip() or "1"
    if choice == "2":
        return "-p-"
    if choice == "3":
        ports = input("Enter ports (example: 22,80,443 or 1-1024,3389): ").strip()
        return f"-p {ports}" if ports else "--top-ports 1000"
    return "--top-ports 1000"

def get_exclusions():
    print("\nExclusions (optional):")
    print(" Example: 192.168.1.5,192.168.1.50/32")
    exclude = input("Exclude IPs/CIDRs: ").strip()
    return f"--exclude {exclude}" if exclude else ""

def get_safety_profile():
    print("\nEnvironment Profile:")
    print(" 1 - Standard Enterprise IT")
    print(" 2 - Hybrid IT/OT SAFE MODE  [Best choice for unknown environments]")
    choice = input("Select profile (default=2): ").strip() or "2"
    if choice == "1":
        return {"name": "IT", "timing_override": None, "flags": ["--max-retries", "3", "--host-timeout", "45m"]}
    return {"name": "OT_SAFE", "timing_override": "-T2", "flags": ["--max-retries", "2", "--host-timeout", "30m"]}

def get_skip_minutes():
    print("\nSkip recently scanned hosts:")
    print(" Example: 60 (skip hosts scanned in last 60 minutes)")
    s = input(f"Minutes (default={DEFAULT_SKIP_MINUTES}): ").strip()
    if not s:
        return DEFAULT_SKIP_MINUTES
    try:
        v = int(s)
        return max(0, min(v, 24 * 60))
    except Exception:
        return DEFAULT_SKIP_MINUTES

def get_batch_size():
    print("\nBatch/Wave size (adaptive scanning):")
    print(" Example: 50  [Best choice for large environments]")
    s = input(f"Batch size (default={DEFAULT_BATCH_SIZE}): ").strip()
    if not s:
        return DEFAULT_BATCH_SIZE
    try:
        v = int(s)
        return max(10, min(v, 500))
    except Exception:
        return DEFAULT_BATCH_SIZE

def get_base_concurrency():
    print("\nBase concurrency cap (adaptive will adjust within this cap):")
    print(" Example: 4  [Best choice for large environments]")
    s = input(f"Max workers (default={DEFAULT_CONCURRENCY}): ").strip()
    if not s:
        return DEFAULT_CONCURRENCY
    try:
        v = int(s)
        return max(1, min(v, 16))
    except Exception:
        return DEFAULT_CONCURRENCY

# ------------------------- Logging -------------------------

def log_error(command, error):
    log_file = LOGS_DIR / f"scan_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("==== SCAN ERROR LOG ====\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"Command: {command}\n\n")
        f.write(str(error) + "\n")
    print(f"[!] Error logged: {log_file}")

# ------------------------- Discovery & precheck -------------------------

def nmap_ping_sweep(cidr):
    print(f"[+] Auto network discovery (ping sweep): {cidr}")
    cmd = ["nmap", "-sn", "--stats-every", "5s", cidr]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        hosts = re.findall(r"Nmap scan report for ([\d\.]+)", out)
        print(f"[✓] Live hosts found: {len(hosts)}")
        return hosts
    except subprocess.CalledProcessError as e:
        log_error(" ".join(cmd), e.output)
        return []

def write_inventory_csv(scope_label, hosts, run_folder):
    out = Path(run_folder) / "inventory.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scope", "host"])
        for h in hosts:
            w.writerow([scope_label, h])
    print(f"[✓] Inventory CSV: {out}")
    return str(out)

def light_fingerprint_ports(hosts, max_hosts=64):
    """
    Very light pre-detection:
      - Scans a small host sample with a small port list to infer device mix (PLC/ICS/IoT/printer)
      - This is a safety step; keep it low impact.
    """
    sample = hosts[:max_hosts]
    if not sample:
        return {}

    ports = "22,23,80,443,445,3389,161,9100,631,502,102,20000,44818,47808"
    results = {}

    for h in sample:
        cmd = ["nmap", "-n", "-Pn", "-p", ports, "--max-retries", "1", "--max-rate", "20", "--host-timeout", "2m", h]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            open_found = [int(p) for p in re.findall(r"^(\d+)/tcp\s+open\b", out, flags=re.M)]
            results[h] = open_found
        except Exception:
            results[h] = []
    return results

def ping_sample_metrics(hosts, samples=10):
    """
    Measures packet loss and avg RTT via system ping to a small IP sample.
    If ICMP blocked, returns pessimistic values.
    """
    sample = [h for h in hosts[:samples] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h)]
    if not sample:
        return 100.0, 9999.0

    losses = []
    rtts = []

    for h in sample:
        cmd = ["ping", "-c", "3", "-W", "1", h]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            m_loss = re.search(r"(\d+)%\s+packet loss", out)
            if m_loss:
                losses.append(float(m_loss.group(1)))
            m_rtt = re.search(r"rtt .* = [\d\.]+/([\d\.]+)/", out)
            if m_rtt:
                rtts.append(float(m_rtt.group(1)))
        except Exception:
            losses.append(100.0)

    loss = sum(losses) / max(1, len(losses))
    rtt = (sum(rtts) / len(rtts)) if rtts else 9999.0
    return loss, rtt

# ------------------------- Parsing, classification, scoring -------------------------

def parse_nmap_text(nmap_file_path):
    open_ports = []     # list[(port:int, proto, line)]
    os_lines = []
    service_lines = []
    notes = []
    filtered_lines = 0
    total_port_lines = 0

    try:
        with open(nmap_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip("\n")
                if "/tcp" in s or "/udp" in s:
                    total_port_lines += 1
                    if "filtered" in s.lower():
                        filtered_lines += 1

                m = PORT_OPEN_RE.match(s.strip())
                if m:
                    open_ports.append((int(m.group(1)), m.group(2).lower(), s.strip()))
                    service_lines.append(s.strip())

                if s.strip().startswith("Running:") or "OS details" in s or s.strip().startswith("OS CPE:"):
                    os_lines.append(s.strip())

                if any(k in s.lower() for k in ["warning", "failed", "timeout", "reset", "too many"]):
                    notes.append(s.strip())
    except FileNotFoundError:
        pass

    filtered_ratio = filtered_lines / max(1, total_port_lines)
    return open_ports, os_lines, service_lines, notes, filtered_ratio

def detect_plc_ics(open_ports, service_lines):
    ports = {p for p, _, _ in open_ports}
    svc = " ".join(service_lines).lower()
    if any(p in ICS_PORTS for p in ports):
        return True
    if any(x in svc for x in ["modbus", "dnp3", "ethernet/ip", "enip", "s7", "bacnet"]):
        return True
    return False

def classify_asset(open_ports, os_lines, service_lines):
    ports = {p for p, _, _ in open_ports}
    os_text = " ".join(os_lines).lower()
    svc_text = " ".join(service_lines).lower()

    if detect_plc_ics(open_ports, service_lines):
        return "PLC/ICS"
    if any(p in PRINTER_PORTS for p in ports) and any(x in svc_text for x in ["ipp", "jetdirect", "printer", "hp", "canon", "epson"]):
        return "Printer"
    if any(p in WINDOWS_HINT_PORTS for p in ports) or "windows" in os_text or "microsoft" in os_text:
        return "Windows"
    if any(p in LINUX_HINT_PORTS for p in ports) or any(x in os_text for x in ["linux", "ubuntu", "debian", "centos", "red hat"]):
        return "Linux"
    if any(p in NETWORK_DEVICE_HINT_PORTS for p in ports) or any(x in svc_text for x in ["cisco", "juniper", "mikrotik", "router", "switch"]):
        return "Network Device"
    if any(x in svc_text for x in ["upnp", "rtsp", "onvif", "embedded", "busybox"]):
        return "IoT"
    return "Unknown"

def attack_surface_score(open_ports):
    ports = {p for p, _, _ in open_ports}
    score = 0
    for p in ports:
        score += RISK_WEIGHTS.get(p, 0)
    if any(p in ICS_PORTS for p in ports):
        score += 8
    return score

def risk_level(score):
    if score >= 14:
        return "Critical"
    if score >= 9:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"

def exposure_findings(open_ports, service_lines):
    ports = {p for p, _, _ in open_ports}
    findings = []

    def add(sev, title, detail):
        findings.append({"severity": sev, "title": title, "detail": detail})

    if any(p in ICS_PORTS for p in ports):
        add("Critical", "Industrial protocol exposure", "ICS/OT protocol ports detected; verify segmentation and change control.")
    if 23 in ports:
        add("High", "Telnet exposed", "TCP/23 open; replace with SSH or restrict access.")
    if 445 in ports or 139 in ports:
        add("High", "SMB exposed", "SMB ports open; ensure hardening and restrict lateral movement paths.")
    if 3389 in ports:
        add("High", "RDP exposed", "TCP/3389 open; ensure MFA/NLA and restricted access.")
    if 161 in ports:
        add("Medium", "SNMP exposed", "UDP/161 open; ensure SNMPv3 and restrict access.")
    if 80 in ports and 443 not in ports:
        add("Medium", "HTTP without HTTPS", "TCP/80 open while 443 absent; validate encryption requirements.")
    if 21 in ports:
        add("Medium", "FTP exposed", "TCP/21 open; prefer SFTP/FTPS and restrict auth.")
    if not findings:
        add("Info", "No high-risk exposures detected", "No common high-risk ports found in this scan scope.")

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 9))
    return findings

def ip_to_subnet24(ip):
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return "unknown"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"

# ------------------------- Adaptive controller (batch+telemetry) -------------------------

def device_mix_from_precheck(precheck_ports_map):
    mix = {"Windows": 0, "Linux": 0, "Network Device": 0, "IoT": 0, "Printer": 0, "PLC/ICS": 0, "Unknown": 0}
    for _, ports in precheck_ports_map.items():
        asset = classify_asset([(p, "tcp", "") for p in ports], [], [])
        mix[asset] = mix.get(asset, 0) + 1
    return mix

def recommend_rate_and_concurrency(host_count, loss_pct, rtt_ms, safety_profile, device_mix, firewall_hint):
    """
    Adaptive scan control:
      - Higher loss/latency => lower rate & concurrency
      - OT_SAFE clamps more
      - PLC/ICS presence => very conservative
      - Firewall filtering hint => reduce rate & concurrency a bit (avoid state-table stress)
    """
    # base from size
    if host_count < 50:
        base_rate = 200
        base_conc = 6
    elif host_count < 200:
        base_rate = 120
        base_conc = 4
    elif host_count < 1000:
        base_rate = 60
        base_conc = 3
    else:
        base_rate = 30
        base_conc = 2

    # OT clamps
    if safety_profile["name"] == "OT_SAFE":
        base_rate = min(base_rate, 50)
        base_conc = min(base_conc, 3)

    # loss/latency adjustments
    if loss_pct >= 30 or rtt_ms >= 250:
        base_rate = max(8, int(base_rate * 0.5))
        base_conc = max(1, int(base_conc * 0.5))
    elif loss_pct >= 10 or rtt_ms >= 120:
        base_rate = max(10, int(base_rate * 0.7))
        base_conc = max(1, int(base_conc * 0.7))

    # device mix adjustments
    if device_mix.get("PLC/ICS", 0) > 0:
        base_rate = max(5, int(base_rate * 0.5))
        base_conc = max(1, int(base_conc * 0.5))
    if device_mix.get("IoT", 0) >= 5 or device_mix.get("Printer", 0) >= 5:
        base_rate = max(8, int(base_rate * 0.7))
        base_conc = max(1, int(base_conc * 0.8))

    # firewall filtering hint
    if firewall_hint >= 0.6:
        base_rate = max(8, int(base_rate * 0.7))
        base_conc = max(1, int(base_conc * 0.8))
    elif firewall_hint >= 0.3:
        base_rate = max(10, int(base_rate * 0.85))

    return base_rate, base_conc

def split_batches(hosts, batch_size):
    return [hosts[i:i+batch_size] for i in range(0, len(hosts), batch_size)]

# ------------------------- Nmap command helpers + runner (real-time output) -------------------------

def timestamped_out_base(prefix, target):
    ts = int(time.time())
    clean = target.replace(".", "_").replace("/", "_").replace(":", "_")
    return str(SCANS_DIR / f"{prefix}_{clean}_{ts}")

def build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate):
    cmd = ["nmap", "-vv", "--stats-every", "5s"]

    if safety_profile["timing_override"]:
        cmd.append(safety_profile["timing_override"])
    else:
        cmd.append(timing)

    cmd.extend(safety_profile["flags"])
    cmd += ["--max-rate", str(max_rate)]

    if exclude_flag:
        cmd.extend(exclude_flag.split())
    return cmd

def build_nse_args(module, enable, blocked=False):
    if not enable or blocked:
        return []
    scripts = SAFE_NSE.get(module, [])
    if not scripts:
        return []
    return ["--script", ",".join(scripts)]

def run_scan_stream(cmd, out_base):
    cmd_str = " ".join(cmd)
    print(f"\n[+] Running:\n{cmd_str}\n")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line.rstrip())
        rc = proc.wait()
        if rc != 0:
            log_error(cmd_str, f"Non-zero exit code: {rc}")
            return False
        try:
            shutil.copy(out_base + ".nmap", out_base + ".txt")
        except Exception:
            pass
        return True
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        try:
            proc.terminate()
        except Exception:
            pass
        log_error(cmd_str, "Interrupted by user")
        return False
    except Exception as e:
        log_error(cmd_str, str(e))
        return False

# ------------------------- Scan modules (menu options) -------------------------

def assemble_result(host, scan_type, out_base):
    open_ports, os_lines, service_lines, notes, filtered_ratio = parse_nmap_text(out_base + ".nmap")
    asset = classify_asset(open_ports, os_lines, service_lines)
    score = attack_surface_score(open_ports)
    level = risk_level(score)
    findings = exposure_findings(open_ports, service_lines)
    ts = datetime.now().isoformat(timespec="seconds")
    subnet = ip_to_subnet24(host)

    return HostResult(
        host=host,
        timestamp=ts,
        scan_type=scan_type,
        ports_open=[ln for _, _, ln in open_ports],
        os_lines=os_lines,
        service_lines=service_lines,
        asset_type=asset,
        risk_score=score,
        risk_level=level,
        findings=findings,
        out_base=out_base,
        notes=notes,
        filtered_ratio_hint=filtered_ratio,
        subnet=subnet
    )

def scan_exposure_assessment(target, timing, safety_profile, ports_flag, exclude_flag, max_rate, enable_scripts, allow_ics_override):
    """
    Menu 1 "Vulnerability Scan" (SAFE) => Exposure Assessment.
    Two-pass:
      - baseline scan
      - optional SAFE NSE allowlist pass if not PLC/ICS (or override)
    """
    out_base = timestamped_out_base("exposure", target)
    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-sS", "-sV", "--version-light", "--version-intensity", "2"]
    cmd += ports_flag.split()
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None

    res = assemble_result(target, "Exposure Assessment", out_base)
    is_ics = (res.asset_type == "PLC/ICS") or detect_plc_ics(
        [(int(re.match(r"^(\d+)/", s).group(1)), "tcp", "") for s in res.ports_open if re.match(r"^(\d+)/", s)],
        res.service_lines
    )

    if enable_scripts:
        if is_ics and not allow_ics_override:
            print("[!] PLC/ICS suspected. SAFE scripts blocked (override not enabled).")
            return res

        out_base2 = timestamped_out_base("exposure_scripts", target)
        cmd2 = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
        cmd2 += ["-sS", "-sV", "--version-light", "--version-intensity", "2"]
        cmd2 += ports_flag.split()
        cmd2 += build_nse_args("baseline", enable=True, blocked=False)
        cmd2 += ["-oA", out_base2, target]
        run_scan_stream(cmd2, out_base2)
        return assemble_result(target, "Exposure Assessment", out_base2)

    return res

def scan_tcp_udp(target, timing, safety_profile, ports_flag, exclude_flag, max_rate):
    if safety_profile["name"] == "OT_SAFE":
        print("\n[!] OT_SAFE: UDP scanning can be disruptive.")
        if not prompt_yes_no("Proceed with UDP scan anyway?", default=False):
            return None
    out_base = timestamped_out_base("tcp_udp", target)
    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-sS", "-sU", "-sV", "--version-light", "--version-intensity", "2"]
    cmd += ports_flag.split()
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None
    return assemble_result(target, "Full TCP+UDP", out_base)

def scan_os_smb(target, timing, safety_profile, ports_flag, exclude_flag, max_rate):
    if safety_profile["name"] == "OT_SAFE":
        print("\n[!] OT_SAFE: OS detection can stress fragile stacks.")
        if not prompt_yes_no("Proceed with OS detection?", default=False):
            return None
    out_base = timestamped_out_base("os_smb", target)
    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-O", "--osscan-guess", "-sS", "-sV", "--version-light", "--version-intensity", "2"]
    cmd += ports_flag.split()
    # Keep scripts conservative; SMB fingerprinting is a user choice
    if prompt_yes_no("Add SMB OS discovery script (SAFE) if SMB ports present?", default=False):
        cmd += ["--script", "smb-os-discovery"]
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None
    return assemble_result(target, "OS + SMB Fingerprinting", out_base)

def scan_malware_ad(target, timing, safety_profile, ports_flag, exclude_flag, max_rate, allow_ics_override):
    """
    Menu 4 combines malware indicator (opt-in) + AD safe allowlist (opt-in).
    """
    if safety_profile["name"] == "OT_SAFE":
        print("\n[!] OT_SAFE: scripts may be noisy. Use caution.")
        if not prompt_yes_no("Proceed with this combined scan?", default=False):
            return None

    enable_malware = prompt_yes_no("Enable malware NSE script (opt-in)?", default=False)
    enable_ad = prompt_yes_no("Enable safe AD scripts (ldap-rootdse/ldap-search)?", default=False)

    # First baseline pass to classify and detect ICS
    out_base = timestamped_out_base("malware_ad_base", target)
    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-sS", "-sV", "--version-light", "--version-intensity", "2"]
    cmd += ports_flag.split()
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None

    res = assemble_result(target, "Malware+AD (baseline)", out_base)
    if res.asset_type == "PLC/ICS" and not allow_ics_override and (enable_malware or enable_ad):
        print("[!] PLC/ICS suspected. Scripts blocked unless override enabled.")
        return res

    # Optional script pass
    if enable_malware or enable_ad:
        out_base2 = timestamped_out_base("malware_ad_scripts", target)
        cmd2 = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
        cmd2 += ["-sS", "-sV", "--version-light", "--version-intensity", "2"]
        cmd2 += ports_flag.split()
        if enable_malware:
            cmd2 += ["--script", "malware"]
        if enable_ad:
            cmd2 += build_nse_args("ad", enable=True, blocked=False)
        cmd2 += ["-oA", out_base2, target]
        run_scan_stream(cmd2, out_base2)
        return assemble_result(target, "Malware+AD (scripts)", out_base2)

    return res

def scan_full_combo(target, timing, safety_profile, ports_flag, exclude_flag, max_rate, allow_ics_override):
    """
    Menu 6 Full Combo (SAFE) = Exposure Assessment + optional safe baseline scripts.
    """
    enable_scripts = prompt_yes_no("Enable SAFE allowlisted scripts? (recommended in IT)", default=(safety_profile["name"] != "OT_SAFE"))
    return scan_exposure_assessment(target, timing, safety_profile, ports_flag, exclude_flag, max_rate, enable_scripts, allow_ics_override)

def scan_ssl(target, timing, safety_profile, exclude_flag, max_rate):
    out_base = timestamped_out_base("ssl", target)
    print("\nTLS Port:")
    print(" Example: 443  [Best choice]")
    port = input("Enter TLS port (default 443): ").strip() or "443"
    include_ciphers = prompt_yes_no("Include ssl-enum-ciphers (slower)?", default=False)

    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-p", port, "-sS"]
    cmd += ["--script", "ssl-cert,ssl-enum-ciphers" if include_ciphers else "ssl-cert"]
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None
    return assemble_result(target, "SSL/TLS Certificate", out_base)

def scan_smb_deep(target, timing, safety_profile, exclude_flag, max_rate, allow_ics_override):
    """
    Menu 8 SMB Deep Scan (SAFE allowlist only).
    """
    out_base = timestamped_out_base("smb", target)
    cmd = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd += ["-sS", "-p", "445", "-sV", "--version-light", "--version-intensity", "2"]
    cmd += ["-oA", out_base, target]
    if not run_scan_stream(cmd, out_base):
        return None

    res = assemble_result(target, "SMB Deep (baseline)", out_base)
    if res.asset_type == "PLC/ICS" and not allow_ics_override:
        print("[!] PLC/ICS suspected. SMB scripts blocked unless override enabled.")
        return res

    out_base2 = timestamped_out_base("smb_scripts", target)
    cmd2 = build_base_nmap_cmd(timing, safety_profile, exclude_flag, max_rate)
    cmd2 += ["-sS", "-p", "445", "-sV", "--version-light", "--version-intensity", "2"]
    cmd2 += build_nse_args("smb", enable=True, blocked=False)
    cmd2 += ["-oA", out_base2, target]
    run_scan_stream(cmd2, out_base2)
    return assemble_result(target, "SMB Deep (scripts)", out_base2)

# ------------------------- Reports: TXT/CSV/HTML + graphs -------------------------

def write_host_summary_txt(run_folder, result: HostResult):
    safe_host = result.host.replace("/", "_")
    path = Path(run_folder) / f"{safe_host}_summary.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("==== Nmap Pro OSS Enterprise Summary ====\n")
        f.write(f"Timestamp: {result.timestamp}\n")
        f.write(f"Host: {result.host}\n")
        f.write(f"Subnet: {result.subnet}\n")
        f.write(f"Scan Type: {result.scan_type}\n")
        f.write(f"Asset Type: {result.asset_type}\n")
        f.write(f"Risk: {result.risk_level} ({result.risk_score})\n")
        f.write(f"Filtered Ratio Hint: {result.filtered_ratio_hint:.2f}\n\n")

        f.write(">> Open Ports:\n")
        f.write("\n".join(result.ports_open) + "\n\n")

        f.write(">> OS Lines:\n")
        f.write("\n".join(result.os_lines) + "\n\n")

        f.write(">> Findings (ranked):\n")
        for item in result.findings:
            f.write(f"- [{item['severity']}] {item['title']}: {item['detail']}\n")

        if result.notes:
            f.write("\n>> Notes:\n")
            f.write("\n".join(result.notes) + "\n")
    return str(path)

def append_hosts_csv(run_folder, result: HostResult):
    path = Path(run_folder) / "hosts.csv"
    exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["timestamp","host","subnet","scan_type","asset_type","risk_level","risk_score","open_ports_count","filtered_ratio_hint","out_base"])
        w.writerow([result.timestamp, result.host, result.subnet, result.scan_type, result.asset_type,
                    result.risk_level, result.risk_score, len(result.ports_open),
                    f"{result.filtered_ratio_hint:.2f}", result.out_base])
    return str(path)

def append_findings_csv(run_folder, result: HostResult):
    path = Path(run_folder) / "findings.csv"
    exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["timestamp","host","subnet","scan_type","asset_type","risk_level","risk_score","severity","title","detail"])
        for item in result.findings:
            w.writerow([result.timestamp, result.host, result.subnet, result.scan_type, result.asset_type,
                        result.risk_level, result.risk_score, item["severity"], item["title"], item["detail"]])
    return str(path)

def compute_subnet_scores(results):
    """
    Attack surface per subnet = sum of host risk scores (simple, effective).
    """
    scores = {}
    for r in results:
        scores[r.subnet] = scores.get(r.subnet, 0) + int(r.risk_score)
    # sorted list
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return ranked

def write_subnet_scores_csv(run_folder, subnet_ranked):
    path = Path(run_folder) / "subnet_scores.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subnet","attack_surface_score"])
        for subnet, score in subnet_ranked:
            w.writerow([subnet, score])
    return str(path)

def show_terminal_dashboard(results):
    if not console:
        return
    table = Table(title="Nmap Pro OSS Enterprise - Results", box=box.SIMPLE_HEAVY)
    table.add_column("Host", style="bold")
    table.add_column("Subnet")
    table.add_column("Class")
    table.add_column("Risk")
    table.add_column("Open Ports")
    table.add_column("Top Finding")
    for r in results:
        top = r.findings[0]["title"] if r.findings else "-"
        table.add_row(r.host, r.subnet, r.asset_type, f"{r.risk_level} ({r.risk_score})", str(len(r.ports_open)), top)
    console.print(table)

def build_topology_graph(results):
    """
    Topology visualization:
      - subnet nodes connect to host nodes (simple but very useful at scale)
    """
    if nx is None:
        return None
    G = nx.Graph()
    for r in results:
        subnet = r.subnet
        G.add_node(subnet, kind="subnet")
        G.add_node(r.host, kind="host", asset=r.asset_type, risk=r.risk_score)
        G.add_edge(subnet, r.host)
    return G

def draw_graph_png(G, out_png, title):
    if nx is None or plt is None or G is None:
        return None
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42)

    # draw all nodes (default styling)
    nx.draw(G, pos, with_labels=True, node_size=600)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()
    return str(out_png)

def build_risk_heatmap_png(results, out_png):
    if plt is None:
        return None
    sorted_r = sorted(results, key=lambda x: x.risk_score, reverse=True)
    hosts = [r.host for r in sorted_r]
    scores = [r.risk_score for r in sorted_r]
    if not hosts:
        return None
    data = [scores]
    plt.figure(figsize=(max(8, len(hosts) * 0.6), 2.8))
    plt.imshow(data, aspect="auto")
    plt.yticks([])
    plt.xticks(range(len(hosts)), hosts, rotation=90)
    plt.title("Risk Heatmap (Attack Surface Score)")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()
    return str(out_png)

def build_attack_graph(results):
    """
    Graph-based attack modeling (safe):
      - hosts connect to capability nodes based on exposed services
      - This is NOT exploitation; it models potential access paths for analyst review.
    """
    if nx is None:
        return None

    G = nx.Graph()
    # capability nodes
    caps = ["SMB_Lateral", "RDP_Remote", "SSH_Remote", "SNMP_Exposure", "Telnet_Exposure", "ICS_Exposure", "Web_Surface"]
    for c in caps:
        G.add_node(c, kind="capability")

    for r in results:
        G.add_node(r.host, kind="host", asset=r.asset_type, risk=r.risk_score)

        ports = set()
        for line in r.ports_open:
            m = re.match(r"^(\d+)/(tcp|udp)\s+open", line)
            if m:
                ports.add(int(m.group(1)))

        if 445 in ports or 139 in ports:
            G.add_edge(r.host, "SMB_Lateral")
        if 3389 in ports:
            G.add_edge(r.host, "RDP_Remote")
        if 22 in ports:
            G.add_edge(r.host, "SSH_Remote")
        if 161 in ports:
            G.add_edge(r.host, "SNMP_Exposure")
        if 23 in ports:
            G.add_edge(r.host, "Telnet_Exposure")
        if any(p in ICS_PORTS for p in ports) or r.asset_type == "PLC/ICS":
            G.add_edge(r.host, "ICS_Exposure")
        if 80 in ports or 443 in ports:
            G.add_edge(r.host, "Web_Surface")

    return G

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Nmap Pro OSS Enterprise - {{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 18px; }
    .meta { color: #333; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; }
    th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
    th { background: #f2f2f2; }
    .Critical, .High { font-weight: bold; }
    pre { margin: 0; white-space: pre-wrap; }
  </style>
</head>
<body>
<h1>Nmap Pro OSS Enterprise Report</h1>
<div class="meta">
  <div><b>Title:</b> {{ title }}</div>
  <div><b>Generated:</b> {{ generated }}</div>
  <div><b>Scope:</b> {{ scope }}</div>
  <div><b>Adaptive per-wave:</b> batch={{ batch_size }}, base_concurrency={{ base_concurrency }}</div>
</div>

<h2>Subnet Attack Surface Ranking</h2>
<table>
  <tr><th>Subnet</th><th>Attack Surface Score</th></tr>
  {% for s in subnet_scores %}
  <tr><td>{{ s.subnet }}</td><td>{{ s.score }}</td></tr>
  {% endfor %}
</table>

<h2>Host Summary</h2>
<table>
  <tr><th>Host</th><th>Subnet</th><th>Scan</th><th>Class</th><th>Risk</th><th>Open Ports</th><th>Top Findings</th></tr>
  {% for h in hosts %}
  <tr>
    <td>{{ h.host }}</td>
    <td>{{ h.subnet }}</td>
    <td>{{ h.scan_type }}</td>
    <td>{{ h.asset_type }}</td>
    <td class="{{ h.risk_level }}">{{ h.risk_level }} ({{ h.risk_score }})</td>
    <td><pre>{{ h.ports_open }}</pre></td>
    <td>
      {% for f in h.findings %}
        <div class="{{ f.severity }}">[{{ f.severity }}] {{ f.title }}</div>
      {% endfor %}
    </td>
  </tr>
  {% endfor %}
</table>

<h2>Findings (All)</h2>
<table>
  <tr><th>Host</th><th>Subnet</th><th>Severity</th><th>Title</th><th>Detail</th></tr>
  {% for f in all_findings %}
  <tr>
    <td>{{ f.host }}</td>
    <td>{{ f.subnet }}</td>
    <td class="{{ f.severity }}">{{ f.severity }}</td>
    <td>{{ f.title }}</td>
    <td>{{ f.detail }}</td>
  </tr>
  {% endfor %}
</table>

{% if topology_png %}
<h2>Topology Map</h2>
<img src="{{ topology_png }}" style="max-width: 100%;">
{% endif %}

{% if heatmap_png %}
<h2>Risk Heatmap</h2>
<img src="{{ heatmap_png }}" style="max-width: 100%;">
{% endif %}

{% if attack_graph_png %}
<h2>Attack Graph Model</h2>
<img src="{{ attack_graph_png }}" style="max-width: 100%;">
{% endif %}

</body>
</html>
"""

def write_html_dashboard(run_folder, scope_label, run_id, results, subnet_ranked, batch_size, base_concurrency,
                        topology_png=None, heatmap_png=None, attack_graph_png=None):
    if Template is None:
        print("[!] Jinja2 not available. Skipping HTML dashboard.")
        return None

    all_findings = []
    for r in results:
        for f in r.findings:
            all_findings.append({"host": r.host, "subnet": r.subnet, "severity": f["severity"], "title": f["title"], "detail": f["detail"]})

    html_path = Path(run_folder) / f"dashboard_{scope_label.replace('/','_')}_{run_id}.html"
    t = Template(HTML_TEMPLATE)
    html = t.render(
        title=f"{scope_label} / Run {run_id}",
        generated=str(datetime.now()),
        scope=scope_label,
        batch_size=batch_size,
        base_concurrency=base_concurrency,
        subnet_scores=[{"subnet": s, "score": sc} for s, sc in subnet_ranked],
        hosts=[{
            "host": r.host,
            "subnet": r.subnet,
            "scan_type": r.scan_type,
            "asset_type": r.asset_type,
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "ports_open": "\n".join(r.ports_open)[:3000],
            "findings": r.findings[:8],
        } for r in results],
        all_findings=all_findings,
        topology_png=topology_png,
        heatmap_png=heatmap_png,
        attack_graph_png=attack_graph_png
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] HTML dashboard: {html_path}")
    return str(html_path)

def zip_run_bundle(run_folder):
    zip_path = Path(str(run_folder) + ".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(run_folder):
            for fn in files:
                fp = Path(root) / fn
                z.write(fp, arcname=str(fp.relative_to(run_folder)))
    print(f"[✓] Run ZIP bundle: {zip_path}")
    return str(zip_path)

# ------------------------- Web dashboard -------------------------

def start_web_dashboard(run_folder, port=5000):
    if Flask is None or render_template_string is None or send_from_directory is None:
        print("[!] Flask not available; cannot start web dashboard.")
        return
    app = Flask(__name__)

    @app.route("/")
    def index():
        items = sorted([p.name for p in Path(run_folder).glob("*.html")], reverse=True)
        page = """
        <h1>Nmap Pro OSS Enterprise - Web Dashboard</h1>
        <p>Run folder: {{ folder }}</p>
        <ul>
        {% for i in items %}
          <li><a href="/report/{{ i }}">{{ i }}</a></li>
        {% endfor %}
        </ul>
        """
        return render_template_string(page, items=items, folder=str(run_folder))

    @app.route("/report/<path:filename>")
    def report(filename):
        return send_from_directory(str(run_folder), filename)

    print(f"[+] Web UI: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)

# ------------------------- Scheduling -------------------------

def parse_datetime_prompt():
    print("\nSchedule date & time")
    print(" Example date: 2026-04-10")
    print(" Example time: 23:30")
    d = input("Enter date (YYYY-MM-DD): ").strip()
    t = input("Enter time (HH:MM, 24h): ").strip()
    return datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M")

def schedule_flow(run_callable):
    print("\nScheduling:")
    print(" 1 - Run once now                             [Best choice]")
    print(" 2 - Run once at specific date/time           (example: 2026-04-10 23:30)")
    print(" 3 - Daily at a chosen time                   (example: 02:00)")
    print(" 4 - Weekly at a chosen time                  (example: 02:00)")
    print(" 5 - Monthly at a chosen time                 (example: 02:00)")
    choice = input("Select option (default=1): ").strip() or "1"

    if choice == "1":
        run_callable()
        return

    if choice == "2":
        dt = parse_datetime_prompt()
        while datetime.now() < dt:
            remaining = dt - datetime.now()
            print(f"[i] Scheduled in: {str(remaining).split('.')[0]}")
            time.sleep(30)
        run_callable()
        return

    print("\nChoose time of day for recurring schedule.")
    print(" Example time: 02:00 (2 AM)")
    time_str = input("Enter time (HH:MM, 24h): ").strip()
    at_time = datetime.strptime(time_str, "%H:%M").time()

    def next_occurrence(days):
        now = datetime.now()
        candidate = datetime.combine(now.date(), at_time)
        if candidate <= now:
            candidate += timedelta(days=days)
        return candidate

    while True:
        if choice == "3":
            dt = next_occurrence(1)
        elif choice == "4":
            dt = next_occurrence(7)
        elif choice == "5":
            dt = next_occurrence(30)
        else:
            print("Invalid schedule option; running once.")
            run_callable()
            return

        print(f"[+] Next run scheduled for: {dt}")
        while datetime.now() < dt:
            remaining = dt - datetime.now()
            print(f"[i] Scheduled in: {str(remaining).split('.')[0]}")
            time.sleep(60)
        run_callable()

# ------------------------- Main orchestration (batch waves + adaptive mid-run) -------------------------

def run_scan_suite(menu_choice):
    targets, ttype, scope_label = get_target_type()

    timing = get_timing()
    safety_profile = get_safety_profile()
    skip_minutes = get_skip_minutes()
    batch_size = get_batch_size()
    base_concurrency = get_base_concurrency()

    ports_flag = ""
    exclude_flag = ""
    if menu_choice in ("1","2","3","4","5","6"):
        ports_flag = get_port_selection()
        exclude_flag = get_exclusions()
        if safety_profile["name"] == "OT_SAFE" and ports_flag.strip() == "-p-":
            print("\n[!] OT_SAFE: all-ports scanning can be disruptive.")
            if not prompt_yes_no("Continue anyway?", default=False):
                ports_flag = "--top-ports 1000"

    allow_ics_override = prompt_yes_no(
        "\nIf PLC/ICS is detected, allow scripts anyway? (NOT recommended)", default=False
    )

    # Expand CIDR into discovered hosts
    host_list = []
    if ttype == "cidr":
        host_list = nmap_ping_sweep(targets[0])
    else:
        host_list = targets

    if not host_list:
        print("[-] No targets to scan.")
        return

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_folder = REPORTS_DIR / f"run_{scope_label.replace('/','_')}_{run_id}"
    run_folder.mkdir(parents=True, exist_ok=True)

    write_inventory_csv(scope_label.replace("/", "_"), host_list, run_folder)

    # Precheck: fragile device mix sample (small/low impact)
    print("\n[+] Pre-scan device mix (light fingerprint) ...")
    precheck = light_fingerprint_ports(host_list, max_hosts=min(64, len(host_list)))
    mix = device_mix_from_precheck(precheck)
    print("[i] Sampled device mix:", mix)

    # Determine script enable defaults
    enable_safe_scripts = False
    if menu_choice in ("1","6"):
        enable_safe_scripts = prompt_yes_no(
            "Enable SAFE allowlisted scripts? (recommended in IT, off by default in OT_SAFE)",
            default=(safety_profile["name"] != "OT_SAFE")
        )

    # Split into waves/batches
    batches = split_batches(host_list, batch_size)
    print(f"\n[+] Scanning in waves: batch_size={batch_size}, total_waves={len(batches)}")

    results = []

    def scan_one(host, max_rate):
        # skip logic
        if failures_for(host) >= MAX_FAILURES_PER_HOST:
            print(f"[!] Skipping {host}: exceeded {MAX_FAILURES_PER_HOST} failures.")
            return None
        if scanned_recently(host, skip_minutes):
            print(f"[i] Skipping {host}: scanned within last {skip_minutes} minutes.")
            return None

        try:
            res = None
            if menu_choice == "1":
                res = scan_exposure_assessment(host, timing, safety_profile, ports_flag, exclude_flag, max_rate, enable_safe_scripts, allow_ics_override)
            elif menu_choice == "2":
                res = scan_tcp_udp(host, timing, safety_profile, ports_flag, exclude_flag, max_rate)
            elif menu_choice == "3":
                res = scan_os_smb(host, timing, safety_profile, ports_flag, exclude_flag, max_rate)
            elif menu_choice == "4":
                res = scan_malware_ad(host, timing, safety_profile, ports_flag, exclude_flag, max_rate, allow_ics_override)
            elif menu_choice == "5":
                # not used (kept for numbering parity); treat as exposure assessment
                res = scan_exposure_assessment(host, timing, safety_profile, ports_flag, exclude_flag, max_rate, enable_safe_scripts, allow_ics_override)
            elif menu_choice == "6":
                res = scan_full_combo(host, timing, safety_profile, ports_flag, exclude_flag, max_rate, allow_ics_override)
            elif menu_choice == "7":
                res = scan_ssl(host, timing, safety_profile, exclude_flag, max_rate)
            elif menu_choice == "8":
                res = scan_smb_deep(host, timing, safety_profile, exclude_flag, max_rate, allow_ics_override)

            if res:
                clear_failure(host)
                record_scan_time(host)
            else:
                record_failure(host)
            return res

        except Exception as e:
            record_failure(host)
            log_error("scan_one", str(e))
            return None

    # Wave execution with telemetry re-measurement and adaptive adjustments
    for wave_idx, batch in enumerate(batches, start=1):
        print(f"\n========== WAVE {wave_idx}/{len(batches)} ==========")
        print(f"Targets in wave: {len(batch)} (example host: {batch[0]})")

        # Re-measure network health between waves
        loss_pct, rtt_ms = ping_sample_metrics(batch, samples=min(10, len(batch)))
        # Firewall filtering hint: use precheck emptiness as proxy (many closed/filtered)
        # Also incorporate previous wave filtered ratios (if any)
        prev_filtered_hint = 0.0
        if results:
            # last 20 results average
            tail = results[-min(20, len(results)):]
            prev_filtered_hint = sum(r.filtered_ratio_hint for r in tail) / max(1, len(tail))

        # Adaptive rate and concurrency
        max_rate, concurrency = recommend_rate_and_concurrency(
            host_count=len(batch),
            loss_pct=loss_pct,
            rtt_ms=rtt_ms,
            safety_profile=safety_profile,
            device_mix=mix,
            firewall_hint=prev_filtered_hint
        )
        # Bound concurrency by user base cap
        concurrency = min(concurrency, base_concurrency)

        print(f"[i] Wave telemetry: loss={loss_pct:.1f}% rtt={rtt_ms:.1f}ms filtered_hint={prev_filtered_hint:.2f}")
        print(f"[i] Adaptive settings: --max-rate {max_rate}, concurrency {concurrency}")

        # Emergency pause if network is very unhealthy
        if loss_pct >= 60:
            print("[!] High packet loss detected. Pausing 120 seconds before continuing...")
            time.sleep(120)

        # Run wave with concurrency
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(scan_one, h, max_rate): h for h in batch}
            for fut in as_completed(futures):
                host = futures[fut]
                try:
                    res = fut.result()
                    if not res:
                        print(f"[-] No result for {host} (skipped/failed).")
                        continue

                    results.append(res)

                    # Copy nmap artifacts into run folder
                    for ext in (".nmap", ".gnmap", ".xml", ".txt"):
                        src = Path(res.out_base + ext)
                        if src.exists():
                            shutil.copy(src, run_folder / src.name)

                    # Write reports
                    write_host_summary_txt(run_folder, res)
                    append_hosts_csv(run_folder, res)
                    append_findings_csv(run_folder, res)

                except Exception as e:
                    log_error("future_result", str(e))

    if not results:
        print("[-] No results collected.")
        return

    # Subnet attack surface ranking
    subnet_ranked = compute_subnet_scores(results)
    write_subnet_scores_csv(run_folder, subnet_ranked)

    # Terminal dashboard
    show_terminal_dashboard(results)

    # Build topology + heatmap + attack graph
    topology_png = None
    heatmap_png = None
    attack_graph_png = None

    if nx is not None and plt is not None:
        topoG = build_topology_graph(results)
        if topoG is not None:
            topology_png_path = Path(run_folder) / "topology.png"
            draw_graph_png(topoG, str(topology_png_path), "Topology (Subnet -> Host)")

        heatmap_path = Path(run_folder) / "risk_heatmap.png"
        build_risk_heatmap_png(results, str(heatmap_path))

        atkG = build_attack_graph(results)
        if atkG is not None:
            atk_png_path = Path(run_folder) / "attack_graph.png"
            draw_graph_png(atkG, str(atk_png_path), "Attack Graph (Service Capability Model)")
            # export graphml for external tools
            try:
                nx.write_graphml(atkG, str(Path(run_folder) / "attack_graph.graphml"))
            except Exception:
                pass

        topology_png = "topology.png" if (Path(run_folder) / "topology.png").exists() else None
        heatmap_png = "risk_heatmap.png" if (Path(run_folder) / "risk_heatmap.png").exists() else None
        attack_graph_png = "attack_graph.png" if (Path(run_folder) / "attack_graph.png").exists() else None

    # HTML dashboard
    write_html_dashboard(
        run_folder=run_folder,
        scope_label=scope_label,
        run_id=run_id,
        results=results,
        subnet_ranked=subnet_ranked,
        batch_size=batch_size,
        base_concurrency=base_concurrency,
        topology_png=topology_png,
        heatmap_png=heatmap_png,
        attack_graph_png=attack_graph_png
    )

    # ZIP bundle
    zip_run_bundle(run_folder)

    # Offer web dashboard
    if Flask is not None and prompt_yes_no("Start web dashboard UI now?", default=False):
        print(" Example: 5000  [Best choice]")
        port_in = input("Web UI port (default 5000): ").strip()
        port = int(port_in) if port_in.isdigit() else 5000
        start_web_dashboard(run_folder, port=port)

# ------------------------- Main Menu (as requested) -------------------------

def main_menu():
    require_authorization()

    while True:
        clear_screen()
        banner()

        print("Scan Menu:")
        print(" 1 - Vulnerability Scan (Exposure Assessment - SAFE)   [Best choice for first pass]")
        print(" 2 - Full TCP + UDP Port Scan                          [Use carefully in OT]")
        print(" 3 - OS Detection + SMB Fingerprinting                 [Confirm in OT]")
        print(" 4 - Malware Indicator + Active Directory Enumeration  [Opt-in scripts]")
        print(" 6 - Full Combo Scan (SAFE)                            [Good for IT after scoping]")
        print(" 7 - SSL/TLS Certificate Scan                          [Best for web endpoints]")
        print(" 8 - SMB Deep Scan (SAFE allowlist)                    [For Windows/SMB focus]")
        print(" 9 - Exit")
        print("\nBest practice: Start with option 1 using Top 1000 ports + OT_SAFE if environment is unknown.\n")

        choice = input("Option: ").strip()
        if choice == "9":
            print("Goodbye!")
            break
        if choice not in {"1","2","3","4","6","7","8"}:
            print("[-] Invalid choice.")
            input("Press Enter...")
            continue

        def run_callable():
            run_scan_suite(choice)

        schedule_flow(run_callable)
        input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main_menu()

 
