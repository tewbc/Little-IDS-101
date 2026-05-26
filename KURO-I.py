import time
import os
import re
import json
import requests
import ipaddress
import subprocess
from collections import defaultdict
from telegram import Update

# --------------------------------

# Log paths
# EX: log path /opt/en_log
LOGFILE = "/opt/_log/ssl_access_log"
AUDIT_LOG = "/opt/_log/AI_audit.log"
BAN_LOG = "/opt/_log/AI_ban_history.jsonl"
LOG_MAX_BYTES = 20 * 1024 * 1024  # 20 MB per file
LOG_BACKUP_COUNT = 5              # 5 series copy

#Server Call signed
SERVER_CID = "SAMPLE"

# Due to Blocking in .htaccess file on top of web directory use 90 rather than 60
WINDOW_SECONDS = 90
ATTACK_THRESHOLD = 3

# Testing or Production
AUTO_BAN = True					  # True for production
BAN_CACHE_TTL = 86400 * 7

#Semi auto ban ip
pending_bans = {}
APPROVAL_MODE = False             # Set to True when AUTO_BAN is False
AUTO_BAN_TIMEOUT = 300            # If AUTO_BAN is False, It will be waited on BAN list for 3 minutes and BAN...!
LAST_UPDATE_ID = None

#Telegram connect api
BOT_TOKEN = "botAPI"
ALLOWED_ID = "userID"
CHAT_ID = "chatID"

VLLM_URL = "http://localhost:8000/v1/chat/completions"
# Qwen2.5-coder:7b for small one
MODEL_NAME = "Qwen/Qwen2.5-14B-Instruct" 

# Change 14 to faculty Digit
WHITELIST_NETWORKS = [
    "127.0.0.0/8",
    "10.72.0.0/16"                # IP safety ranges
]
    
# Start here ---------------------
# Add more critical pattern here that will skip AI analyst when recon_score >= 5

SUSPICIOUS_PATTERNS = [
    # Joomla / CMS exploits
    "plugin=tassos",
    "nrframework",
    "task=include",
    "task=download",
    "task=file",
    # WordPress
    "wp-login",
    "xmlrpc",
    # Common exposed files/tools
    "phpmyadmin",
    ".env",
    "vendor/phpunit",
    "cgi-bin",
    # Path traversal
    "opt/",
    "etc/passwd",
    "etc/shadow",
    "/proc/self/",
    "../",
    "..%2f",
    "%2e%2e",
    "%252e",
    "....//",
    # Router/IoT exploits
    "HNAP1",
    "boaform",
    # Shell / RCE
    "shell",
    "cmd=",
    # SQL Injection
    "union select",
    "select from",
    "information_schema",
    # Encoding tricks
    "base64",
    # Log4Shell (CVE-2021-44228)
    "${jndi:",
    "${${lower:",
    # Spring4Shell (CVE-2022-22965)
    "class.module.classLoader",
    "/actuator/",
    # Server-Side Template Injection (SSTI)
    "{{7*7}}",
    "${7*7}",
    "<%=",
    # Admin probing
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/.git/",
    "/.svn/",
    "/.htaccess",
    # Backup/config file leaks
    ".bak",
    ".sql",
    ".conf~",
]

#extract IP, method, path, statusCode, User-Agent
APACHE_PATTERN = re.compile(
    r'^(\S+).*?"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(.*?)\s+HTTP.*?"\s+(\d{3}).*?"([^"]*)"'
)

#For Joomla < 5.0
TASSOS_CVE_PATTERN = re.compile(
    r'option=com_ajax.*'
    r'(nrframework|tassos)',
    re.IGNORECASE
)

# Log4Shell (CVE-2021-44228) — Support varies obfuscation forms
LOG4SHELL_PATTERN = re.compile(
    r'\$\{[^\}]*jndi\s*:',
    re.IGNORECASE
)

# Spring4Shell (CVE-2022-22965)
SPRING4SHELL_PATTERN = re.compile(
    r'class\.module\.classLoader|'
    r'class\[.*\]\[.*\]\[.*\]',
    re.IGNORECASE
)

# SSTI — Server-Side Template Injection
SSTI_PATTERN = re.compile(
    r'(\{\{.*\}\}|'
    r'\$\{.*\}|'
    r'<%=.*%>)',
    re.IGNORECASE
)

# Scanner User-Agent that don't wanted
SCANNER_UA_PATTERN = re.compile(
    r'(zgrab|nuclei|masscan|shodan|'
    r'nmap|sqlmap|nikto|dirbuster|'
    r'gobuster|wfuzz|acunetix|nessus|'
    r'openvas|burpsuite)',
    re.IGNORECASE
)

# Webshell should keep away
WEBSHELL_PATTERN = re.compile(
    r"(wso|shell|alfanew|cloud|zcache|"
    r"WSOEnigma|cux|xleet|moon|"
    r"fm\.php|test\.php|wp-info)",
    re.IGNORECASE
)

# Global vars
subnet_tracker = defaultdict(list)
attack_buffer = defaultdict(list)
already_banned_cache = {}                 # Need to use timestamp so "set" is not the right form
llm_failures = 0                          # Monitor Local LLM is active?
last_llm_alert = 0                        # TimeStamp for LLM fail  

# Sub process that is in the defined format cmd in visudo for user kuro only
# action: 'ban' , 'unban'
# target: 'ip' , 'subnet'
# target_type: 'ip' , 'subnet'
def execute_ban_command(action, target, target_type, update=None):
    # ตรวจสอบสิทธิ์ update อาจเป็น None ถ้าเรียกจาก internal path
    if update is None or not hasattr(update, 'message') or update.message is None:
        return "Unauthorized: no update context"

    if str(update.message.chat_id) != str(ALLOWED_ID):
        update.message.reply_text("⛔ Unauthorized!")
        return "Unauthorized"

    if target_type == 'ip':
        if not is_valid_ip(target): 
            return "Invalid IP Format"

        # fail2ban banip / unbanip)
        cmd = ["sudo", "/usr/bin/fail2ban-client", "set", "ai-apache", f"{action}ip", target]
    else:

        # Wait for define subnet check function
        
        # ipset add / del
        ipset_action = "add" if action == "ban" else "del"
        cmd = ["sudo", "/usr/sbin/ipset", ipset_action, "blacklisted_subnets", f"{target}.0/24"]

    try:
        subprocess.run(cmd, check=True)
        
        target_display = f"{target}" if target_type == 'ip' else f"{target}.0/24"
        message = (
            "🔒 EVENT SUCCESS\n\n"
            f"Action: {action.upper()}\n"
            f"Target Type: {target_type.upper()}\n"
            f"Target: {target_display}\n"
        )
        send_telegram_to_chat(CHAT_ID, message)
        
        return f"✅ Success: {action.upper()} {target_type} -> {target_display}"

    except Exception as e:
        target_display = f"{target}" if target_type == 'ip' else f"{target}.0/24"
        message = (
            "❌ EVENT FAILED\n\n"
            f"Action: {action.upper()}\n"
            f"Target: `{target_display}`\n"
            f"Error: {str(e)}\n"
        )
        send_telegram_to_chat(CHAT_ID, message)
        
        return f"❌ Error: {str(e)}"

# Get IP for pending list with 3 minutes limited, processing IP ban
def process_pending_bans():
    now = time.time()
    expired = []

    # Process BAN, ...555
    for ip, data in (pending_bans.items()):
        age = (now - data["timestamp"])

        if (age >= AUTO_BAN_TIMEOUT):
            print(
                f"[TIMEOUT BAN] "
                f"{ip}"
            )
            ban_ip(ip)
            expired.append(ip)

    # Clear IP pending list
    for ip in expired:
        del pending_bans[ip]

# AUTO_BAN = False, System will asking command and wait for 3 miniutes, then auto ban
def request_ban_approval(ip, analysis, recon_score):

    # Listing BAN ip with timestamp and result analysis
    pending_bans[ip] = {
        "timestamp": time.time(),
        "analysis": analysis
    }

    message = (
        "🚨 HIGH RISK EVENT\n\n"
        f"IP: {ip}\n"
        f"Type: "
        f"{analysis['attack_type']}\n"
        f"Confidence: "
        f"{analysis['confidence']}\n"
        f"Recon Score: "
        f"{recon_score}\n\n"
        "Reply:\n\n"
        f"BAN:{ip}\n"
        f"IGNORE:{ip}\n\n"
        "Auto-ban in 3 minutes."
    )

    send_telegram_to_chat(CHAT_ID,message)

# -- Telegram -------------------------------------------------------------

# Telegram command check..!
def check_telegram_commands():
    global LAST_UPDATE_ID
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    params = {"timeout": 1}
    
    if LAST_UPDATE_ID:
        params["offset"] = LAST_UPDATE_ID + 1

    try:
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            if "result" in data:
                for update in data["result"]:
                    LAST_UPDATE_ID = update["update_id"]
                    
                    # Message incoming check...!
                    if "message" in update and "text" in update["message"]:
                        chat_id = update["message"]["chat"]["id"]
                        user_id = update["message"]["from"]["id"]
                        text = update["message"]["text"].strip()

                        # User, Caht ID must matched or quit
                        if str(user_id) != str(ALLOWED_ID) or str(chat_id) != str(CHAT_ID):
                            send_telegram_to_chat(chat_id, "⛔ *Unauthorized User!* You cannot control this server.")
                            continue

                        # Command extracting "/fban " or /funban 
                        if text.startswith("/fban "):
                            parts = text.split()
                            if len(parts) == 3:
                                # ip or subnet
                                target_type = parts[1].lower()
                                
                                # Value of IP or Subnet
                                target = parts[2]
                                
                                # Create class obj: update for repeated ban for execute_ban_command(.., update)
                                # For AUTO_BAN or Manual BAN
                                class MockUpdate:
                                    class MockMessage:
                                        chat_id = user_id
                                        def reply_text(self, txt):
                                            send_telegram_to_chat(chat_id, txt)
                                    message = MockMessage()

                                result_msg = execute_ban_command(action="ban", target=target, target_type=target_type, update=MockUpdate())
                                send_telegram_to_chat(chat_id, result_msg)
                                
                            else:
                                # When command through telegram 
                                send_telegram_to_chat(chat_id, "💡 Usage: `/fban ip 1.2.3.4` or `/fban subnet 1.2.3`")
                                
                        elif text.startswith("/funban "):
                            parts = text.split()
                            if len(parts) == 3:
                                target_type = parts[1].lower()
                                target = parts[2]
                                
                                class MockUpdate:
                                    class MockMessage:
                                        chat_id = user_id
                                        def reply_text(self, txt):
                                            send_telegram_to_chat(chat_id, txt)
                                    message = MockMessage()

                                result_msg = execute_ban_command(action="unban", target=target, target_type=target_type, update=MockUpdate())
                                send_telegram_to_chat(chat_id, result_msg)
    
    except Exception as e:
        print(f"[-] Telegram polling error: {e}")

# Telegram send message to chat
def send_telegram_to_chat(chat_id, message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}, timeout=5)
    except Exception as e:
        print(f"[-] Telegram reply error: {e}")

# -- LOG ------------------------------------------------------------------

# Create LOG rotatation
def rotate_log(filepath):
    # If file size overs 20MB, it will renamed its extension to .1, .2, ...
    # And delete file that is over LOG_BACKUP_COUNT
    try:
        if os.path.getsize(filepath) < LOG_MAX_BYTES:
            return

        # change old Log by incremented by 1, start with oldest first
        for i in range(LOG_BACKUP_COUNT - 1, 0, -1):
            src = f"{filepath}.{i}"
            dst = f"{filepath}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)

        # Rename LOG_name.log to .1
        os.rename(filepath, f"{filepath}.1")
        print(f"[LOG ROTATE] {filepath}")

    except Exception as e:
        print(f"[LOG ROTATE ERROR] {filepath}: {e}")

# Write audit LOG        
def write_audit_log(event):
    try:
        rotate_log(AUDIT_LOG)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print("Audit log error:", e)

# Write BAN LoG
def write_ban_log(event):
    try:
        rotate_log(BAN_LOG)
        with open(BAN_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print("Ban log error:", e)

# -- BAN ------------------------------------------------------------------

# Use to check and return as subnet format, V.4 / V.6
def get_subnet_key(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return ".".join(ip.split(".")[:3])
        else:
            return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except Exception:
        return "unknown"

# Use to check ip format, V.4 / V.6 and return the right IP format
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
        
# Subnet ban function
def ban_subnet(subnet_prefix):
    cidr = None

    try:
        test_ip = subnet_prefix.rstrip(".") + ".1"
        ip_obj = ipaddress.ip_address(test_ip)

        # IP in White list .. quit
        for net in WHITELIST_NETWORKS:
            if ip_obj in ipaddress.ip_network(net, strict=False):
                print(f"[SKIP] Subnet {subnet_prefix} is whitelisted")
                return False

        cidr = f"{subnet_prefix}.0/24"

        # Run command with defined sudo
        result = subprocess.run([
                "sudo",
                "ipset",
                "add",
                "blacklisted_subnets",
                cidr
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True
            )
        
        if result.returncode != 0:
            raise Exception(result.stderr)

        print(f"[!!!] Banned Subnet: {cidr}")
        send_telegram_to_chat(CHAT_ID, f"🛑 BANNED SUBNET: {cidr}")
        
        # Write Log for banned subnet
        write_ban_log({
            "timestamp": time.time(),
            "SubNet": cidr,
            "service": "Apache",
            "reason": "AUTO_BAN"
        })
        
        return True
        
    except Exception as e:
        cidr_display = cidr if cidr else f"{subnet_prefix}.0/24"
        print("Ban failed:", str(e))

        send_telegram_to_chat(CHAT_ID, f">❌< Failed to ban Subnet:{cidr_display}\n Error: {e}")
        return False

# IP ban
def ban_ip(ip):
    # IP in White list .. quit
    if is_whitelisted(ip) or ip in already_banned_cache:
        return False
        
    already_banned_cache[ip] = time.time()
    
    try:
        result = subprocess.run(
            [
                "sudo",
                "fail2ban-client",
                "set",
                "ai-apache",
                "banip",
                ip
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            raise Exception(
                result.stderr
            )

        print(f"[+] Banned IP: {ip}")

        send_telegram_to_chat(CHAT_ID,
            f">🛑< {ip} is BANNED\n"
        )

        write_ban_log({
            "timestamp": time.time(),
            "ip": ip,
            "service": "Apache",
            "reason": "AUTO_BAN"
        })

        return True

    except Exception as e:
        print("Ban failed:", str(e))

        send_telegram_to_chat(CHAT_ID, f">❌< Failed to ban IP:{ip}\n Error: {e}")
        return False

# Load BAN log when restart
def load_banned_cache():
    try:
        with open(BAN_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)

                    if "ip" in e:
                        already_banned_cache[e["ip"]] = e.get(
                            "timestamp",
                            time.time()
                        )

                except json.JSONDecodeError:
                    pass  # skip corrupted line

        print(
            f"[+] Ban cache loaded: "
            f"{len(already_banned_cache)} IPs"
        )

    except FileNotFoundError:
        print(
            "[+] No ban history found, "
            "starting fresh"
        )

# -- Exception list -------------------------------------------------------

# White List ^^
def is_whitelisted(ip):
    ip_obj = ipaddress.ip_address(ip)

    for network in WHITELIST_NETWORKS:

        if ip_obj in ipaddress.ip_network(network):
            return True

    return False

# Extract apache log line
def parse_apache_line(line):
    try:
        parts = line.split('"')

        if len(parts) < 3:
            return None

        # left side
        prefix = parts[0].split()

        if len(prefix) < 1:
            return None

        ip = prefix[0]

        # request section
        request = parts[1]

        req_parts = request.split()

        if len(req_parts) < 2:
            return None

        method = req_parts[0].upper()
        path = req_parts[1]

        # validate method
        allowed_methods = {
            "GET",
            "POST",
            "HEAD",
            "PUT",
            "DELETE",
            "OPTIONS",
            "PATCH"
        }

        if method not in allowed_methods:
            return None

        # status code
        suffix = parts[2].split()

        if len(suffix) < 2:
            return None

        status = int(suffix[0])

        # optional user-agent
        user_agent = ""

        if len(parts) >= 6:
            user_agent = parts[5]

        return {
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
            "user_agent": user_agent
        }

    except Exception as e:
        print(f"[PARSE ERROR] {e}")

        return None

# -- Local LLM-------------------------------------------------------------

# Yep...from A-RAG to this little one
def analyze_apache(
    ip,
    paths,
    request_count,
    unique_paths,
    error_ratio,
    recon_score,
    security_denials,
    not_found_count,
    tassos_indicator,
    distributed_recon,
    unique_subnet_ips,
    log4shell=False,
    spring4shell=False,
    ssti=False,
    scanner_ua=False
):

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": """
You are a cybersecurity detection engine.

STRICT POLICY:

Apache detection policy:

Strong malicious indicators:

- /.env
- /phpmyadmin
- /vendor/phpunit
- /cgi-bin
- /HNAP1
- /etc/passwd
- path traversal: ../, %2e%2e, %252e, ....//
- Log4Shell: ${jndi: (log4shell=true)
- Spring4Shell: class.module.classLoader (spring4shell=true)
- SSTI: {{7*7}}, ${7*7}, <%=
- Scanner tools: zgrab, nuclei, masscan, shodan (scanner_ua=true)

Behavior indicators:

- error_ratio > 0.7
- unique_paths > 6
- repeated admin probing
- repeated reconnaissance

Classification:

1. harmless browsing
   → monitor

2. suspicious probing
   → suspicious_recon

3. exploit attempts or aggressive enumeration
   → malicious_recon

4. critical exploit (log4shell/spring4shell/ssti=true)
   → critical_exploit (confidence >= 0.99, block_ip immediately)

High-risk Joomla indicators:

- option=com_ajax
- nrframework
- tassos
- unusual AJAX requests to Joomla framework plugins

Repeated requests to com_ajax with framework/plugin parameters
→ malicious_recon

Strong indicators:

- recon_score >= 4
- multiple 403 security denials
- repeated exploit path probing
- many unique suspicious paths

403 responses on protected exploit paths are strong malicious indicators.

Distributed reconnaissance from multiple IPs within the same subnet is a strong malicious indicator.
Examples:
- rotating scanners
- botnets
- proxy-based reconnaissance
- coordinated enumeration

Return ONLY JSON.

Schema:

{
  "malicious": true,
  "attack_type": "scanner_recon|malicious_recon|critical_exploit",
  "confidence": 0.95,
  "recommended_action": "monitor|block_ip",
  "reason_code": "LOW_SIGNAL|RECON|AGGRESSIVE_ENUM|LOG4SHELL|SPRING4SHELL|SSTI"
}
"""
            },
            {
                "role": "user",
                "content": json.dumps({
                    "service": "apache",
                    "ip": ip,
                    "window_seconds": WINDOW_SECONDS,
                    "request_count": request_count,
                    "unique_paths": unique_paths,
                    "error_ratio": error_ratio,
                    "recon_score": recon_score,
                    "security_denials": security_denials,
                    "not_found_count": not_found_count, 
                    "tassos_indicator": tassos_indicator,
                    "distributed_recon": distributed_recon,
                    "unique_subnet_ips": unique_subnet_ips,
                    "log4shell": log4shell,
                    "spring4shell": spring4shell,
                    "ssti": ssti,
                    "scanner_ua": scanner_ua,
                    "paths": paths[:20]
                })
            }
        ],
        "temperature": 0.0,
        "max_tokens": 120,
        "response_format": {
            "type": "json_object"
        }
    }

    try:
        response = requests.post(
            VLLM_URL,
            json=payload,
            timeout=60
        )

        result = response.json()

        return json.loads(
            result["choices"][0]
            ["message"]["content"]
        )

    except Exception as e:
        # When LLM has slept
        global llm_failures
        global last_llm_alert

        llm_failures += 1
        print(f"[LLM ERROR #{llm_failures}]", str(e))

        now = time.time()
        if now - last_llm_alert > 1800:
            send_telegram_to_chat(CHAT_ID, 
                "⚠️ vLLM Offline\n\n"
                "Qwen/vLLM unavailable.\n"
                "Running in fallback mode."
            )
            last_llm_alert = now

        return {
            "malicious": False,
            "attack_type": "unknown",
            "confidence": 0.0,
            "recommended_action": "monitor",
            "reason_code": "LLM_ERROR"
        }

# -- BAN ------------------------------------------------------------------

# read one line of apache's log a time..!
def follow(file):

    file.seek(0, 2)

    while True:
        line = file.readline()

        if not line:
            time.sleep(0.1)
            continue

        yield line

# sub process that checking line of log, analyst, scoring, alert and take action
def flush_old_events():
    now = time.time()
    expired = []

    for ip, events in attack_buffer.items():
        # If we are already waiting for a Telegram approval on this IP,
        # don't run AI analysis again. Just skip it.
        if ip in pending_bans:
            continue

        recent = [
            e for e in events if now - e["timestamp"] < WINDOW_SECONDS
        ]

        attack_buffer[ip] = recent

        if len(recent) >= ATTACK_THRESHOLD:
            recon_score = 0
            paths = [e["path"] for e in recent]

            # For specific location & file
            protected_hits = sum(
                1 for p in paths
                if any(x in p for x in [
                    "wp-login",
                    "phpmyadmin",
                    ".env",
                    "phpunit",
                    "cgi-bin",
                    "hnap1",
                    "xmlrpc"
                ])
            )
            statuses = [e["status"] for e in recent]
            request_count = len(recent)
            unique_paths = len(set(paths))
            error_ratio = round((len([s for s in statuses if s >= 400]) / request_count),2)
            tassos_indicator = any(e.get("tassos_cve", False) for e in recent)
            log4shell_indicator = any(e.get("log4shell", False) for e in recent)
            spring4shell_indicator = any(e.get("spring4shell", False) for e in recent)
            ssti_indicator = any(e.get("ssti", False) for e in recent)
            scanner_ua_indicator = any(e.get("scanner_ua", False) for e in recent)
            security_denials = len([s for s in statuses if s == 403])
            not_found_count = len([    s for s in statuses if s == 404])

            # lots of denied requests
            if (security_denials >= 2 and protected_hits >= 2):
                recon_score += 3

            # many 404s
            if not_found_count >= 3:
                recon_score += 1

            # known suspicious paths
            if unique_paths >= 3:
                recon_score += 1

            # tassos indicator
            if tassos_indicator:
                recon_score += 2

            # Log4Shell = critical
            if log4shell_indicator:
                recon_score += 5

            # Spring4Shell = critical
            if spring4shell_indicator:
                recon_score += 5

            # SSTI attempt
            if ssti_indicator:
                recon_score += 3

            # Known scanner tool
            if scanner_ua_indicator:
                recon_score += 2

            subnet = get_subnet_key(ip)
            recent_subnet = [
                e for e in subnet_tracker[subnet]
                if now - e["timestamp"] < WINDOW_SECONDS
            ]
            subnet_tracker[subnet] = recent_subnet

            unique_subnet_ips = len(
                set(e["ip"] for e in recent_subnet)
            )
            
            unique_subnet_paths = len(
                set(e["path"] for e in recent_subnet)
            )
            
            # For Slow scanner and Slow bruteforce with manay IP on the same subnet
            distributed_recon = (unique_subnet_ips >= 5 and unique_subnet_paths >= 3)
            
            if distributed_recon:
                recon_score += 3
                print(
                    f"[DISTRIBUTED RECON] "
                    f"{subnet}.0/24 "
                    f"IPs={unique_subnet_ips} "
                    f"Paths={unique_subnet_paths}"
                )
            
            if distributed_recon or (unique_subnet_ips >= 8 and request_count > 13):
                # Agressive BAN, for my case can unban later :-)
                ban_subnet(subnet)
                continue

            # recon_score >=5 no need to use LLM, Like I've done in Perl script. ><"
            if recon_score >= 5:
                print(f"[RULE-BAN] {ip} recon_score={recon_score} (bypassed LLM)")
                send_telegram_to_chat(CHAT_ID,
                    f"⚡ {SERVER_CID} RULE-BAN\n\n"
                    f"IP: {ip}\n"
                    f"Recon Score: {recon_score}\n"
                    f"Reason: High score, LLM bypassed\n"
                    f"Paths:\n{chr(10).join(paths[:5])}"
                )
                
                write_audit_log({
                    "timestamp": time.time(),
                    "service": "Apache",
                    "ip": ip,
                    "attempts": len(recent),
                    "recon_score": recon_score,
                    "analysis": {"malicious": True, "attack_type": "rule_based", "confidence": 1.0,
                                 "recommended_action": "block_ip", "reason_code": "RULE_BAN"}
                })
                ban_ip(ip)
                expired.append(ip)
                continue
            
            # LLM use for analysis
            analysis = analyze_apache(
                ip,
                paths,
                request_count,
                unique_paths,
                error_ratio,
                recon_score,
                security_denials,
                not_found_count,
                tassos_indicator,
                distributed_recon,
                unique_subnet_paths,
                log4shell=log4shell_indicator,
                spring4shell=spring4shell_indicator,
                ssti=ssti_indicator,
                scanner_ua=scanner_ua_indicator
            )
            
            # Keep audit log
            audit_event = {
                "timestamp": time.time(),
                "service": "Apache",
                "ip": ip,
                "attempts": len(recent),
                "distributed_recon": distributed_recon,
                "subnet_ips": unique_subnet_ips,
                "subnet_paths": unique_subnet_paths,
                "analysis": analysis
            }
            write_audit_log(audit_event)

            message = (
                f"🚨 {SERVER_CID} APACHE EVENT\n\n"
                f"IP: {ip}\n"
                f"Requests: {request_count}\n"
                f"Unique Paths: {unique_paths}\n"
                f"403 Denials: {security_denials}\n"
                f"404 Count: {not_found_count}\n"
                f"Recon Score: {recon_score}\n\n"
                f"Paths:\n"
                f"{chr(10).join(paths[:10])}\n\n"
                "AI VERDICT\n"
                f"Malicious: "
                f"{analysis['malicious']}\n"
                f"Type: "
                f"{analysis['attack_type']}\n"
                f"Confidence: "
                f"{analysis['confidence']}\n"
                f"Action: "
                f"{analysis['recommended_action']}"
            )

            # Telegram texting
            print("\n" + "=" * 60)
            print(message)
            send_telegram_to_chat(CHAT_ID,message)

            # AUTO_BAN:  Off=Test, On=Ban IP
            # BANNING LOGIC
            # Trust the AI verdict, but keep a safety check on confidence
            if (
                analysis["malicious"]
                and analysis["confidence"] >= 0.9
                and analysis["recommended_action"] == "block_ip"
            ):
                if APPROVAL_MODE:
                    print(f"[PENDING BAN] {ip}")
                    request_ban_approval(ip, analysis, recon_score)
                elif AUTO_BAN:
                    print(f"[AUTO BAN] {ip}")
                    ban_ip(ip)
            else:
                print(f"[MONITORING] {ip} - Did not meet ban thresholds.")

            expired.append(ip)

    # Clear data when unused
    # Prune attack_buffer — clear an IP, expired events
    for ip in expired:
        del attack_buffer[ip]

    # Prune subnet_tracker — clear a subnet, expired events
    stale_subnets = [
        subnet for subnet, events in subnet_tracker.items()
        if not any(now - e["timestamp"] < WINDOW_SECONDS for e in events)
    ]

    for subnet in stale_subnets:
        del subnet_tracker[subnet]

    if stale_subnets:
        print(f"[CLEANUP] Pruned {len(stale_subnets)} stale subnets from tracker")
    
    # Prune ban ips cache
    stale_bans = [
        ip for ip, ts
        in already_banned_cache.items()
        if now - ts > BAN_CACHE_TTL
    ]
    
    for ip in stale_bans:
        del already_banned_cache[ip]

# -- Main function --------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print( ">>> KURO-I Apache AI Monitor <<<")
    print(f"[+] Log      : {LOGFILE}")
    print(f"[+] Window   : {WINDOW_SECONDS}s")
    print(f"[+] Threshold: {ATTACK_THRESHOLD} hits")
    print(f"[+] Model    : {MODEL_NAME}")
    print(f"[+] Auto-ban : {AUTO_BAN}")
    print("=" * 60 + "\n")
    
    # Reload IP Ban from Log
    load_banned_cache()
    print(f"[+] Loaded {len(already_banned_cache)} banned IPs from history")
    
    last_telegram_check = 0
    last_flush = 0

    try:
        with open(LOGFILE, "r") as logfile:
            
            loglines = follow(logfile)

            for line in loglines:
                
                now = time.time()
                
                # Checking telegram every 5 sec
                if (now - last_telegram_check > 5):
                    check_telegram_commands()
                    process_pending_bans()

                    last_telegram_check = now
                
                # Excute suspected in here
                if (now - last_flush > 2):
                    flush_old_events()
                    last_flush = now
                        
                if line is None:
                    continue

                try:
                    try:
                        parsed = parse_apache_line(line)
                        if not parsed:
                            continue
                    
                    except Exception as e:
                        print(
                            "[PARSER ERROR]",
                            str(e)
                        )
                        continue

                    ip = parsed["ip"]
                    method = parsed["method"]
                    path = parsed["path"].lower()
                    status = parsed["status"]
                    user_agent = parsed["user_agent"]
                    
                    # Check if can skip
                    if is_whitelisted(ip) or ip in pending_bans or ip in already_banned_cache:
                        continue

                    suspicious = any(
                        x.lower() in path
                        for x in
                        SUSPICIOUS_PATTERNS
                    )

                    # For joomla extension in my website
                    legit_rstbox = (
                        "plugin=rstbox" in path
                        and "task=trackevent" in path
                        and "event=" in path
                    )
                    
                    legit_ajax_intro = (
                        "option=com_ajax" in path
                        and "module=ajax_intro_articles" in path
                        and "cmd=load" in path
                    )

                    if (legit_rstbox or legit_ajax_intro):
                        continue

                    # Webshell is coming...!
                    webshell_match = (WEBSHELL_PATTERN.search(path))
                    if webshell_match:
                        suspicious = True

                    # CVE-2026-21627 detection
                    tassos_match = (TASSOS_CVE_PATTERN.search(path))
                    if tassos_match:
                        suspicious = True
                        print(
                            "[CVE-2026-21627 "
                            "INDICATOR]",
                            path
                        )

                    # Log4Shell detection
                    log4shell_match = LOG4SHELL_PATTERN.search(path) or LOG4SHELL_PATTERN.search(user_agent)
                    if log4shell_match:
                        suspicious = True
                        print("[LOG4SHELL INDICATOR]", path[:120])

                    # Spring4Shell detection
                    spring4shell_match = SPRING4SHELL_PATTERN.search(path)
                    if spring4shell_match:
                        suspicious = True
                        print("[SPRING4SHELL INDICATOR]", path[:120])

                    # SSTI detection
                    ssti_match = SSTI_PATTERN.search(path)
                    if ssti_match:
                        suspicious = True
                        print("[SSTI INDICATOR]", path[:120])

                    # Scanner User-Agent detection
                    scanner_ua_match = SCANNER_UA_PATTERN.search(user_agent)
                    if scanner_ua_match:
                        suspicious = True
                        print(f"[SCANNER UA] {scanner_ua_match.group(0)} :: {ip}")

                    # keep suspected IP/subnet in attack_buffer and subnet_tracker
                    if suspicious:
                        event_time = time.time()
                        attack_buffer[ip].append({
                            "path": path,
                            "method": method,
                            "status": int(status),
                            "tassos_cve": bool(tassos_match),
                            "log4shell": bool(log4shell_match),
                            "spring4shell": bool(spring4shell_match),
                            "ssti": bool(ssti_match),
                            "scanner_ua": bool(scanner_ua_match),
                            "user_agent": user_agent[:200],
                            "timestamp": event_time
                        })
                    
                        subnet =  get_subnet_key(ip)
                        subnet_tracker[subnet].append({
                            "ip": ip,
                            "timestamp": event_time,
                            "path": path
                        })

                except Exception as e:

                    print(f"[MAIN LOOP ERROR] {e}")
                    time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] KURO-I stopped.")
    except FileNotFoundError:
        print(f"[FATAL] Log file not found: {LOGFILE}")

# -- Loopy ----------------------------------------------------------------
if __name__ == "__main__":
    main()
