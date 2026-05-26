# Little-IDS-101 "KURO/KIMI" ~ My new kittens (May-26)

### Lightweight AI-Assisted Behavioral IDS for Apache

> Experimental behavior-based intrusion detection daemon for Apache HTTP servers using temporal correlation, subnet swarm analysis, rule heuristics, and local LLM-assisted classification.

---

# Overview

KURO-I is a lightweight Python-based IDS/IPS designed for Linux web servers running Apache. Unlike traditional log-based blocking tools that rely only on static regex rules or request counts, KURO-I attempts to correlate attacker behavior over time and classify malicious activity using both deterministic heuristics and AI-assisted analysis.

The project began as a compact AI-enhanced replacement for simple `fail2ban`-style detection, but has evolved into a small behavioral detection engine capable of identifying:

* distributed reconnaissance
* rotating-IP subnet scans
* low-and-slow probing
* webshell discovery attempts
* exploit pattern enumeration
* suspicious scanner tooling
* coordinated subnet activity

KURO-I is intentionally lightweight and suitable for:

* homelabs
* small VPS servers
* self-hosted environments
* research/testing
* educational IDS experimentation

It is **not intended as a replacement for enterprise IDS platforms** such as Suricata, Zeek, CrowdStrike, or Wazuh.

---

# Core Features

## Behavioral Detection Engine

Instead of detecting only per-IP abuse, KURO-I correlates:

* request timing
* suspicious paths
* subnet activity
* scanner behavior
* request diversity
* HTTP error ratios

This allows detection of distributed reconnaissance patterns that commonly bypass simple threshold-based banning systems.

---

## AI-Assisted Classification

KURO-I can integrate with a local LLM backend (tested with vLLM-compatible APIs) to classify suspicious activity.

The AI receives structured telemetry such as:

* recon score
* path diversity
* subnet swarm behavior
* scanner indicators
* HTTP response anomalies

and returns:

* malicious / benign assessment
* attack type
* confidence score
* recommended action

The AI layer is optional and deterministic fallback rules still operate even if the model becomes unavailable.

---

## Distributed Reconnaissance Detection

KURO-I tracks suspicious activity across multiple IPs belonging to the same subnet.

Example:

```text
118.107.44.79
118.107.44.76
118.107.44.89
118.107.44.123
```

If several IPs within a short time window probe different suspicious paths, the subnet is treated as a coordinated scanner swarm.

This is particularly effective against:

* rotating proxies
* cheap botnets
* VPS scanner pools
* low-and-slow recon

---

## CVE-Specific Pattern Detection

KURO-I supports targeted exploit heuristics.

Current examples include:

* webshell indicators
* suspicious PHP execution paths
* known exploit probes
* CVE-2026-21627-related activity
* Joomla enumeration patterns

Additional signatures can be added easily.

---

## Scanner Tool Detection

Built-in user-agent heuristics detect common offensive tooling such as:

* nuclei
* sqlmap
* masscan
* zgrab
* gobuster
* dirbuster
* nikto

---

## Telegram Integration

Optional Telegram integration allows:

* live attack notifications
* pending ban review
* remote operational monitoring
* manual approval workflows
* subnet unban commands
* cache inspection

This enables lightweight remote administration without full dashboards.

---

## Automatic Ban & Subnet Ban

KURO-I can automatically:

* block IPs via `ipset`
* optionally block suspicious subnets
* maintain persistent ban caches
* reload previous bans after restart

Subnet banning should be used carefully due to possible CGNAT or shared-network false positives.

---

## IPv6-Aware

Subnet tracking supports:

* IPv4 `/24`
* IPv6 `/64`

allowing future compatibility with mixed-stack internet traffic.

---

# Detection Philosophy

KURO-I uses layered analysis:

```text
Apache Log
    ↓
Safe Parser
    ↓
Suspicious Path Heuristics
    ↓
Temporal Correlation
    ↓
Subnet Correlation
    ↓
Recon Scoring
    ↓
Rule Engine
    ↓
AI Classification
    ↓
Ban / Monitor / Approve
```

The goal is to detect attacker behavior rather than only isolated requests.

---

# Architecture

## Main Components

| Component            | Purpose                            |
| -------------------- | ---------------------------------- |
| Apache log follower  | Real-time log ingestion            |
| Safe log parser      | Resilient request extraction       |
| attack_buffer        | Per-IP event tracking              |
| subnet_tracker       | Distributed recon tracking         |
| AI classifier        | LLM-assisted threat assessment     |
| Rule fallback engine | Deterministic emergency protection |
| ipset integration    | Fast kernel-level blocking         |
| Telegram interface   | Remote operational control         |
| Log rotation         | Long-running daemon safety         |

---

# Technologies Used

* Python 3
* Apache HTTPD
* ipset
* iptables / nftables
* Telegram Bot API
* Local LLM API (vLLM/OpenAI-compatible)
* Linux systemd

---

# Current Detection Capabilities

| Capability                  | Status       |
| --------------------------- | ------------ |
| Suspicious path detection   | Stable       |
| Webshell heuristics         | Stable       |
| Distributed recon detection | Stable       |
| Subnet swarm analysis       | Stable       |
| AI-assisted classification  | Stable       |
| IPv6 subnet support         | Experimental |
| Telegram control            | Stable       |
| ASN correlation             | Planned      |
| JA3/TLS fingerprinting      | Planned      |
| Adaptive thresholds         | Planned      |
| Async event queue           | Planned      |

---

# Example Detection

```json
{
  "service": "Apache",
  "ip": "118.107.44.79",
  "analysis": {
    "malicious": true,
    "attack_type": "distributed_recon",
    "confidence": 0.91,
    "recommended_action": "block_subnet"
  }
}
```

---

# Safety Notes

KURO-I can automatically block network traffic.

Improper configuration may:

* block legitimate users
* affect CGNAT users
* impact shared hosting traffic
* disrupt mobile carrier clients

Subnet auto-banning should be enabled cautiously.

Recommended deployment progression:

1. monitor-only mode
2. IP auto-ban
3. subnet monitor
4. optional subnet auto-ban

---

# Recommended Deployment

Suitable for:

* VPS hardening
* homelab research
* small organization edge servers
* AI-assisted security experimentation
* red/blue-team educational environments

Not recommended as sole protection for:

* enterprise production environments
* high-scale commercial hosting
* critical infrastructure

---

# Future Roadmap

Planned features include:

* ASN reputation tracking
* JA3/TLS correlation
* adaptive threat scoring
* Redis-backed event queues
* async worker pipelines
* Prometheus/Grafana metrics
* web dashboard
* entropy-based path analysis
* long-term telemetry analytics

---

# Disclaimer

KURO-I is an experimental security project.

It is provided for research, educational, and defensive purposes only.

Use at your own risk.

The author assumes no responsibility for:

* accidental blocking
* service interruption
* misclassification
* operational damage
* misuse of the software

---

# License

MIT License

---

# Author Notes

KURO-I was designed with a focus on:

* simplicity
* transparency
* hackability
* low resource usage
* behavior-oriented detection
* local AI integration

The project intentionally avoids heavyweight enterprise dependencies while exploring how lightweight behavioral correlation and local AI models can improve small-scale intrusion detection systems.

