# KURO-I Architecture

## Overview

KURO-I is a lightweight behavioral intrusion detection daemon designed for Apache HTTP servers. The system combines deterministic rule-based detection with AI-assisted behavioral analysis to identify reconnaissance activity, exploit probing, webshell discovery, and distributed scanning behavior.

The architecture intentionally prioritizes:

* low resource usage
* transparency
* hackability
* modular correlation logic
* operational simplicity

Rather than acting as a traditional signature-only IDS, KURO-I attempts to model attacker behavior over time using temporal event correlation and subnet swarm analysis.

---

# High-Level Architecture

```text id="7q5uql"
                    ┌────────────────────┐
                    │ Apache Access Log  │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │  Safe Log Parser   │
                    └─────────┬──────────┘
                              │
             ┌────────────────┴────────────────┐
             │                                 │
             ▼                                 ▼
    ┌─────────────────┐              ┌─────────────────┐
    │ attack_buffer   │              │ subnet_tracker  │
    │ per-IP events   │              │ subnet behavior │
    └────────┬────────┘              └─────────┬───────┘
             │                                 │
             └────────────────┬────────────────┘
                              ▼
                    ┌────────────────────┐
                    │ Correlation Engine │
                    │ flush_old_events() │
                    └─────────┬──────────┘
                              │
               ┌──────────────┴──────────────┐
               │                             │
               ▼                             ▼
    ┌────────────────────┐       ┌────────────────────┐
    │ Rule-Based Engine  │       │ AI Classification  │
    │ deterministic IDS  │       │ LLM-assisted logic │
    └─────────┬──────────┘       └─────────┬──────────┘
              │                            │
              └─────────────┬──────────────┘
                            ▼
                  ┌──────────────────┐
                  │ Decision Engine  │
                  │ monitor / block  │
                  └────────┬─────────┘
                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼                                 ▼
 ┌──────────────────┐             ┌──────────────────┐
 │ ipset / firewall │             │ Telegram Control │
 │ automatic bans   │             │ remote operator  │
 └──────────────────┘             └──────────────────┘
```

---

# Core Detection Pipeline

## 1. Apache Log Ingestion

KURO-I continuously tails Apache access logs using a lightweight file follower.

Responsibilities:

* real-time monitoring
* non-blocking log consumption
* log rotation awareness
* daemon-friendly operation

Typical source:

```text id="7xln0x"
/var/log/httpd/access_log
```

or:

```text id="3w8d1h"
/var/log/apache2/access.log
```

---

# 2. Safe Request Parser

Earlier versions relied on large regular expressions for parsing Apache logs. The current architecture uses structured splitting logic to improve resilience against malformed or hostile requests.

The parser extracts:

* source IP
* HTTP method
* request path
* status code
* user-agent

Goals:

* survive malformed requests
* avoid catastrophic regex failures
* resist quote injection
* safely ignore corrupted entries

---

# 3. Event Buffers

## attack_buffer

Tracks suspicious events per individual IP.

Structure:

```python id="k31vkl"
attack_buffer[ip] = [
    {
        "path": "...",
        "method": "...",
        "status": 404,
        "timestamp": ...
    }
]
```

Used for:

* request counting
* path diversity
* temporal correlation
* recon scoring

---

## subnet_tracker

Tracks suspicious activity grouped by subnet.

IPv4:

```text id="e3qjto"
192.168.1.0/24
```

IPv6:

```text id="w06cjc"
2001:db8::/64
```

Purpose:

* detect rotating-IP scanners
* detect distributed reconnaissance
* identify swarm behavior
* correlate low-and-slow attacks

---

# 4. Correlation Engine

The main correlation logic runs periodically using:

```python id="bbjlwm"
flush_old_events()
```

instead of executing full analysis on every request.

This architecture significantly reduces CPU overhead during scan floods.

---

## Correlation Window

KURO-I uses a sliding temporal window:

```python id="ih0z9o"
WINDOW_SECONDS
```

Only recent events are analyzed.

Old events are pruned to prevent:

* memory leaks
* stale telemetry
* long-term daemon degradation

---

# Reconnaissance Scoring System

KURO-I calculates a behavioral reconnaissance score based on multiple weighted indicators.

Current indicators include:

| Signal              | Description               |
| ------------------- | ------------------------- |
| suspicious paths    | probing sensitive files   |
| unique paths        | enumeration diversity     |
| error ratios        | abnormal HTTP failures    |
| security denials    | forbidden resource access |
| scanner user-agents | offensive tooling         |
| webshell indicators | suspicious PHP access     |
| CVE patterns        | known exploit probes      |
| distributed recon   | subnet swarm behavior     |

---

# Distributed Reconnaissance Detection

One of the core architectural features of KURO-I is subnet-level behavioral correlation.

Example:

```text id="2cm2pn"
118.107.44.79
118.107.44.76
118.107.44.89
118.107.44.123
```

If multiple IPs within the same subnet probe different suspicious paths within the correlation window, the system marks the behavior as:

```text id="3knb0g"
distributed_recon
```

Detection logic:

```python id="7d0iw8"
distributed_recon = (
    unique_subnet_ips >= 5
    and unique_subnet_paths >= 3
)
```

This improves detection against:

* rotating proxies
* VPS scanner pools
* botnets
* distributed recon frameworks

---

# Rule-Based Detection Engine

KURO-I contains deterministic fallback protection independent of AI availability.

Examples:

* excessive recon score
* exploit indicators
* aggressive enumeration
* scanner tooling
* webshell signatures

This ensures detection remains operational even if:

* AI backend crashes
* inference hangs
* GPU becomes unavailable
* model timeout occurs

---

# AI-Assisted Classification

Optional LLM integration provides semantic behavioral analysis.

The AI receives structured telemetry such as:

```json id="5qj2h5"
{
  "request_count": 14,
  "unique_paths": 7,
  "distributed_recon": true,
  "scanner_detected": true,
  "recon_score": 6
}
```

The model returns:

* malicious assessment
* attack type
* confidence score
* recommended action

Typical outputs:

* scanner_recon
* malicious_recon
* exploit_attempt
* webshell_probe
* false_positive

---

# Decision Engine

Final enforcement decisions combine:

* deterministic scoring
* AI classification
* operational thresholds
* whitelist validation
* subnet correlation

Possible actions:

| Action         | Description         |
| -------------- | ------------------- |
| monitor        | telemetry only      |
| alert          | notify operator     |
| block_ip       | add IP to ipset     |
| block_subnet   | optional subnet ban |
| pending_review | manual approval     |

---

# Firewall Integration

KURO-I uses:

* ipset
* iptables
* nftables-compatible workflows

Advantages of ipset:

* kernel-level performance
* scalable blocking
* fast lookup
* efficient subnet handling

---

# Telegram Control Plane

Telegram integration provides lightweight remote administration.

Supported capabilities:

* attack notifications
* pending ban review
* subnet unban
* cache inspection
* operational monitoring
* manual approvals

Security model:

* authorized user validation
* optional chat validation
* isolated bot token

---

# State Persistence

KURO-I maintains operational state using:

* audit logs
* ban logs
* persistent cache reload
* rotating JSONL telemetry

This prevents:

* forgetting bans after restart
* duplicate enforcement
* telemetry loss

---

# Log Rotation System

KURO-I performs internal log rotation for:

* audit logs
* ban logs

Goals:

* bounded disk usage
* stable long-term operation
* manageable telemetry files

---

# Memory Management

The architecture actively prunes:

* stale IP events
* old subnet telemetry
* expired cache entries
* outdated bans

This prevents unbounded memory growth during long runtimes.

---

# IPv6 Support

Subnet correlation supports:

| Protocol | Subnet |
| -------- | ------ |
| IPv4     | /24    |
| IPv6     | /64    |

The architecture is therefore future-compatible with mixed-stack internet environments.

---

# Current Operational Flow

```text id="zof4p8"
Apache Request
    ↓
Safe Parser
    ↓
Suspicious Pattern Check
    ↓
attack_buffer update
    ↓
subnet_tracker update
    ↓
Periodic Correlation Engine
    ↓
Recon Score Calculation
    ↓
Rule Engine
    ↓
AI Classification
    ↓
Decision Engine
    ↓
ipset / Telegram / Audit Log
```

---

# Design Goals

KURO-I intentionally prioritizes:

## Lightweight Operation

Designed for:

* VPS systems
* homelabs
* small servers
* low-resource environments

---

## Transparency

Detection logic is intentionally readable and hackable.

The project favors:

* explicit heuristics
* understandable scoring
* observable telemetry

over opaque black-box behavior.

---

## Hybrid Detection

KURO-I combines:

* deterministic IDS logic
* behavioral correlation
* AI-assisted semantic reasoning

This hybrid approach improves resilience and flexibility.

---

# Future Architecture Roadmap

Planned future capabilities:

* ASN correlation
* JA3/TLS fingerprinting
* entropy-based detection
* adaptive thresholds
* Redis-backed queues
* asynchronous worker pipelines
* Prometheus metrics
* Grafana dashboards
* long-term telemetry analytics
* multi-service monitoring
* distributed agent architecture

---

# Security Considerations

KURO-I performs active network blocking.

Improper configuration may:

* block legitimate users
* affect CGNAT clients
* impact shared hosting
* trigger false positives

Recommended deployment progression:

1. monitor-only mode
2. IP auto-ban
3. subnet monitoring
4. optional subnet auto-ban

---

# Conclusion

KURO-I is a lightweight behavioral IDS focused on combining:

* temporal correlation
* subnet swarm analysis
* deterministic heuristics
* AI-assisted reasoning

into a compact and transparent defensive platform suitable for experimentation, research, and lightweight operational deployment.
