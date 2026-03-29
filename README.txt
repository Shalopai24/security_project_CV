Security Log Analytics Engine (Python & SQL)

A professional detection engine designed to identify automated cyber attacks within authentication and API traffic logs. Built to simulate Detection Engineering workflows used in high-traffic e-commerce platforms.

Overview

This project implements two detection modes — batch analysis for forensic investigation and real-time streaming for production-grade monitoring. It identifies three critical attack patterns by analysing time-series data and behavioural anomalies.

Two Detection Modes

|           Mode            |          File        |      Use Case                                                            |
| **Batch (Pandas)**        | `analyzer.py`        | Forensic log analysis, rule development, post-incident investigation     |
| **Streaming (Real-time)** | `stream_analyzer.py` | Real-time detection with sliding windows — Kafka-compatible architecture |

analyzer.py uses Pandas 'resample()' for batch aggregation.  
stream_analyzer.py uses 'deque'-based sliding windows with alert TTL suppression — closer to how production SIEM systems work.

Key Features

- Brute Force Detection — sliding window count of failed logins per IP/user pair. Fires on first breach, suppressed for 10 minutes after (TTL).
- Credential Stuffing Detection — flags IPs attempting to authenticate as multiple unique accounts within 60 seconds (indicative of leaked database testing).
- Bot Activity Detection — detects high-frequency API requests by IP/User-Agent/endpoint clustering. Uses `deque` in streaming mode for O(1) eviction.
- Alert TTL Suppression — prevents alert spam: once an IP is flagged, cooldown window applies before re-alerting.
- Input Validation — both engines validate required columns and handle malformed timestamps gracefully.

## Detection Logic

| Attack Type         |             Logic                       | Threshold        |
| Brute Force         | Failed logins per IP/User in 60s window | > 5 attempts     |
| Credential Stuffing | Unique users per IP in 60s window       | > 5 unique users |
| Bot Traffic         | Requests per IP/endpoint in 60s window  | > 20 requests    |

All thresholds are configurable in the `Config` section of each file.

Tech Stack

- Python — Pandas (time-series resampling, rolling windows), `collections.deque` (streaming state)
- SQL — Window Functions (`LAG`, `LEAD`, `PARTITION BY`), CTEs — scalable implementation for Big Data environments
- Concepts — Sliding window analysis, alert suppression (TTL), anomaly detection, false positive minimisation

Project Structure
security_project_CV/
├── analyzer.py           # Batch engine — Pandas, resample(), forensic analysis
├── stream_analyzer.py    # Streaming engine — deque, real-time, TTL suppression
├── sql/
│   ├── brute_force.sql        # LAG-based sequential attempt analysis
│   ├── bots.sql               # Window function frequency detection
│   └── credentials_stuffing.sql  # Distinct user count per IP
├── logs.csv              # Sample dataset for testing
└── README.md

Why Two Modes?

analyzer.py is optimised for forensic investigation — load a full log file, run aggregations, understand what happened. Pandas 'resample()' is ideal here.

stream_analyzer.py is optimised for production detection — processes events one-by-one as they arrive, maintains sliding windows in memory using 'deque', fires alerts in real-time. Replace 'csv.DictReader' with a Kafka consumer and the architecture scales to millions of events per second.

Limitations & Future Work

- Streaming engine resets state on restart — production would use Redis for persistent window state
- No IP reputation scoring or geolocation enrichment yet
- Credential stuffing uses 'resample()' in batch mode — 'rolling()' with 'nunique' is not natively supported in Pandas; streaming version solves this with 'deque' + 'set()'
- Could extend with VPN/proxy detection and shared-IP whitelisting to reduce false positives