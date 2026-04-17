# GhostSIEM

Lightweight Security Information and Event Management for Linux systems.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/ghostsiem/ghostsiem/actions/workflows/ci.yml/badge.svg)

---

## Architecture

```
+------------------+     +---------------+     +------------------+
|   Collectors     |     |  Normalizer   |     |   Detection      |
|                  +---->+               +---->+   Engine         |
|  syslog          |     |  IP extract   |     |                  |
|  auth.log        |     |  severity     |     |  SIGMA rules     |
|  JSON files      |     |  GeoIP stub   |     |  threshold       |
+------------------+     +---------------+     |  field matching  |
                                               +--------+---------+
                                                        |
                              +-------------------------+
                              |
                    +---------v---------+     +------------------+
                    |   Alert Manager   |     |   Storage        |
                    |                   |     |                  |
                    |  dedup / rate     |     |  SQLite + WAL    |
                    |  console          |     |  events table    |
                    |  file (JSONL)     |     |  alerts table    |
                    |  webhook          |     +------------------+
                    +-------------------+             |
                                               +------v-----------+
                                               |   REST API       |
                                               |                  |
                                               |  GET /events     |
                                               |  GET /alerts     |
                                               |  GET /stats      |
                                               |  GET /health     |
                                               +------------------+
```

## Quick Start

```bash
# Install
pip install ghostsiem

# List built-in detection rules
ghostsiem rules list --builtin

# Start everything (collectors + detection + API)
ghostsiem run --config examples/config.yaml
```

## Installation

### From PyPI

```bash
pip install ghostsiem
```

### From Source

```bash
git clone https://github.com/ghostsiem/ghostsiem.git
cd ghostsiem
pip install -e ".[dev]"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `ghostsiem collect --config config.yaml` | Start log collectors |
| `ghostsiem detect --rules rules/` | Run detection on stored events |
| `ghostsiem serve --port 8080` | Start the REST API server |
| `ghostsiem run --config config.yaml` | Start everything together |
| `ghostsiem rules list --builtin` | Show loaded detection rules |
| `ghostsiem status` | Show event/alert counts |

## Library Usage

```python
from ghostsiem import Collector, DetectionEngine, AlertManager, Event

# Load detection rules
engine = DetectionEngine()
engine.load_rules_from_directory("rules/")

# Evaluate an event
alerts = engine.evaluate(event)
```

## SIGMA Rule Format

GhostSIEM uses SIGMA-compatible YAML rules. Each rule defines detection logic with selections, conditions, and optional filters.

```yaml
title: Failed SSH Login
id: gs-001
status: stable
description: Detects failed SSH login attempts.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: high
detection:
    selection:
        message|contains: "Failed password"
    condition: selection
tags:
    - attack.initial_access
    - attack.t1078
```

### Supported Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| (default) | Substring match | `message: "error"` |
| `\|contains` | Substring match | `message\|contains: "Failed"` |
| `\|startswith` | Prefix match | `process\|startswith: "ssh"` |
| `\|endswith` | Suffix match | `hostname\|endswith: ".internal"` |
| `\|re` | Regex match | `message\|re: "port \d{4,5}"` |

### Condition Operators

- `selection` -- single selection match
- `selection1 and selection2` -- all must match
- `selection1 or selection2` -- any must match
- `selection and not filter` -- match selection, exclude filter
- `1 of selection*` -- any selection matching the prefix
- `all of selection*` -- all selections matching the prefix

### Threshold Rules (Brute Force)

```yaml
detection:
    selection:
        message|contains: "Failed password"
    threshold:
        field: src_ip
        value: 5
    timeframe: "60s"
    condition: selection
```

## Built-in Rules

| ID | Rule | Severity | Description |
|----|------|----------|-------------|
| gs-001 | Failed SSH Login | HIGH | Single failed SSH login attempt |
| gs-002 | SSH Brute Force | CRITICAL | 5+ failures from same IP in 60s |
| gs-003 | SSH Unusual Source | MEDIUM | Successful login from any source |
| gs-004 | Sudo Command | MEDIUM | Sudo execution (filters pam_unix) |
| gs-005 | New User Created | HIGH | useradd/adduser detected |
| gs-006 | Service State Change | LOW | Service started or stopped |
| gs-007 | Firewall Rule Change | HIGH | iptables/ufw modification |
| gs-008 | Large Outbound Transfer | HIGH | scp/rsync/curl/wget usage |

## API Reference

The REST API runs on port 8080 by default.

### Endpoints

**GET /api/v1/health**
```json
{"status": "healthy", "service": "ghostsiem", "timestamp": "..."}
```

**GET /api/v1/events**

Query parameters: `severity`, `source`, `hostname`, `start_time`, `end_time`, `limit`, `offset`

```json
{
  "count": 50,
  "limit": 100,
  "offset": 0,
  "events": [...]
}
```

**GET /api/v1/alerts**

Query parameters: `severity`, `rule_id`, `start_time`, `end_time`, `limit`, `offset`

**GET /api/v1/stats**
```json
{
  "total_events": 1234,
  "total_alerts": 56,
  "events_by_severity": {"high": 100, "medium": 200},
  "top_rules": [{"rule": "Failed SSH Login", "count": 30}],
  "events_per_hour": [{"hour": "2026-04-15 10:00", "count": 42}]
}
```

## Configuration Reference

```yaml
log_level: INFO

collectors:
  - type: syslog          # syslog, auth, json
    path: /var/log/syslog
    poll_interval: 1.0

  - type: auth
    path: /var/log/auth.log

  - type: json
    path: /var/log/app/events.json
    field_map:             # Custom field mapping
      ts: timestamp
      host: hostname
      lvl: severity
      msg: message

detection:
  rules_dir: rules/

alerts:
  dedup_window: 300        # Suppress duplicates within 5 min
  handlers:
    - type: console
    - type: file
      path: alerts.jsonl
    - type: webhook
      url: https://hooks.slack.com/services/XXX

storage:
  path: ghostsiem.db

api:
  host: 0.0.0.0
  port: 8080
```

Environment variables override config with `GHOSTSIEM_` prefix:
- `GHOSTSIEM_DB_PATH`
- `GHOSTSIEM_API_PORT`
- `GHOSTSIEM_LOG_LEVEL`

## Integration

GhostSIEM is designed to work alongside **SentinelPulse** for a complete security monitoring stack. Feed GhostSIEM alerts into SentinelPulse dashboards via the webhook handler for unified incident management.

## Development

```bash
# Install dev dependencies
make dev

# Run tests
make test

# Lint
make lint

# Format
make format
```

## License

MIT License. Copyright (c) 2026 Joe Munene.
