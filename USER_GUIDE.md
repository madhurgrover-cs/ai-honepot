# 🛡️ AI Honeypot - User Guide

## Overview

The AI Honeypot is an intelligent deception system that uses machine learning to predict attacker behavior, maps attacks to industry standards (MITRE ATT&CK), and automatically generates actionable threat intelligence.

**Key Features:**
- 🔮 ML-based attack prediction using Markov chains
- 🎯 MITRE ATT&CK framework mapping
- 📊 Real-time attack monitoring dashboard
- 🤖 Auto-generated incident response playbooks
- 📤 Threat intelligence export (IOCs, STIX 2.1)
- 🎭 Adaptive deception based on attacker skill level

---

## Quick Start

### Prerequisites
- Python 3.11+
- pip (Python package manager)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/madhurgrover-cs/ai-honepot.git
cd ai-honepot
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Start the honeypot**
```bash
python app.py
```

The honeypot will start on `http://localhost:8000`

### Docker Deployment (Recommended)

```bash
docker-compose up --build
```

---

## Using the Honeypot

### 1. Real-Time Dashboard

**URL:** `http://localhost:8000/demo`

The dashboard provides live monitoring of attacks as they happen.

**Features:**
- Total attack counter
- Current attacker tracking
- Threat level indicators (LOW/MEDIUM/HIGH/CRITICAL)
- Attacker skill level detection (NOVICE/INTERMEDIATE/ADVANCED/AUTOMATED)
- Real-time attack timeline
- WebSocket-powered live updates

**How to use:**
1. Open the dashboard in your browser
2. Launch attacks (see section 2)
3. Watch the dashboard update in real-time

---

### 2. Launching Test Attacks

To test the honeypot, simulate attacks using these URLs:

**SQL Injection:**
```
http://localhost:8000/search?q=' OR 1=1--
http://localhost:8000/search?q=UNION SELECT * FROM users--
```

**Authentication Bypass:**
```
http://localhost:8000/login?user=admin&pass=' OR '1'='1
```

**Admin Access:**
```
http://localhost:8000/admin?token=fake_token
```

**Cross-Site Scripting (XSS):**
```
http://localhost:8000/search?q=<script>alert('XSS')</script>
```

**Command Injection:**
```
http://localhost:8000/search?q=; ls -la
```

---

### 3. Getting Your Attacker ID

Each attacker is tracked with a unique ID stored in browser cookies.

**How to find your attacker ID:**
1. Open browser DevTools (Press `F12`)
2. Go to **Application** tab
3. Click **Cookies** → `http://localhost:8000`
4. Find `attacker_id` and copy the value

**Example:** `2a346b0bb2774e798507557e63da1587`

You'll need this ID to access the API endpoints below.

---

## API Endpoints

All endpoints return JSON unless otherwise specified. Replace `{attacker_id}` with your actual attacker ID.

### Attack Prediction

**Endpoint:** `GET /api/prediction/{attacker_id}`

**Description:** Predicts the attacker's next move using ML

**Example:**
```
http://localhost:8000/api/prediction/2a346b0bb2774e798507557e63da1587
```

**Response:**
```json
{
  "current_stage": "exploitation",
  "next_stage": "privilege_escalation",
  "predicted_goal": "data_theft",
  "goal_confidence": "75.0%",
  "next_likely_vectors": [
    {"vector": "admin_access", "probability": "60.0%"},
    {"vector": "command_execution", "probability": "30.0%"}
  ],
  "time_to_compromise_minutes": 15,
  "threat_level": "high"
}
```

---

### MITRE ATT&CK Mapping

**Endpoint:** `GET /api/mitre/{attacker_id}`

**Description:** Maps attacks to MITRE ATT&CK framework

**Example:**
```
http://localhost:8000/api/mitre/2a346b0bb2774e798507557e63da1587
```

**Response:**
```json
{
  "ttps": {
    "tactics_used": ["INITIAL_ACCESS", "CREDENTIAL_ACCESS"],
    "techniques_used": [
      {"id": "T1190", "name": "Exploit Public-Facing Application"}
    ],
    "total_techniques": 2,
    "tactic_coverage": "14.3%"
  },
  "apt_matches": [
    {"group": "APT28", "similarity": "40.0%", "common_ttps": 2}
  ]
}
```

---

### Forensic Timeline

**Endpoint:** `GET /api/timeline/{attacker_id}`

**Description:** Complete attack timeline with statistics

**Example:**
```
http://localhost:8000/api/timeline/2a346b0bb2774e798507557e63da1587
```

**Response:**
```json
{
  "attacker_id": "2a346b0bb2774e798507557e63da1587",
  "total_attacks": 5,
  "successful_attacks": 5,
  "failed_attacks": 0,
  "success_rate": "100.0%",
  "campaign_duration": "0:05:30",
  "first_seen": "2026-02-11T15:57:52",
  "last_seen": "2026-02-11T16:03:22"
}
```

---

### Attack Narrative

**Endpoint:** `GET /api/timeline/{attacker_id}/narrative`

**Description:** Human-readable attack story

**Example:**
```
http://localhost:8000/api/timeline/2a346b0bb2774e798507557e63da1587/narrative
```

**Response:**
```json
{
  "narrative": "Attack Campaign Analysis for 2a346b0bb2774e798507557e63da1587\n\nCampaign Duration: 0:05:30\nTotal Attacks: 5\n\nAttack Progression:\n1. [0:00:00] SQL Injection on /search - Successful\n2. [0:01:15] Admin Access on /admin - Successful\n..."
}
```

---

### Indicators of Compromise (IOCs)

**Endpoint:** `GET /api/threat-intel/{attacker_id}/iocs`

**Description:** Generates IOCs for threat intelligence sharing

**Example:**
```
http://localhost:8000/api/threat-intel/2a346b0bb2774e798507557e63da1587/iocs
```

**Response:**
```json
{
  "attacker_id": "2a346b0bb2774e798507557e63da1587",
  "generated_at": "2026-02-11T16:00:00",
  "indicators": [
    {
      "type": "ipv4-addr",
      "value": "127.0.0.1",
      "confidence": "high",
      "description": "Malicious IP"
    },
    {
      "type": "pattern",
      "value": "' OR 1=1--",
      "confidence": "medium",
      "description": "SQL injection pattern"
    }
  ]
}
```

---

### STIX Bundle Export

**Endpoint:** `GET /api/threat-intel/{attacker_id}/stix`

**Description:** Exports threat intelligence in STIX 2.1 format

**Example:**
```
http://localhost:8000/api/threat-intel/2a346b0bb2774e798507557e63da1587/stix
```

**Response:** STIX 2.1 JSON bundle with threat actors, attack patterns, and indicators

---

### Incident Response Playbook

**Endpoint:** `GET /api/playbook/{attack_type}`

**Description:** Downloads incident response playbook (Markdown file)

**Example:**
```
http://localhost:8000/api/playbook/SQL%20Injection
```

**Response:** Downloads `SQL_Injection_playbook.md` with:
- Incident overview
- Detection indicators
- Containment steps
- Investigation procedures
- Remediation actions
- Recovery steps
- Sigma rules for SIEM

---

### CSV Export

**Endpoint:** `GET /api/export/attacks`

**Description:** Exports all attacks as CSV file

**Example:**
```
http://localhost:8000/api/export/attacks
```

**Response:** Downloads `attacks.csv` with all attack data

---

### Canary Analytics

**Endpoint:** `GET /api/canary/dashboard`

**Description:** Analytics for canary token tracking

**Example:**
```
http://localhost:8000/api/canary/dashboard
```

**Response:**
```json
{
  "overview": {
    "total_tokens": 15,
    "active_tokens": 12,
    "used_tokens": 3,
    "total_usages": 8,
    "effectiveness": {
      "extraction_rate": "45.0%",
      "reuse_rate": "30.0%"
    }
  }
}
```

---

## Understanding the System

### How Attack Prediction Works

The system uses a **Markov chain model** that learns from attack sequences:

1. **Tracks attack patterns** - Records what attacks follow other attacks
2. **Builds transition matrix** - Calculates probabilities (e.g., SQL Injection → Admin Access: 60%)
3. **Predicts next move** - Uses historical data to predict likely next attack
4. **Estimates timing** - Calculates time-to-compromise based on average intervals

### MITRE ATT&CK Integration

Every attack is mapped to the MITRE ATT&CK framework:

- **Tactics** - The "why" (e.g., INITIAL_ACCESS, CREDENTIAL_ACCESS)
- **Techniques** - The "how" (e.g., T1190: Exploit Public-Facing Application)
- **APT Matching** - Compares attacker behavior to known threat groups

### Adaptive Deception

The honeypot adjusts responses based on detected skill level:

- **NOVICE** - Easy wins, obvious vulnerabilities to keep them engaged
- **INTERMEDIATE** - Balanced challenge with realistic responses
- **ADVANCED** - Rabbit holes and time-wasting fake leads
- **AUTOMATED** - Honeypot evasion detection

---

## Use Cases

### 1. Security Research
- Study attacker behavior patterns
- Discover new attack techniques
- Build threat intelligence databases

### 2. Enterprise Security
- Early warning system for targeted attacks
- Generate threat intelligence specific to your industry
- Train security teams with real attack data

### 3. Incident Response Training
- Use attack timelines for training scenarios
- Practice with auto-generated playbooks
- Understand attack progression

### 4. Threat Intelligence Sharing
- Export STIX bundles to share with community
- Feed IOCs into SIEM systems
- Contribute to collective defense

---

## Advanced Features

### Canary Tokens

The honeypot embeds fake credentials in responses:
- API keys
- Database passwords
- Authentication tokens

When attackers extract and use these tokens, the system:
- Tracks extraction and usage
- Calculates effectiveness metrics
- Detects token sharing between attackers

### Behavioral Analysis

Tracks attacker behavior over time:
- Request patterns and timing
- Tool signatures (sqlmap, Nikto, etc.)
- Skill level progression
- Attack sophistication

### Real-Time Alerts

WebSocket-powered notifications for:
- High-severity attacks
- Canary token usage
- APT group matches
- Skill level escalation

---

## Troubleshooting

### Server won't start
- Check Python version: `python --version` (needs 3.11+)
- Install dependencies: `pip install -r requirements.txt`
- Check port 8000 is available: `netstat -an | findstr 8000`

### Dashboard not updating
- Ensure WebSocket support: `pip install "uvicorn[standard]"`
- Check browser console for errors (F12)
- Verify server is running

### API returns 404
- Confirm server is running on port 8000
- Check attacker_id is correct (from cookies)
- Verify endpoint URL spelling

### No attacks logged
- Launch test attacks (see section 2)
- Check `attacks.json` file exists
- Verify file permissions

---

## Security Considerations

### Isolation
- Run in containerized environment (Docker recommended)
- Deploy in separate VLAN/DMZ
- Isolate from production systems

### Data Safety
- All credentials in responses are fake
- No real sensitive data exposed
- Attacker input is sanitized before logging

### Monitoring
- Monitor honeypot health
- Set up alerts for high-severity attacks
- Regular log review

---

## Technical Specifications

**Backend:** Python 3.11, FastAPI  
**Real-time:** WebSockets  
**ML:** Markov chains for prediction  
**Standards:** MITRE ATT&CK, STIX 2.1  
**Deployment:** Docker, docker-compose  
**Storage:** JSON logging (upgradeable to PostgreSQL/MongoDB)  
**Performance:** <100ms response time, handles 100+ concurrent connections  

---

## API Endpoint Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/prediction/{id}` | GET | Attack predictions |
| `/api/mitre/{id}` | GET | MITRE ATT&CK mapping |
| `/api/timeline/{id}` | GET | Forensic timeline |
| `/api/timeline/{id}/narrative` | GET | Attack narrative |
| `/api/canary/dashboard` | GET | Canary analytics |
| `/api/threat-intel/{id}/iocs` | GET | IOC generation |
| `/api/threat-intel/{id}/stix` | GET | STIX bundle |
| `/api/playbook/{type}` | GET | Incident playbook |
| `/api/export/attacks` | GET | CSV export |
| `/api/fingerprint` | POST | Browser fingerprint |

---

## Support & Documentation

- **GitHub:** https://github.com/madhurgrover-cs/ai-honepot
- **API Reference:** See `api_reference.md`
- **Technical Details:** See `technical_deep_dive.md`
- **Testing Guide:** See `browser_testing.md`

---

## License

MIT License - See LICENSE file for details

---

**Built with ❤️ for cybersecurity research and defense**
