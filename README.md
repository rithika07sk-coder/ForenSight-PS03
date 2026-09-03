# ForenSight

## Digital Forensics Investigation and Attack Story Reconstruction System

**Tagline:** From Scattered Logs to a Clear Attack Story

---

## 1. Team Details

- **Team Name:** NeuroNex
- **Team Leader:** Rithikakrishnan G
- **Register Number:** 25101018
- **College:** Manakula Vinayagar Institute of Technology
- **Domain:** Cybersecurity
- **Problem Statement ID:** PS_ID: 3
- **Team Leader Email:** rithika07rk@gmail.com

### Team Members

- Akash S
- 25101001
---

## 2. Problem Statement

During a suspected cyberattack, a university may collect evidence from multiple sources such as login activity, file-access records, system events, and network activity. These logs are often stored separately and may use different formats.

Because the evidence is fragmented, investigators may find it difficult to identify the possible entry point, trace suspicious activities, determine affected systems and accounts, identify accessed files, and understand the complete attack sequence.

### Target Users

- University security teams
- Security Operations Center (SOC) analysts
- IT administrators
- Digital-forensics investigators

### Importance

Manual analysis of separate log sources is slow and may miss important relationships between events. A system that connects evidence, builds a timeline, and explains the probable attack story can help investigators analyze incidents faster and make evidence-based decisions.

---

## 3. Proposed Solution

We propose **ForenSight**, a web-based Digital Forensics Investigation System.

ForenSight accepts simulated forensic logs from authentication systems, file-access logs, system events, and network activity. It converts all records into a common event format and correlates related events using timestamp, user account, IP address, host, file, and logical activity sequence.

The system creates a chronological incident timeline and an attack relationship graph. It identifies the possible initial entry point, suspicious activity chain, affected assets, and the most likely attack story.

ForenSight provides a confidence score and supporting evidence for every important finding.

> The system provides investigation hypotheses. It does not automatically confirm an attack or attribute actions to an individual. Final verification is done by a human investigator.

---

## 4. Approach / Methodology

### Basic Working Flow

```text
Simulated Forensic Logs
        ↓
Log Upload
        ↓
Data Normalization
        ↓
Event Correlation
        ↓
Timeline Construction
        ↓
Attack Graph Generation
        ↓
Blast Radius Analysis
        ↓
Confidence Scoring
        ↓
Attack Story Generation
        ↓
Human Investigator Verification
```

### Methodology Steps

1. Create simulated authentication, file-access, system-event, and network logs.
2. Upload logs in CSV or JSON format.
3. Convert all records into a common event structure.
4. Arrange events based on timestamp.
5. Correlate events using common users, hosts, IP addresses, files, and time proximity.
6. Detect suspicious patterns such as multiple failed logins followed by a successful login.
7. Build a chronological timeline and attack relationship graph.
8. Identify affected accounts, systems, files, and external IP addresses.
9. Generate an evidence-backed attack story with a confidence score.
10. Allow the investigator to verify or reject the finding.

### Evidence Correlation Factors

- Same user account
- Same host or server
- Same source or destination IP address
- Same file or object
- Close timestamps
- Logical action sequence

Example suspicious sequence:

```text
Failed VPN Login
      ↓
Successful VPN Login
      ↓
Sensitive File Access
      ↓
File Compression
      ↓
External Data Transfer
```

---

## 5. Technology / Tools

| Technology / Tool | Purpose |
|---|---|
| Python | Main programming language for analysis and correlation |
| Streamlit | Web dashboard and user interface |
| Pandas | Log reading, data cleaning, filtering, and normalization |
| SQLite | Local storage of forensic events |
| NetworkX | Event relationship and attack graph analysis |
| PyVis | Interactive attack graph visualization |
| Plotly | Timeline and dashboard visualizations |
| CSV / JSON | Simulated forensic log input format |
| GitHub | Version control and team collaboration |

### Optional Future Scope

- OpenSearch for scalable log search and security analytics
- Neo4j for graph database storage
- FastAPI for backend APIs
- MITRE ATT&CK mapping for suspicious activity patterns

---

## 6. Expected Output / MVP

The MVP will demonstrate:

- Uploading simulated login, file-access, system, and network logs
- Converting all logs into a common event format
- Displaying a unified chronological event timeline
- Searching and filtering events by user, host, IP address, source, and severity
- Detecting suspicious activities using simple correlation rules
- Connecting related events across multiple log sources
- Displaying an interactive attack relationship graph
- Identifying the possible initial entry point
- Showing affected accounts, systems, files, and IP addresses
- Generating an explainable attack story
- Displaying confidence scores
- Providing supporting event IDs and raw evidence
- Allowing human investigator verification

### Example Demonstration Output

```text
Possible Entry Point:
Compromised VPN Login

Affected Account:
student01

Affected Systems:
vpn-server, research-server

Affected File:
solar_grid_results.xlsx

Possible Activity:
File access → File compression → External data transfer

Confidence Level:
High

Status:
Requires Human Investigator Verification
```

---

## 7. Team Roles

| Team Member | Responsibility |
|---|---|
| Rithikakrishnan G| Project coordination, problem analysis, final integration, and PPT presentation |
| Rithikakrishnan G| Creation of simulated forensic logs and data normalization |
| Akash S | Event-correlation rules, attack detection, and confidence scoring |
| Akash S | Dashboard development, timeline, and attack graph visualization |
| Rithikakrishnan G | Testing, README documentation, references, and demonstration preparation |

> Every team member understands the problem statement, proposed solution, methodology, technology stack, expected MVP, and individual responsibility.

---

## 8. Feasibility

The project is feasible within the hackathon timeframe because:

- The problem statement allows teams to create simulated forensic evidence.
- The MVP uses simple CSV or JSON files instead of real sensitive university data.
- Python provides free libraries for log analysis, graph creation, and visualization.
- Rule-based correlation is transparent, practical, and does not require a large labelled dataset.
- Streamlit allows rapid development of a working dashboard.
- The complete prototype can run locally on a laptop.
- The project focuses on one clearly defined university attack scenario.
- The system can later be expanded using OpenSearch, Neo4j, SIEM integration, and machine-learning models.

### MVP Scope

```text
Authentication Logs
+ File-Access Logs
+ System Events
+ Network Logs
        ↓
Correlation Engine
        ↓
Timeline + Attack Graph
        ↓
Attack Story + Confidence Score
```

---

## 9. References / Data Sources

1. X’O CODE 2026 Problem Statements  
   **PS_ID: 3 — Digital Forensics: Find the Attack Story**

2. X’O CODE 2026 Idea Submission — Screening Round Rules and Guidelines

3. Team-created simulated forensic logs:
   - Authentication logs
   - File-access logs
   - System-event logs
   - Network-activity logs

4. MITRE ATT&CK Framework  
   Used as a future reference for mapping suspicious cyberattack techniques.

5. OpenSearch Security Analytics Documentation  
   Used as a future reference for scalable security-log analysis.

---

## Responsible Use

ForenSight is intended for educational purposes and authorized defensive cybersecurity investigations only.

The prototype uses fictional and simulated logs. The system does not automatically confirm an attack or attribute actions to individuals. All findings must be reviewed by a qualified human investigator.
