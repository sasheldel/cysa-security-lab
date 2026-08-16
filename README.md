# CySA+ Security Lab
**Exam Target:** October 4, 2026

Lab environment for CompTIA CySA+ CS0-004 prep. Built on RHEL 10 with Wazuh SIEM, Kali Linux, and Metasploitable2.

---

## Study Materials

### Books
- *CompTIA CySA+ CS0-004 All-in-One Exam Guide* -- Mike Chapple / David Seidl

### Courses
- Jason Dion CySA+ CS0-004 (Udemy)

---

## Lab Architecture

| Machine | Role | IP |
|---|---|---|
| **Mac Mini** | Hypervisor / Workstation | Host |
| **RHEL 10 VM** | Wazuh Manager + Indexer + Dashboard | 172.16.28.128 |
| **Kali VM** | Wazuh Agent / Attacker | 172.16.28.129 |
| **Metasploitable2** | Vulnerable Target | DHCP |

---

## Projects

### Project 1: Auth Log Sentinel
scripts/auth_sentinel.sh

Parses /var/log/secure for failed SSH attempts, flags brute-force thresholds, maps to MITRE ATT&CK T1110.

### Project 2: Network Alert Correlator
scripts/net_correlator.sh

Captures network traffic with tshark, counts SYN packets, cross-references with Wazuh alerts.

### Project 3: Vulnerability Report Parser
scripts/vuln_parser.sh

Runs nmap --script vuln, parses output to CSV with CVSS prioritization.

### Project 4: MITRE ATT&CK Mapper
scripts/mitre_mapper.sh

Queries Wazuh alerts and maps observed techniques to MITRE framework.

### Project 5: IR Triage Toolkit
scripts/ir_triage.sh

Incident response evidence collector -- processes, connections, logs, file hashes.

### Project 6: System Hardening Auditor
scripts/hardening_audit.sh

CIS benchmark checks for RHEL -- SSH config, firewall, auditd, PAM.

### Project 7: Compliance Baseline Checker
scripts/compliance_check.sh

OpenSCAP automation for RHEL 10 CIS Level 1.

### Project 8: SOC Daily Dashboard
scripts/soc_dashboard.sh

Master report aggregating Projects 1--4 into a single markdown output.

---

## How to Use

Scripts are built and tested on RHEL 10. Run manually or review output in /var/reports/.

    sudo /usr/local/bin/auth_sentinel.sh
    sudo /usr/local/bin/net_correlator.sh

---

## Exam Domains

| Domain | Weight | Projects |
|---|---|---|
| 1.0 Threat & Vulnerability Management | 20% | 2, 3, 7 |
| 2.0 Software & Systems Security | 12% | 6 |
| 3.0 Security Operations | 33% | 1, 2, 4, 8 |
| 4.0 Incident Response | 25% | 5 |
| 5.0 Compliance & Assessment | 10% | 7 |
