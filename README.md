# CySA+ Security Lab
**Exam Target:** October 4, 2026  
**Lab Stack:** RHEL 10 (Wazuh SIEM) + Kali Linux (attacker) + Metasploitable2 (target)

## Projects
| # | Project | Domain | Status |
|---|---|---|---|
| 1 | Auth Log Sentinel | Security Operations | ✅ Complete |
| 2 | Network Alert Correlator | Threat/Vuln + SecOps | 🔄 In Progress |
| 3 | Vulnerability Report Parser | Threat/Vuln | ⬜ Planned |
| 4 | MITRE ATT&CK Mapper | Security Operations | ⬜ Planned |
| 5 | IR Triage Toolkit | Incident Response | ⬜ Planned |
| 6 | System Hardening Auditor | Software Security | ⬜ Planned |
| 7 | Compliance Baseline Checker | Compliance | ⬜ Planned |
| 8 | SOC Daily Dashboard | All Domains | ⬜ Planned |

## Architecture
- **RHEL 10 VM:** Wazuh Manager + Indexer + Dashboard
- **Kali VM:** Wazuh Agent + attack tools (Hydra, nmap)
- **Metasploitable2:** Intentionally vulnerable target
