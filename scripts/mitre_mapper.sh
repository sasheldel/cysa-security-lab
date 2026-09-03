#!/bin/bash

REPORT_FILE="/var/reports/mitre_report_$(date +%Y%m%d_%H%M%S).txt"
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"

echo "=== MITRE ATT&CK Alert Mapping Report ===" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "Analyst: $(whoami)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Check dependencies
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not found. Install: sudo dnf install jq" >> "$REPORT_FILE"
    cat "$REPORT_FILE"
    exit 1
fi

if [ ! -f "$ALERTS_FILE" ]; then
    echo "ERROR: Wazuh alerts file not found: $ALERTS_FILE" >> "$REPORT_FILE"
    cat "$REPORT_FILE"
    exit 1
fi

# Section A: Technique frequency
echo "--- TECHNIQUE FREQUENCY ---" >> "$REPORT_FILE"
echo "(How many times each MITRE technique was observed)" >> "$REPORT_FILE"
jq -r 'select(.rule.mitre.id != null) | .rule.mitre.id[]' "$ALERTS_FILE" 2>/dev/null | sort | uniq -c | sort -nr >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section B: Technique + Tactic + Source IP breakdown
echo "--- TECHNIQUE + TACTIC + SOURCE IP ---" >> "$REPORT_FILE"
jq -r 'select(.rule.mitre.id != null) | "\(.rule.mitre.id[0]) | \(.rule.mitre.technique[0]) | \(.rule.mitre.tactic[0]) | src: \(.srcip // "N/A")"' "$ALERTS_FILE" 2>/dev/null | sort | uniq -c | sort -nr >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section C: Recent alerts with full MITRE context
echo "--- RECENT MITRE-MAPPED ALERTS (Last 15) ---" >> "$REPORT_FILE"
jq -r 'select(.rule.mitre.id != null) | "\(.timestamp) | \(.rule.mitre.id | join(", ")) | \(.rule.mitre.technique | join(", ")) | \(.rule.mitre.tactic | join(", ")) | src: \(.srcip // "N/A") | \(.rule.description // "No description")"' "$ALERTS_FILE" 2>/dev/null | tail -15 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section D: Cross-reference with lab projects
echo "--- LAB PROJECT CROSS-REFERENCE ---" >> "$REPORT_FILE"
echo "Project 1 (Auth Sentinel) -> T1110 Brute Force:" >> "$REPORT_FILE"
T1110_COUNT=$(jq -r 'select(.rule.mitre.id != null) | .rule.mitre.id[]' "$ALERTS_FILE" 2>/dev/null | grep -c "T1110")
echo "  T1110 observations in Wazuh: $T1110_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Project 2 (Network Correlator) -> T1046 Network Service Scanning:" >> "$REPORT_FILE"
T1046_COUNT=$(jq -r 'select(.rule.mitre.id != null) | .rule.mitre.id[]' "$ALERTS_FILE" 2>/dev/null | grep -c "T1046")
echo "  T1046 observations in Wazuh: $T1046_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section E: Summary stats
echo "--- SUMMARY STATISTICS ---" >> "$REPORT_FILE"
TOTAL_MITRE=$(jq 'select(.rule.mitre.id != null) | .rule.mitre.id[]' "$ALERTS_FILE" 2>/dev/null | wc -l)
UNIQUE_TECHNIQUES=$(jq -r 'select(.rule.mitre.id != null) | .rule.mitre.id[]' "$ALERTS_FILE" 2>/dev/null | sort -u | wc -l)
echo "Total MITRE technique observations: $TOTAL_MITRE" >> "$REPORT_FILE"
echo "Unique techniques observed: $UNIQUE_TECHNIQUES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "=== END REPORT ===" >> "$REPORT_FILE"
cat "$REPORT_FILE"
