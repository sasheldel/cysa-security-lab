#!/bin/bash

TARGET="172.16.28.128"
REPORT_FILE="/var/reports/vuln_report_$(date +%Y%m%d).csv"

echo "=== Vulnerability Scan Report ==="
echo "Target: $TARGET"
echo "Date: $(date)"
echo ""

# Run nmap vulnerability scan
echo "[*] Running nmap vulnerability scan (this takes 2-3 minutes)..."
sudo nmap -sV --script vuln -oN /tmp/nmap_vuln.txt "$TARGET" 2>/dev/null

# Parse findings into CSV with REAL CVSS scores
echo "severity,cve,port,service,cvss_score,description" > "$REPORT_FILE"

# Extract CVE lines with their CVSS scores from vulners output
grep -E "CVE-[0-9]{4}-[0-9]+" /tmp/nmap_vuln.txt | grep -E "[0-9]+\.[0-9]+.*https://vulners" | while read line; do
    # Extract CVE
    CVE=$(echo "$line" | grep -oE "CVE-[0-9]{4}-[0-9]+" | head -1)
    
    # Extract CVSS score (the number before the URL)
    CVSS=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+" | head -1)
    
    # Determine severity from CVSS
    if awk "BEGIN {exit !($CVSS >= 9.0)}"; then
        SEVERITY="CRITICAL"
    elif awk "BEGIN {exit !($CVSS >= 7.0)}"; then
        SEVERITY="HIGH"
    elif awk "BEGIN {exit !($CVSS >= 4.0)}"; then
        SEVERITY="MEDIUM"
    else
        SEVERITY="LOW"
    fi
    
    # Extract port from context (look back 10 lines for PORT/PROTOCOL)
    PORT=$(grep -B 10 "$CVE" /tmp/nmap_vuln.txt | grep -oE "^[0-9]+/(tcp|udp)" | tail -1)
    [ -z "$PORT" ] && PORT="unknown"
    
    # Extract service
    SERVICE=$(grep -B 10 "$CVE" /tmp/nmap_vuln.txt | grep -oE "^[0-9]+/(tcp|udp).*[a-zA-Z0-9-]+/" | tail -1 | awk '{print $3}')
    [ -z "$SERVICE" ] && SERVICE="unknown"
    
    # Write to CSV
    echo "$SEVERITY,$CVE,$PORT,$SERVICE,$CVSS,$line" >> "$REPORT_FILE"
done

echo ""
echo "--- OPEN PORTS ---"
grep -E "^[0-9]+/(tcp|udp)" /tmp/nmap_vuln.txt | head -20

echo ""
echo "--- VULNERABILITY SUMMARY ---"
echo "Total CVEs found: $(grep -c "CVE-" /tmp/nmap_vuln.txt 2>/dev/null || echo 0)"
echo "Critical (9.0+): $(grep -c "CRITICAL" "$REPORT_FILE" 2>/dev/null || echo 0)"
echo "High (7.0-8.9): $(grep -c "HIGH" "$REPORT_FILE" 2>/dev/null || echo 0)"
echo "Medium (4.0-6.9): $(grep -c "MEDIUM" "$REPORT_FILE" 2>/dev/null || echo 0)"
echo "Low (0.1-3.9): $(grep -c "LOW" "$REPORT_FILE" 2>/dev/null || echo 0)"

echo ""
echo "Report saved: $REPORT_FILE"
cat "$REPORT_FILE"
