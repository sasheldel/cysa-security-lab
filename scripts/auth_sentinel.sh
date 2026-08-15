#!/bin/bash

LOG_FILE="/var/log/secure"
REPORT_FILE="/var/reports/auth_report_$(date +%Y-%m-%d).txt"
THRESHOLD=5

# Create report header
echo "=== Authentication Security Report ===" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section A: Top 10 failed SSH attempts by IP
echo "--- TOP 10 FAILED SSH IPs ---" >> "$REPORT_FILE"
grep "Failed password" "$LOG_FILE" | \
    awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
    grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | \
    sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section B: Off-hours successful logins (00:00-05:00)
echo "--- OFF-HOURS SUCCESSFUL LOGINS (00-05) ---" >> "$REPORT_FILE"
grep "Accepted" "$LOG_FILE" | \
    awk '{h=substr($3,1,2); if(h>=0 && h<=5) print $0}' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section C: Failed sudo attempts
echo "--- FAILED SUDO ATTEMPTS ---" >> "$REPORT_FILE"
grep "sudo:.*authentication failure" "$LOG_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section D: IPs exceeding threshold
echo "--- BRUTE FORCE ALERTS (>$THRESHOLD attempts) ---" >> "$REPORT_FILE"
grep "Failed password" "$LOG_FILE" | \
    awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
    grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | \
    sort | uniq -c | \
    awk -v t=$THRESHOLD '$1 > t {print $2 ": " $1 " attempts"}' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section E: MITRE ATT&CK mapping
echo "--- MITRE ATT&CK MAPPING ---" >> "$REPORT_FILE"
echo "T1110 Brute Force: Failed password attempts" >> "$REPORT_FILE"
echo "T1078 Valid Accounts: Successful logins" >> "$REPORT_FILE"
echo "T1548 Abuse Elevation: Sudo failures" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "=== END REPORT ===" >> "$REPORT_FILE"
cat "$REPORT_FILE"
