#!/bin/bash

TRIAGE_DIR="/var/reports/ir_triage_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TRIAGE_DIR"

REPORT_FILE="$TRIAGE_DIR/ir_report.txt"
EVIDENCE_DIR="$TRIAGE_DIR/evidence"

mkdir -p "$EVIDENCE_DIR"

echo "=== INCIDENT RESPONSE TRIAGE REPORT ===" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "Analyst: $(whoami)" >> "$REPORT_FILE"
echo "Uptime: $(uptime)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section A: System Identity
echo "--- SYSTEM IDENTIFICATION ---" >> "$REPORT_FILE"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$REPORT_FILE"
echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
echo "Architecture: $(uname -m)" >> "$REPORT_FILE"
echo "IP Addresses: $(ip addr show | grep 'inet ' | awk '{print $2}' | tr '\n' ' ')" >> "$REPORT_FILE"
echo "MAC Addresses: $(ip link show | grep 'link/ether' | awk '{print $2}' | tr '\n' ' ')" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section B: Running Processes
echo "--- RUNNING PROCESSES ---" >> "$REPORT_FILE"
ps aux --sort=-%cpu >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section C: Process Tree
echo "--- PROCESS TREE ---" >> "$REPORT_FILE"
pstree -p >> "$REPORT_FILE" 2>/dev/null || echo "pstree not available" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section D: Network Connections
echo "--- NETWORK CONNECTIONS ---" >> "$REPORT_FILE"
ss -tulnp >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "--- ESTABLISHED CONNECTIONS ---" >> "$REPORT_FILE"
ss -tunap state established >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section E: Routing and ARP
echo "--- ROUTING TABLE ---" >> "$REPORT_FILE"
ip route >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "--- ARP TABLE ---" >> "$REPORT_FILE"
ip neigh >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section F: Logged In Users
echo "--- CURRENTLY LOGGED IN USERS ---" >> "$REPORT_FILE"
who >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
w >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section G: Login History
echo "--- RECENT SUCCESSFUL LOGINS ---" >> "$REPORT_FILE"
last -n 20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "--- RECENT FAILED LOGINS ---" >> "$REPORT_FILE"
lastb -n 20 >> "$REPORT_FILE" 2>/dev/null || echo "lastb not available" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section H: Authentication Failures (from secure log)
echo "--- AUTHENTICATION FAILURES (LAST 50 LINES) ---" >> "$REPORT_FILE"
grep "Failed password\|authentication failure" /var/log/secure | tail -n 50 >> "$REPORT_FILE" 2>/dev/null || echo "No secure log" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section I: Suspicious Temp Files
echo "--- FILES IN TEMP DIRECTORIES (LAST 24 HOURS) ---" >> "$REPORT_FILE"
find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section J: Recent SUID/SGID Binaries
echo "--- SUID/SGID BINARIES ---" >> "$REPORT_FILE"
find / -perm /6000 -type f 2>/dev/null | head -50 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section K: Cron Jobs
echo "--- SYSTEM CRON JOBS ---" >> "$REPORT_FILE"
cat /etc/crontab >> "$REPORT_FILE"
ls -la /etc/cron.* 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "--- USER CRON JOBS ---" >> "$REPORT_FILE"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^no crontab" | sed "s/^/$user: /" >> "$REPORT_FILE"
done
echo "" >> "$REPORT_FILE"

# Section L: Sudoers
echo "--- SUDOERS CONFIGURATION ---" >> "$REPORT_FILE"
cat /etc/sudoers 2>/dev/null >> "$REPORT_FILE"
ls -la /etc/sudoers.d/ 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section M: Environment Variables
echo "--- ENVIRONMENT VARIABLES ---" >> "$REPORT_FILE"
env >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section N: Loaded Kernel Modules
echo "--- LOADED KERNEL MODULES ---" >> "$REPORT_FILE"
lsmod >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section O: File Hashes of Running Processes
echo "--- FILE HASHES OF RUNNING BINARIES ---" >> "$REPORT_FILE"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    if [ -f "/proc/$pid/exe" ]; then
        exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
        if [ -n "$exe" ] && [ -f "$exe" ]; then
            hash=$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')
            echo "$pid | $exe | $hash" >> "$REPORT_FILE"
        fi
    fi
done
echo "" >> "$REPORT_FILE"

# Section P: Disk and Mounts
echo "--- DISK USAGE ---" >> "$REPORT_FILE"
df -h >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "--- MOUNT POINTS ---" >> "$REPORT_FILE"
mount >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section Q: Open Files (lsof summary)
echo "--- OPEN FILES SUMMARY ---" >> "$REPORT_FILE"
lsof +c0 2>/dev/null | wc -l >> "$REPORT_FILE"
echo "Total open files count above" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Save raw evidence files
cp /var/log/secure "$EVIDENCE_DIR/secure_backup.log" 2>/dev/null
cp /var/log/messages "$EVIDENCE_DIR/messages_backup.log" 2>/dev/null
cp /var/log/audit/audit.log "$EVIDENCE_DIR/audit_backup.log" 2>/dev/null

echo "=== END TRIAGE REPORT ===" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Triage directory: $TRIAGE_DIR" >> "$REPORT_FILE"
echo "Report file: $REPORT_FILE" >> "$REPORT_FILE"
echo "Evidence files: $EVIDENCE_DIR" >> "$REPORT_FILE"

cat "$REPORT_FILE"
