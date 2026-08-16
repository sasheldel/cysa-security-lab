#!/bin/bash

INTERFACE="any"
CAPTURE_FILE="/tmp/capture_$(date +%Y%m%d_%H%M%S).pcap"
REPORT_FILE="/var/reports/netcorr_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Network Alert Correlation Report ===" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "Interface: $INTERFACE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Capture 90 seconds of traffic
echo "Capturing 90 seconds on $INTERFACE..."
echo "START YOUR ATTACK FROM KALI NOW - You have 90 seconds" >> "$REPORT_FILE"
sudo tshark -i "$INTERFACE" -w "$CAPTURE_FILE" -a duration:90 2>/dev/null

# Section A: Unique source IPs
echo "--- UNIQUE SOURCE IPs ---" >> "$REPORT_FILE"
sudo tshark -r "$CAPTURE_FILE" -T fields -e ip.src 2>/dev/null | \
    grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | \
    sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section B: TCP SYN packets (potential scans)
echo "--- TCP SYN PACKETS (potential scans) ---" >> "$REPORT_FILE"
sudo tshark -r "$CAPTURE_FILE" 'tcp.flags.syn==1 and tcp.flags.ack==0' 2>/dev/null | wc -l >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section C: Kali VM traffic count
echo "--- KALI VM TRAFFIC (172.16.28.129) ---" >> "$REPORT_FILE"
sudo tshark -r "$CAPTURE_FILE" 'ip.src==172.16.28.129' 2>/dev/null | wc -l >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section D: SSH traffic
echo "--- SSH TRAFFIC (port 22) ---" >> "$REPORT_FILE"
sudo tshark -r "$CAPTURE_FILE" 'tcp.port==22' 2>/dev/null | wc -l >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section E: Wazuh agent traffic (port 1514)
echo "--- WAZUH AGENT TRAFFIC (port 1514) ---" >> "$REPORT_FILE"
sudo tshark -r "$CAPTURE_FILE" 'tcp.port==1514' 2>/dev/null | wc -l >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Section F: Cross-reference with Wazuh alerts
echo "--- WAZUH ALERTS (LAST HOUR) ---" >> "$REPORT_FILE"
sudo cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | jq -r '
  select(.rule.groups[]? | contains("suricata") or contains("ossec") or contains("syscheck"))
  | "\(.timestamp) | \(.rule.description) | src: \(.srcip // "N/A")"
' | tail -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Capture saved: $CAPTURE_FILE" >> "$REPORT_FILE"
echo "Report saved: $REPORT_FILE" >> "$REPORT_FILE"
cat "$REPORT_FILE"
