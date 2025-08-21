#!/bin/bash
set -e

LOG_FILE="log/cowrie.json"
OUTPUT_DIR="reports"
DATE=$(date +%Y-%m-%d)

mkdir -p "$OUTPUT_DIR"

echo "Generating honeypot report for $DATE..."

# Generate basic statistics
echo "=== Honeypot Attack Report $DATE ===" > "$OUTPUT_DIR/report-$DATE.txt"
echo "" >> "$OUTPUT_DIR/report-$DATE.txt"

# Total events
TOTAL=$(wc -l < "$LOG_FILE")
echo "Total events recorded: $TOTAL" >> "$OUTPUT_DIR/report-$DATE.txt"

# Failed logins
FAILED=$(grep "cowrie.login.failed" "$LOG_FILE" | wc -l)
echo "Failed login attempts: $FAILED" >> "$OUTPUT_DIR/report-$DATE.txt"

# Successful logins
SUCCESS=$(grep "cowrie.login.success" "$LOG_FILE" | wc -l)
echo "Successful login attempts: $SUCCESS" >> "$OUTPUT_DIR/report-$DATE.txt"

# Commands executed
COMMANDS=$(grep "cowrie.command.input" "$LOG_FILE" | wc -l)
echo "Commands executed: $COMMANDS" >> "$OUTPUT_DIR/report-$DATE.txt"

echo "" >> "$OUTPUT_DIR/report-$DATE.txt"
echo "Top 10 usernames:" >> "$OUTPUT_DIR/report-$DATE.txt"
grep "cowrie.login" "$LOG_FILE" | grep -o '"username": "[^"]*' | grep -o '[^"]*$' | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_DIR/report-$DATE.txt"

echo "" >> "$OUTPUT_DIR/report-$DATE.txt"
echo "Top 10 passwords:" >> "$OUTPUT_DIR/report-$DATE.txt"
grep "cowrie.login" "$LOG_FILE" | grep -o '"password": "[^"]*' | grep -o '[^"]*$' | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_DIR/report-$DATE.txt"

echo "" >> "$OUTPUT_DIR/report-$DATE.txt"
echo "Top 10 source IPs:" >> "$OUTPUT_DIR/report-$DATE.txt"
grep -o '"src_ip": "[^"]*' "$LOG_FILE" | grep -o '[^"]*$' | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_DIR/report-$DATE.txt"

echo "" >> "$OUTPUT_DIR/report-$DATE.txt"
echo "Recent commands executed:" >> "$OUTPUT_DIR/report-$DATE.txt"
grep "cowrie.command.input" "$LOG_FILE" | tail -20 | jq -r '"\(.timestamp) - \(.src_ip): \(.input)"' >> "$OUTPUT_DIR/report-$DATE.txt"

echo "Report saved to $OUTPUT_DIR/report-$DATE.txt"
