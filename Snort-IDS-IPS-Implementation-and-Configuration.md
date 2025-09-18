
# Snort IDS/IPS Implementation and Configuration

## Overview
This project demonstrates the implementation and configuration of Snort as an Intrusion Detection and Prevention System (IDS/IPS).  
The setup involved using both a Virtual Machine and a Local Machine to monitor network traffic, detect potential threats, and log security incidents.

---

## Objectives
- Configure Snort in both IDS and IPS modes.
- Develop and apply custom Snort rules for specific attack detection.
- Set up alert monitoring for real-time detection and response.
- Implement log management for incident analysis and investigation.

---

## Environment Setup
- **Operating Systems Used:** Ubuntu (Virtual Machine), Windows (Local Machine)  
- **Tools Installed:**  
  - Snort  
  - Tcpdump (for packet capture and verification)  
  - Nmap (for generating test traffic)  
- **Network Setup:**  
  - VM and local machine connected for traffic monitoring.  
  - Snort configured to analyze traffic on the primary interface.  

---

## Key Highlights

### 1. Configuration
- Installed and configured Snort on both the Virtual Machine and Local Machine.
- Set up Snort to run in IDS mode to capture and analyze traffic.
- Configured Snort to run in IPS mode using inline deployment to block malicious traffic.

### 2. Rule Writing
- Developed custom Snort rules for different scenarios:
  - Detecting ICMP echo requests (ping).
  - Detecting TCP port scans.
  - Detecting specific HTTP traffic patterns.
- Stored all rules in a separate file (`custom.rules`) and included it in the Snort configuration.

### 3. Alert Monitoring
- Configured Snort to generate alerts in console mode for real-time visibility.
- Enabled unified2 output for structured log analysis.
- Verified alerts using sample malicious traffic generated with Nmap and ping sweeps.

### 4. Log Management
- Implemented logging to `/var/log/snort/`.
- Logs included packet captures, alerts, and detailed event descriptions.
- Analyzed logs to identify attacker IPs, payloads, and attack types.

---

## Sample Snort Commands

Run Snort in IDS mode with custom configuration:
```

snort -c /etc/snort/snort.conf -i eth0 -A console

```

Run Snort with custom rule file only:
```

snort -c /etc/snort/custom.rules -i eth0 -A console

```

Run Snort in IPS mode (inline mode with NFQUEUE):
```

snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf

```

---

## Example Custom Rules

Detect ICMP Ping:
```

alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)

```

Detect TCP Port Scan:
```

alert tcp any any -> any any (msg:"TCP Port scan detected"; flags\:S; sid:1000002; rev:1;)

```

Detect SQL Injection attempt:
```

alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR '1'='1"; nocase; sid:1000003; rev:1;)

```

---

## Skills Demonstrated
- Network Security
- IDS/IPS Configuration
- Snort Rule Writing
- Real-time Threat Detection
- Log Management and Analysis
- Incident Response

---

## Learning Outcomes
- Gained practical knowledge in configuring and deploying IDS/IPS systems.
- Improved expertise in rule creation for detecting attacks and anomalies.
- Strengthened ability to analyze logs and respond to incidents.
- Developed a deeper understanding of network traffic analysis and threat detection.

---

## Conclusion
This project was a valuable step in my cybersecurity learning journey.  
It enhanced my technical skills in Snort configuration, custom rule writing, alert monitoring, and log management.  
By simulating real-world attack scenarios and analyzing the results, I gained practical experience in intrusion detection and prevention.  
This knowledge will be applied to future projects and professional challenges in the field of cybersecurity.
