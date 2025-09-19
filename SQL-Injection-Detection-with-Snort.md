# SQL Injection Detection with Snort

## Overview

This project demonstrates how to detect SQL injection (SQLi) attacks on web applications using Snort. It includes guidance for setting up a lab environment, creating and tuning Snort rules to detect malicious HTTP requests, testing with SQLi payloads (e.g., using sqlmap), and analyzing alerts and logs.

This documentation is intended for educational and lab-based testing only. Do not perform SQL injection tests on production or unauthorized systems.

---

## Objectives

* Detect SQL injection attempts targeting web applications using Snort.
* Write custom Snort rules for HTTP traffic inspection.
* Test detection with controlled payloads using tools such as sqlmap.
* Analyze Snort alerts and logs to validate rule effectiveness.

---

## Prerequisites

* Lab environment with at least three VMs: attacker, Snort sensor, victim web server.
* Snort installed on the sensor (Ubuntu/Debian recommended).
* Web server running a test application (Apache/Nginx + MySQL/PHP or vulnerable app like DVWA).
* Tools installed on attacker: `curl`, `sqlmap`.
* Root or sudo privileges on Snort host for packet capture.

Install Snort and dependencies on sensor:

```bash
sudo apt update
sudo apt install -y snort tcpdump apache2 mysql-client php libapache2-mod-php
```

---

## Lab Topology (example)

```
[Attacker VM] ---eth0--> [Snort Sensor] ---eth1--> [Victim Web Server VM]
```

Snort monitors traffic passing from attacker to victim and inspects HTTP requests for SQLi patterns.

---


## Installation and Configuration (Step-by-step)

### 1. Configure Snort

Edit `snort.conf`:

* Set `$HOME_NET` to the victim web server network.
* Include the custom SQLi rules file:

```text
include $RULE_PATH/sqli.rules
```

* Ensure HTTP preprocessor is enabled (default in Snort 2.9+):

```text
preprocessor http_inspect: global iis_unicode_map unicode.map 1252
preprocessor http_inspect_server: server default profile all ports { 80 8080 } oversize_dir_length 500
```

### 2. Create Custom SQL Injection Rules

Example rules in `sqli.rules`:

```text
# Detect simple tautology-based SQL injection
alert tcp any any -> any 80 (msg:"SQLi Attempt - Tautology"; content:"' OR '1'='1"; nocase; http_uri; sid:2000001; rev:1;)

# Detect union-based SQL injection
alert tcp any any -> any 80 (msg:"SQLi Attempt - UNION SELECT"; content:"UNION SELECT"; nocase; http_uri; sid:2000002; rev:1;)

# Detect SQLi via common comment injection
alert tcp any any -> any 80 (msg:"SQLi Attempt - Comment Injection"; content:"--"; http_uri; sid:2000003; rev:1;)
```

**Notes:**

* Use `alert` to generate logs; in IPS setups, `drop` can be used.
* `http_uri` inspects the HTTP request URI.
* Adjust `sid` for local rules and maintain uniqueness.

### 3. Start Snort

```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A console
```

Replace `eth0` with the monitoring interface.

---

## Testing SQL Injection Detection

### Using curl

````bash
curl "http://<victim-ip>/login.php?username=admin' OR '1'='1&password=any"```

### Using sqlmap

```bash
sqlmap -u "http://<victim-ip>/login.php?username=admin&password=test" --batch
````

### Verification

* Monitor Snort console or alert file:

```bash
sudo tail -f /var/log/snort/alert
```

* Confirm that alerts correspond to the SQLi payloads.
* Optionally, use tcpdump on the victim to ensure packets were received.

---

## Rule Tuning and False-Positive Reduction

* Narrow detection rules to relevant parameters and URI paths.
* Use `threshold` or `detection_filter` to avoid triggering on legitimate traffic containing similar characters.
* Whitelist trusted IPs or test traffic sources to prevent unnecessary alerts.

Example threshold:

```text
alert tcp any any -> any 80 (msg:"SQLi Attempt - UNION SELECT"; content:"UNION SELECT"; nocase; http_uri; threshold:type limit, track by_src, count 5, seconds 60; sid:2000002; rev:2;)
```

---

## Logging and SIEM Integration

* Alerts logged to `/var/log/snort/alert` by default.
* For SIEM integration, use unified2 output with Barnyard2 to forward alerts to a centralized system.

Example `snort.conf` output:

```text
output unified2: filename snort.u2, limit 128
```

---

## Troubleshooting

* **Rules not firing:** Check `snort.conf` includes the `sqli.rules` file and interface is correct.
* **High false positives:** Adjust thresholds or narrow URI/content matching.
* **Alerts not logged:** Verify Snort has write permissions to log directories.

---

## Reproducible Steps (Quick Checklist)

1. Prepare attacker, sensor, and victim VMs.
2. Install Snort and web server on respective machines.
3. Create `sqli.rules` and include in `snort.conf`.
4. Start Snort on the sensor.
5. Generate SQL injection payloads using curl or sqlmap.
6. Monitor alerts and validate detections.
7. Tune rules to balance detection and noise.

---

## Next Steps and Enhancements

* Integrate Snort alerts with a SIEM system for correlation.
* Add additional web attack rules (XSS, command injection) for comprehensive WAF-like functionality.
* Create automated test scripts for continuous validation of detection rules.
* Compare Snort detection with other IDS/IPS like Suricata for web traffic.

---

## Safety and Ethics

Only perform SQL injection tests on lab environments and authorized targets. Unauthorized testing on production systems is illegal and unethical.

---

## Conclusion

This project demonstrated the detection of SQL injection attacks using Snort by creating and tuning custom HTTP inspection rules. By testing with controlled payloads and analyzing alerts, it provided hands-on experience in web application security monitoring. The skills gained—including rule creation, traffic analysis, and log management—are directly applicable to SOC operations and real-world web security defense.


