# Detecting Nmap Scans with Snort

## Overview

This project demonstrates how to detect network reconnaissance performed with Nmap using Snort. It includes step-by-step guidance for building a reproducible lab, writing and tuning Snort detection rules for common scan techniques (SYN, XMAS, UDP, NULL), testing with Nmap, and validating alerts and logs for SOC use cases.

This documentation is written for defensive, lab-based testing only. Do not perform scanning or intrusion tests on networks you do not own or have explicit authorization to test.

---

## Objectives

* Identify Nmap scan types using Snort rules (SYN, XMAS, UDP, NULL).
* Create robust, low-noise rules with appropriate thresholds to reduce false positives.
* Verify detections using controlled Nmap scans and packet captures.
* Integrate alerts into a simple log review workflow for incident analysis.

---

## Prerequisites

* A lab with at least two endpoints and one Snort sensor (attacker -> snort-sensor -> victim). Virtual machines are recommended for isolation.
* Snort installed on the sensor host (package or source build). Snort 2.9.x and later are supported; verify documentation for your version.
* Basic tools on the attacker and victim: `nmap`, `tcpdump`, `curl`.
* Root or sudo privileges on the Snort host for packet capture and rule deployment.

Recommended packages on the Snort sensor:

```bash
sudo apt update
sudo apt install -y snort tcpdump nmap build-essential libpcap-dev libpcre3-dev libdumbnet-dev
```

---

## Lab Topology (example)

```
[Attacker VM] ---eth0--> [Snort Sensor] ---eth1--> [Victim VM]
```

For simpler setups, you may run attacker and victim on separate VMs bridged to the same host and run Snort in promiscuous mode on a monitoring interface.

---

## Installation and Configuration (Step-by-step)

### 1. Install Snort and dependencies

Use distribution packages or build from source. For basic detection tests, the packaged Snort is sufficient.

```bash
sudo apt update
sudo apt install -y snort
```

During package setup you may be prompted for network interface and `HOME_NET` configuration. You can edit `/etc/snort/snort.conf` later.

### 2. Configure `snort.conf`

* Set `HOME_NET` to your victim network or host (e.g., `192.168.56.0/24` for VirtualBox host-only).
* Ensure `$RULE_PATH` points to the directory containing your local rule file (e.g., `/etc/snort/rules`).
* Include your custom rules file in `snort.conf` by adding a line such as:

```text
include $RULE_PATH/detection.rules
```

### 3. Place custom rules

Create `configs/detection.rules` (or place in your `$RULE_PATH`) and add the detection rules provided below.

### 4. Start Snort in test mode

Validate configuration before running:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

Start Snort in console alert mode for live testing:

```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A console
```

Replace `eth0` with the monitoring interface on your Snort sensor.

---

## Detection Rules (examples)

Add these rules to `detection.rules`. The `sid` values use the 1000000+ range for local rules. Tune thresholds to match your lab traffic patterns.

**Detect TCP SYN scan (typical Nmap -sS):**

```text
alert tcp any any -> any 1:65535 (msg:"Detection - TCP SYN Scan"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:1000001; rev:1;)
```

**Detect XMAS scan (Nmap -sX) — FIN, PUSH, URG flags set (FPU):**

```text
alert tcp any any -> any 1:65535 (msg:"Detection - XMAS Scan"; flags:FPU; detection_filter:track by_src, count 10, seconds 60; sid:1000002; rev:1;)
```

**Detect NULL scan (Nmap -sN) — no flags set:**

```text
alert tcp any any -> any 1:65535 (msg:"Detection - NULL Scan"; flags:0; detection_filter:track by_src, count 10, seconds 60; sid:1000003; rev:1;)
```

**Detect UDP scan (Nmap -sU):**

```text
alert udp any any -> any 1:65535 (msg:"Detection - UDP Scan"; threshold:type limit, track by_src, count 50, seconds 60; sid:1000004; rev:1;)
```

Notes on rule fields:

* Use `alert` action to log and generate alerts; in IPS/inline setups you can change `alert` to `drop` or `reject` as appropriate.
* `detection_filter` and `threshold` reduce noisy single packets by requiring a number of events from one source within a time window.
* Tune `count` and `seconds` values to match lab traffic and attack speed.

---

## Testing Procedures (Nmap commands)

Perform tests from the attacker VM against the victim IP. Use `-Pn` to skip host discovery if needed.

**SYN scan (stealth):**

```bash
nmap -sS -p 1-1024 -T4 <victim-ip>
```

**XMAS scan:**

```bash
nmap -sX -p 1-1024 <victim-ip>
```

**NULL scan:**

```bash
nmap -sN -p 1-1024 <victim-ip>
```

**UDP scan:**

```bash
sudo nmap -sU -p 1-1024 <victim-ip>
```

**Slow scans (stealthy):**

```bash
nmap -sS -p 1-65535 --scan-delay 500ms <victim-ip>
```

Adjust scan speed to test threshold sensitivity.

---

## Verification and Analysis

1. Monitor Snort console or alert file during scans:

```bash
sudo tail -f /var/log/snort/alert
```

2. Capture traffic on the victim to confirm packets were received:

```bash
sudo tcpdump -n -i eth0 host <attacker-ip>
```

3. Compare timestamps to validate which packets triggered Snort alerts.

4. For structured processing, configure Snort to output unified2 and use Barnyard2 or similar to forward alerts to syslog/ELK/Splunk.

---

## Rule Tuning and False-Positive Reduction

* Increase `count` or `seconds` in detection filters to avoid false positives from benign bursts.
* Add `flow` or port restrictions to narrow detection scope (for example, `-> any 1:1024` if you only care about low ports).
* Whitelist known scanners (internal vulnerability scanners) using `pass` rules placed above detection rules.
* Use `threshold` or `rate_filter` where applicable for legacy and high-performance rule sets.
* Test rules with benign traffic to ensure no required services are accidentally flagged.

Example pass rule to whitelist a scanner IP:

```text
pass ip 10.0.0.5 any -> any any (msg:"Whitelist - Internal Scanner"; sid:1000100; rev:1;)
```

Place `pass` rules before `alert` rules in your rules file or adjust rule ordering accordingly.

---

## Logging and SIEM Integration

* Snort default alert logs are typically saved to `/var/log/snort/alert` or the path configured in `snort.conf`.
* For SIEM ingestion, enable unified2 output and run Barnyard2 to translate unified2 to syslog, database, or Elasticsearch.
* Consider forwarding Snort alerts to a centralized SIEM for correlation with host logs and threat intelligence.

Example `snort.conf` output snippet for unified2:

```text
output unified2: filename snort.u2, limit 128
```

---

## Troubleshooting

**Rules not firing:**

* Confirm `snort.conf` includes your `detection.rules` and `$RULE_PATH` is set correctly.
* Run `snort -T -c /etc/snort/snort.conf` to validate config syntax.
* Ensure interface is in promiscuous/monitor mode and Snort is attached to correct interface.

**High false positives:**

* Increase detection thresholds.
* Narrow rule scope using ports, flows, or IP ranges.

**No alerts in unified2/Barnyard2 pipeline:**

* Verify Barnyard2 is reading the correct unified2 output path and check permissions.
* Check for SELinux/AppArmor restrictions on log paths.

---

## Reproducible Steps (Quick Checklist)

1. Prepare attacker, sensor, and victim VMs.
2. Install Snort and supporting tools on the sensor.
3. Add `detection.rules` to your Snort rule path and include in `snort.conf`.
4. Validate configuration with `snort -T`.
5. Start Snort in console mode: `snort -c /etc/snort/snort.conf -i eth0 -A console`.
6. From attacker, run Nmap scans (SYN, XMAS, NULL, UDP).
7. Verify alerts in Snort logs and confirm via `tcpdump` on victim.
8. Tune thresholds and rule scope to reduce false positives.

---

## Next Steps and Enhancements

* Automate tests with scripts that run Nmap scans and validate expected alerts.
* Integrate alert forwarding to a SIEM (Splunk/ELK) and build dashboards for scan detection trends.
* Compare detection efficacy with Suricata and explore performance differences.
* Add test PCAPs to the repo for offline rule development and unit testing.

---

## Safety and Ethics

Only perform scanning and detection tests within lab environments and on systems and networks for which you have explicit permission. Unauthorized scanning may be illegal and unethical.

---

## Conclusion

Here’s a professional and concise conclusion you can add to the end of the Nmap scan detection project:

---

## Conclusion

This project demonstrated how Snort can effectively detect common reconnaissance techniques such as SYN, XMAS, NULL, and UDP scans generated by Nmap. By creating and tuning custom rules, validating detections with real traffic, and analyzing logs, the project provided practical experience in network monitoring and intrusion detection. The skills gained here form a strong foundation for SOC operations, where early detection of reconnaissance is critical to preventing further compromise.

