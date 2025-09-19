# Snort as Inline IPS (Blocking Traffic)

## Overview

This project demonstrates how to deploy Snort as an inline Intrusion Prevention System (IPS) that can block malicious traffic in real time. The documentation covers the lab topology, prerequisites, step-by-step installation and configuration, example IPS rules, testing procedures, tuning and performance guidance, logging and alerting, and troubleshooting.

This guide is designed for defensive, lab-based testing only. Do not deploy or test on production networks unless you have authorization.

---

## Objectives

* Deploy Snort in inline (IPS) mode using NFQUEUE.
* Create and apply drop rules to block malicious traffic in real time.
* Verify the inline blocking behavior with controlled test traffic.
* Demonstrate rule tuning, logging, and safe rollback procedures.

---

## Prerequisites

* One or more test machines (virtual or physical). Typical lab topology uses two endpoints (attacker and victim) and one Snort inline gateway: attacker -> Snort IPS gateway -> victim.
* Linux distribution (Ubuntu 18.04/20.04/22.04 or Debian-based) for the Snort host. Compatibility varies by distribution and Snort version; test in a controlled lab first.
* Root (sudo) access on the Snort host.
* Basic familiarity with iptables, networking, and packet-capture tools (tcpdump, Wireshark).

Recommended packages (install on the Snort host):

```bash
sudo apt update
sudo apt install -y build-essential gcc make libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev libmagic-dev libnetfilter-queue-dev libmnl-dev tcpdump iptables-persistent
```

Notes:

* `libnetfilter-queue-dev` is required for NFQUEUE support.
* Some distributions provide Snort as a package (`apt install snort`) which is useful for quick IDS testing; for full IPS/NFQ support building DAQ/Snort from source is often required.

---

## Lab Topology (example)

```
[Attacker VM] ---eth0--> [Snort IPS Gateway (inline)] ---eth1--> [Victim VM]
```

* The Snort gateway has two interfaces (one facing the attacker, one facing the victim) and forwards traffic while inspecting it. For simple testing you can also use a single interface with traffic redirected to NFQUEUE.

---



## Installation and Configuration (step-by-step)

### 1. Quick test (IDS mode, package install)

This is a minimal/quick approach to get Snort running for detection-only testing. It may not include NFQUEUE/IPS support.

```bash
sudo apt install -y snort
# Follow prompts to configure network interface and HOME_NET
sudo snort -c /etc/snort/snort.conf -i eth0 -A console
```

Confirm Snort starts and is detecting traffic in console output. This is useful for rule testing but not sufficient for IPS inline blocking.

### 2. Full IPS setup (recommended for NFQUEUE)

For reliable inline operation, install DAQ and Snort (source or packaged builds that include DAQ NFQ support). Steps below provide a general source-build approach. Always check the project website or official docs for the latest versions and instructions.

#### a. Install dependencies

(Already covered in "Prerequisites" — repeat if needed)

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev libmagic-dev libnetfilter-queue-dev libmnl-dev
```

#### b. Build and install DAQ

1. Download the DAQ source tarball from the official Snort downloads page ([https://www.snort.org/downloads](https://www.snort.org/downloads)) or mirror.
2. Extract, configure, build and install:

```bash
wget <DAQ_TARBALL_URL>
tar -xvf daq-*.tar.gz
cd daq-*
./configure
make -j$(nproc)
sudo make install
```

#### c. Build and install Snort (source)

1. Download the Snort source tarball from the official site.
2. Extract, configure, build and install.

```bash
wget <SNORT_TARBALL_URL>
tar -xvf snort-*.tar.gz
cd snort-*
./configure --enable-sourcefire   # optional flag depending on version
make -j$(nproc)
sudo make install
```

Notes:

* The exact configure flags or build workflow differs by Snort version. Consult the official installation guide for the version you choose.
* After install verify Snort recognizes DAQ and NFQUEUE support.

#### d. Verify NFQUEUE availability

Try starting Snort with NFQUEUE DAQ. If the DAQ was built with libnetfilter-queue support and installed correctly, Snort should start without DAQ errors.

```bash
sudo snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf -i eth0 -A console
```

If Snort fails to start showing DAQ-related errors, re-check DAQ installation and required libraries.

### 3. Configure ip forwarding and NFQUEUE rules

For the inline gateway to forward traffic and allow Snort to inspect it, enable IP forwarding on the gateway:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
# To make persistent: edit /etc/sysctl.conf and set net.ipv4.ip_forward=1
```

Use iptables to route traffic to NFQUEUE. Example that queues forwarded traffic to queue number 0:

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

To queue all input or output as needed for your lab:

```bash
sudo iptables -I INPUT  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
```

A file `scripts/enable-nfqueue.sh` in the repo can contain these rules; `scripts/disable-nfqueue.sh` should flush or delete those rules (or use `iptables -D` to remove specific rules).

**Important:** Queuing high volumes of traffic can impact system performance; use targeted rules in production tests and always test in lab environments.

### 4. Start Snort in IPS mode

Run Snort with the `-Q` (packet queue) option, specify DAQ as `nfq`, and point to your configuration file:

```bash
sudo snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf -i eth0 -A console
```

Options explained:

* `-Q` : enable inline queueing mode
* `--daq nfq` : use the NFQUEUE DAQ module
* `--daq-var queue=0` : use NFQUEUE number 0
* `-c` : path to snort.conf
* `-i` : network interface Snort should bind to (in inline mode this is usually not strictly necessary but recommended)
* `-A console` : print alerts to console (useful for debugging)

---

## Example IPS Rules (drop rules)

Place IPS rules in a dedicated rules file (e.g., `configs/ips.rules`) and include it from `snort.conf`.

Example: drop ICMP echo (drop pings) from any source (lab-only rule):

```text
drop icmp any any -> any any (msg:"IPS Drop - ICMP Echo"; sid:1005001; rev:1;)
```

Example: drop simple SQL injection pattern on HTTP 80 (lab test):

```text
drop tcp any any -> any 80 (msg:"IPS Drop - SQL Injection pattern"; content:"' OR '1'='1"; nocase; sid:1005002; rev:1;)
```

Example: block TCP connections from an upstream port-scan signature (SYN with port list):

```text
drop tcp any any -> any 1:65535 (msg:"IPS Drop - TCP SYN Scan"; flags:S; threshold:type limit, track by_src, count 20, seconds 60; sid:1005003; rev:1;)
```

Notes on rules:

* Use `drop` as the action to prevent traffic from reaching the destination.
* Assign unique `sid` values above 1000000 for local rules to avoid conflicts with community rules.
* Add `rev` for rule versioning.
* Tune rules (threshold/detection\_filter) to prevent false positives.

---

## Testing and Verification

Perform all testing within an isolated lab containing only machines you control.

### Basic tests

1. Start Snort in inline mode.
2. Enable NFQUEUE iptables rules.
3. From the attacker VM, generate test traffic.

Examples:

* Ping test (for ICMP drop rule):

```bash
ping -c 4 <victim-ip>
```

* HTTP test with SQL injection payload (for SQLi drop rule):

```bash
curl "http://<victim-ip>/index.php?id=1' OR '1'='1"
```

* Port scan test (for SYN scan rule):

```bash
nmap -sS <victim-ip>
```

Expected results:

* Packets matching drop rules are blocked and should not reach the victim.
* Snort console displays alerts for the matching rules (or logs them to configured alert files).
* `tcpdump` on the victim shows absence of blocked packets when a rule dropped them.

Verification commands on the gateway:

```bash
# Watch Snort console output
sudo tail -f /var/log/snort/alert

# Use tcpdump on the victim to confirm packet absence
sudo tcpdump -i eth0 host <attacker-ip>
```

---

## Logging and Alert Handling

* Snort (in inline mode) continues to generate alerts and logs. Configure `snort.conf` to use unified2 output if you intend to post-process alerts with Barnyard2 or other tools.
* Typical log locations: `/var/log/snort/` (depends on installation). Ensure proper log rotation and disk monitoring.
* For SIEM integration, consider forwarding alerts to syslog, an ELK stack, or a Splunk instance.

Sample Barnyard2 workflow (high level):

1. Configure Snort to write unified2 logs (`output unified2: filename snort.log, limit 128` in snort.conf).
2. Run Barnyard2 to read unified2 and forward to syslog/ELK.

---

## Tuning and Performance Considerations

* Use targeted NFQUEUE iptables rules (match specific source/destination networks or ports) to avoid queueing unnecessary traffic.
* Disable noisy rule sets and run only the rules required for prevention to reduce CPU usage.
* Consider using multiple NFQUEUE instances and multiple Snort workers (if supported) to distribute load.
* Monitor CPU, memory, and queue lengths. Large queue lengths indicate Snort cannot keep up; reduce inspection scope or increase resources.
* Use `pass` rules for trusted hosts to bypass inspection when appropriate.

---

## Safe Rollback and Cleanup

If you need to stop IPS operation and restore normal forwarding:

1. Stop Snort process (PID from systemctl or `ps`):

```bash
sudo pkill snort
```

2. Remove iptables NFQUEUE rules (example cleanup script):

```bash
# Remove all NFQUEUE rules (be careful in production)
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0 || true
sudo iptables -D INPUT  -j NFQUEUE --queue-num 0 || true
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0 || true
```

3. Disable IP forwarding if it was only for testing:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

---

## Troubleshooting

**Snort fails to start with DAQ errors**

* Verify DAQ was built and installed successfully and that libnetfilter-queue is available.
* Check `ldconfig` and library paths; run `sudo ldconfig` after installs.

**Queued packets not reaching Snort**

* Verify iptables rules exist: `sudo iptables -L -v -n`
* Confirm NFQUEUE kernel module and netfilter-queue support are available.
* Use `strace` or system logs to identify permission or missing library errors.

**High packet drop or performance issues**

* Reduce inspection scope (limit rules, whitelist trusted hosts).
* Increase system resources or run Snort on more powerful hardware.

---

## Safety and Ethics

* Do not point IPS configuration or testing at networks or hosts you do not own or have explicit permission to test.
* Use isolated lab environments for all testing.

---

## Example `snort.conf` snippets

Include the `configs/ips.rules` from your Snort configuration by adding an include line:

```text
include $RULE_PATH/ips.rules
```

Enable unified2 output for downstream processing (example):

```text
output unified2: filename snort.u2, limit 128
```

---

## Example `configs/ips.rules`

```text
# Local IPS drop rules - lab use only
# SID values in the 1005000 range for local rules

# Drop ICMP echo
drop icmp any any -> any any (msg:"IPS Drop - ICMP Echo"; sid:1005001; rev:1;)

# Drop simple SQL injection attempt on port 80
drop tcp any any -> any 80 (msg:"IPS Drop - SQL Injection pattern"; content:"' OR '1'='1"; nocase; sid:1005002; rev:1;)

# Drop high-rate SYN scans (example threshold/detection_filter)
drop tcp any any -> any 1:65535 (msg:"IPS Drop - TCP SYN Scan"; flags:S; detection_filter: track by_src, count 20, seconds 60; sid:1005003; rev:1;)
```

---

## Reproducible Steps (quick checklist)

1. Prepare three VMs: attacker, snort-gateway, victim.
2. Install dependencies on snort-gateway.
3. Build/install DAQ and Snort (or install package if only testing IDS mode).
4. Configure `snort.conf` and place `configs/ips.rules` in your rules path.
5. Enable IP forwarding on gateway and add iptables NFQUEUE rules.
6. Start Snort in inline mode with NFQUEUE.
7. Generate test traffic from attacker and confirm Snort drops matching packets.
8. Analyze logs and tune rules as required.

---

## Next Steps / Enhancements

* Integrate Barnyard2 + ELK/Siem for alert aggregation and visualization.
* Implement automated test cases for each IPS rule using scripted traffic generators.
* Compare Snort IPS blocking against Suricata's inline IPS to evaluate performance/efficacy.
* Add a playbook or Ansible role to automate deployment and rollback.

---

## References

Consult the official [Snort documentation](https://docs.snort.org/) and installation guides for the specific Snort version you choose. Always follow vendor documentation for the most current and secure installation steps.

---

## Conclusion

Implementing Snort as an Inline IPS demonstrated its ability to not only detect but also prevent malicious traffic in real time. This project enhanced practical skills in rule tuning, inline deployment, and traffic analysis, providing a strong foundation for applying IPS concepts in real-world SOC environments.


