# Snort IDS/IPS Projects

This repository contains a collection of practical projects focused on using **Snort** as an Intrusion Detection and Prevention System (IDS/IPS) for monitoring network traffic, detecting threats, and preventing malicious activities. Each project simulates real-world use cases relevant to SOC operations, intrusion detection, and incident response.

---

## Purpose

* Demonstrate the use of Snort for analyzing and detecting suspicious network traffic.
* Showcase Snort in both IDS (detection) and IPS (prevention) modes.
* Apply custom Snort rules for identifying malicious patterns and activities.
* Provide reproducible steps for building a hands-on IDS/IPS lab environment.

---

## Project List

### 1. Snort IDS/IPS Implementation and Configuration
**Description:** Demonstrates how to set up and configure Snort on both a virtual machine and a local machine to monitor and secure network traffic.
**Key Features:**
* Full configuration of Snort for IDS/IPS mode.
* Writing and applying custom Snort rules.
* Monitoring alerts for suspicious activity.
* Log management and analysis for incidents.
**Highlights:**
* Detection of specific threats using custom rules.
* Real-time alert monitoring.
* Comprehensive logging of network events.

[View Project](https://github.com/00112244/snort_works/blob/main/Snort-IDS-IPS-Implementation-and-Configuration.md)

---
### 2. Snort as Inline IPS (Blocking Traffic)
**Description:** Demonstrates the configuration of Snort in Inline IPS mode to actively block malicious traffic, going beyond detection and providing real-time prevention.
**Key Features:**
* Deployment of Snort in IPS mode using NFQUEUE.
* Creation and tuning of custom blocking rules.
* Real-time prevention of malicious packets and attacks.
* Logging and verification of blocked events.
**Highlights:**
* Successfully blocked port scans, pings, and SQL injection attempts.
* Showcased packet dropping and active defense capabilities.
* Practical demonstration of Snort’s use as a prevention tool in SOC environments.

[View Project](https://github.com/00112244/snort_works/blob/main/Snort-as-Inline-IPS-(Blocking-Traffic).md)

---

