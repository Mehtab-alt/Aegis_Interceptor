# AEGIS INTERCEPTOR v1.0

**Advanced Local Network Interception & Testing Tool (2025)**

> **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY**

This tool demonstrates ARP spoofing, DNS spoofing, packet sniffing, and network interruption techniques in a controlled lab environment.

### ⚠️ Legal Warning
- Use **only** on networks you own or have **explicit written permission** to test.
- Unauthorized use may violate laws such as the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), or equivalent in your country.
- The author is **not responsible** for any misuse.

A user agreement is enforced on first launch.

### Features
- ARP Spoofing (MitM / DoS)
- DNS Spoofing (selective or wildcard)
- Credential & Cookie Sniffing
- Real-time Latency Monitoring
- Reactive ARP Defense
- Beautiful PyQt6 GUI with live graphs

### Requirements
- Python 3.8+
- Root/Administrator privileges
- Npcap (Windows) or libpcap (Linux)
- Packages: see `requirements.txt`

### Installation
```bash
git clone https://github.com/yourusername/aegis-interceptor.git
cd aegis-interceptor
pip install -r requirements.txt
