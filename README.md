# AEGIS INTERCEPTOR

**Advanced Local Network Interception & Testing Tool (2025)**

<div align="center">
  <img src="assets/banner.png" alt="Aegis Banner" width="100%">
  <br><br>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
  [![Owner](https://img.shields.io/badge/Owner-Mehtab%20Gul-red)]()
  [![Status](https://img.shields.io/badge/Status-Stable-green)]()
</div>

> **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY**

This tool demonstrates ARP spoofing, DNS spoofing, packet sniffing, and network interruption techniques in a controlled lab environment.

### ⚠️ Legal Warning
- Use **only** on networks you own or have **explicit written permission** to test.
- Unauthorized use may violate laws such as the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), or equivalent in your country.
- The author is **not responsible** for any misuse.

A user agreement is enforced on first launch.

### Features
*   **🚀 Raw Socket Injection:** Bypasses standard OS latency for high-performance packet manipulation.
*   **👻 Ghost Mode (MitM):** Intercepts traffic transparently without disrupting target connectivity.
*   **🕸️ Async Scan Engine:** Sweeps subnets 10x faster than standard serial scanners using `asyncio`.
*   **🛡️ Gateway Safe Mode:** Prevents accidental router DoS during audits.
*   **👁️ Passive Fingerprinting:** Identifies OS types (Windows/Linux/iOS) via TTL analysis.

### Requirements
- Python 3.8+
- Root/Administrator privileges
- Npcap (Windows) or libpcap (Linux)
- Packages: see `requirements.txt`

### Installation
```bash
# 1. Clone the repository
git clone https://github.com/MehtabGul/Aegis-Interceptor.git
cd Aegis-Interceptor
