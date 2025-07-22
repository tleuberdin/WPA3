import time
import socket
import os

class TrafficAnalyzer:
    """
    Target Performance Analyzer.
    In addition to pcap analysis (if scapy is used), methods have been added
    for actively measuring baseline and current performance over TCP connections.
    """
    def __init__(self, pcap_file, bssid):
        self.pcap_file = pcap_file
        self.bssid = bssid.lower()
        self.baseline = None

    def establish_baseline(self, duration=2):
    """Measures the target's baseline performance through TCP connection attempts."""
        start = time.time()
        success_count = 0
        while time.time() - start < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((self.bssid, 80))
                s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                _ = s.recv(1024)
                success_count += 1
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except:
                    pass
        self.baseline = success_count / float(duration)
        return self.baseline

    def get_current_performance(self, duration=1):
        start = time.time()
        success_count = 0
        while time.time() - start < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((self.bssid, 80))
                s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                _ = s.recv(1024)
                success_count += 1
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except:
                    pass
        current_perf = success_count / float(duration)
        return current_perf

    def get_reward(self):
        current_perf = self.get_current_performance(duration=1)
        if self.baseline is None:
            self.establish_baseline()
        reward = self.baseline - current_perf
        return reward

    def execute_and_measure(self, attack_func):
        start_time = time.time()
        attack_func()
        attack_duration = time.time() - start_time
        reward = self.get_reward()
        return reward

    def analyze_offline(self):

        try:
            from scapy.all import rdpcap
            from scapy.layers.dot11 import Dot11
            from scapy.layers.eap import EAPOL
        except ImportError:
            print("[WARN] Scapy is not instalkled. Offline analysis is not available.")
            return
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            print(f"[WARN] pcap file {self.pcap_file} not found.")
            return
        self.eapol_count = 0
        self.handshake_detected = False
        try:
            packets = rdpcap(self.pcap_file)
            for pkt in packets:
                self._process_packet(pkt)
        except Exception as e:
            print(f"[ERROR] Reading pcap {self.pcap_file} failed: {e}")

    def _process_packet(self, pkt):
        try:
            from scapy.layers.dot11 import Dot11
            from scapy.layers.eap import EAPOL
        except ImportError:
            return
        if pkt.haslayer(Dot11):
            pass
        if pkt.haslayer(EAPOL):
            self.eapol_count += 1
            if self.eapol_count > 3:
                self.handshake_detected = True

    def get_features(self):
    """Returns a dictionary with features obtained during offline analysis."""
        return {
            "eapol_count": getattr(self, "eapol_count", 0),
            "handshake_detected": int(getattr(self, "handshake_detected", False))
        }

    def reset(self):
    """Reset analyzer state and recalculate baseline."""
        if os.path.exists(self.pcap_file):
            os.remove(self.pcap_file)
        self.establish_baseline()
