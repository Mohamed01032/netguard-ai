"""
NetGuard Lite - live network intrusion detection prototype.

Watches traffic coming into this machine. Every 5 seconds it summarizes the
behavior of each source IP and detects: Port Scan / SYN Flood / Brute Force /
Ping Flood. An Isolation Forest learns what "normal" looks like on your network
and flags anything unusual, even attacks that have no rule.

Usage (run as Administrator / root):
  python netguard.py list                       # list network interfaces
  python netguard.py learn  --iface "Wi-Fi"     # learn normal traffic (optional)
  python netguard.py detect --iface "Wi-Fi"     # start monitoring
  python netguard.py detect --iface "Wi-Fi" --block   # + auto-block attackers
"""
import argparse
import csv
import os
import pickle
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, conf, get_if_addr, sniff

WINDOW = 5  # seconds
AUTH_PORTS = {21, 22, 23, 3389, 3306, 5900}
HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(HERE, "baseline.pkl")
LOG_FILE = os.path.join(HERE, "alerts.csv")
FEATURES = ["syn", "syn_rate", "uniq_ports", "top_port_share", "auth_syn", "udp", "icmp", "pkts"]

RED, YEL, GRN, CYN, RST = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[0m"
if os.name == "nt":
    os.system("")  # enable ANSI colors on Windows


def new_stats():
    return {"pkts": 0, "syn": 0, "udp": 0, "icmp": 0, "ports": defaultdict(int), "auth_syn": 0}


class Monitor:
    """Collects per-source-IP behavior for traffic addressed to this host."""

    def __init__(self, my_ip):
        self.my_ip = my_ip
        self.lock = threading.Lock()
        self.win = defaultdict(new_stats)

    def on_packet(self, p):
        if IP not in p or p[IP].dst != self.my_ip or p[IP].src == self.my_ip:
            return
        with self.lock:
            s = self.win[p[IP].src]
            s["pkts"] += 1
            if TCP in p:
                flags = int(p[TCP].flags)
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK = new connection attempt
                    s["syn"] += 1
                    s["ports"][p[TCP].dport] += 1
                    if p[TCP].dport in AUTH_PORTS:
                        s["auth_syn"] += 1
            elif UDP in p:
                s["udp"] += 1
                s["ports"][p[UDP].dport] += 1
            elif ICMP in p:
                s["icmp"] += 1

    def flush(self):
        """Return the features for the last window and start a new one."""
        with self.lock:
            win, self.win = self.win, defaultdict(new_stats)
        rows = {}
        for ip, s in win.items():
            hits = sum(s["ports"].values()) or 1
            rows[ip] = {
                "syn": s["syn"],
                "syn_rate": s["syn"] / WINDOW,
                "uniq_ports": len(s["ports"]),
                "top_port_share": max(s["ports"].values(), default=0) / hits,
                "top_port": max(s["ports"], key=s["ports"].get) if s["ports"] else None,
                "auth_syn": s["auth_syn"],
                "udp": s["udp"],
                "icmp": s["icmp"],
                "pkts": s["pkts"],
            }
        return rows


def classify(f):
    """Explainable classification: returns (attack, reason) or None."""
    if f["uniq_ports"] >= 15:
        return "Port Scan", f"tried {f['uniq_ports']} different ports in {WINDOW} s"
    if f["syn_rate"] >= 100 and f["top_port_share"] >= 0.8:
        return "SYN Flood", f"{int(f['syn_rate'])} SYN/s on port {f['top_port']}, never completed"
    if f["auth_syn"] >= 10:
        return "Brute Force", f"{f['auth_syn']} connection attempts on login port {f['top_port']}"
    if f["icmp"] >= 50:
        return "Ping Flood", f"{f['icmp']} pings in {WINDOW} s"
    return None


def vec(f):
    return [f[k] for k in FEATURES]


def send_telegram(text):
    token, chat = os.getenv("TELEGRAM_TOKEN"), os.getenv("CHAT_ID")
    if not (token and chat):
        return
    try:
        import requests
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      data={"chat_id": chat, "text": text}, timeout=10)
    except Exception as ex:
        print(f"{YEL}telegram failed: {ex}{RST}")


def block_ip(ip):
    if os.name == "nt":
        cmd = f'netsh advfirewall firewall add rule name="NetGuard block {ip}" dir=in action=block remoteip={ip}'
    else:
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
    os.system(cmd)


def log_alert(ip, kind, reason, score):
    new = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["time", "src_ip", "attack", "reason", "anomaly_score"])
        w.writerow([datetime.now().isoformat(timespec="seconds"), ip, kind, reason, score])


def start_sniffer(iface, mon):
    threading.Thread(
        target=lambda: sniff(iface=iface, filter="ip", prn=mon.on_packet, store=False),
        daemon=True,
    ).start()


def cmd_list():
    print(conf.ifaces)


def cmd_learn(iface, minutes):
    from sklearn.ensemble import IsolationForest
    my_ip = get_if_addr(iface)
    mon = Monitor(my_ip)
    start_sniffer(iface, mon)
    print(f"{CYN}📚 Learning normal traffic on {my_ip} for {minutes} min... "
          f"use the machine normally (browse, YouTube). Do NOT attack now.{RST}")
    samples, end = [], time.time() + minutes * 60
    while time.time() < end:
        time.sleep(WINDOW)
        samples += [vec(f) for f in mon.flush().values()]
        samples.append([0] * len(FEATURES))  # quiet periods are normal too
        print(f"  {len(samples)} samples", end="\r")
    model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42).fit(samples)
    with open(MODEL_FILE, "wb") as fh:
        pickle.dump(model, fh)
    print(f"\n{GRN}✅ Model saved to baseline.pkl ({len(samples)} samples){RST}")


def cmd_detect(iface, auto_block):
    my_ip = get_if_addr(iface)
    model = None
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as fh:
            model = pickle.load(fh)
    mon = Monitor(my_ip)
    start_sniffer(iface, mon)
    blocked = set()
    print(f"{GRN}🛡️  NetGuard running on {my_ip} ({iface}) | "
          f"AI model: {'ON' if model else 'OFF (run learn first)'} | "
          f"auto-block: {'ON' if auto_block else 'OFF'}{RST}")
    print("Press Ctrl+C to stop\n")
    while True:
        time.sleep(WINDOW)
        rows = mon.flush()
        stamp = datetime.now().strftime("%H:%M:%S")
        if not rows:
            print(f"{stamp}  quiet ✓", end="\r")
            continue
        for ip, f in rows.items():
            label = classify(f)
            score = None
            if model is not None:
                score = round(float(-model.score_samples([vec(f)])[0]), 3)
                is_anom = model.predict([vec(f)])[0] == -1
                if not label and is_anom and f["syn"] + f["udp"] + f["icmp"] >= 5:
                    label = ("Anomaly", f"AI model flagged unusual behavior (score {score})")
            if not label:
                continue
            kind, reason = label
            msg = f"🚨 {kind}\nFrom: {ip}\nReason: {reason}"
            if auto_block and ip not in blocked:
                block_ip(ip)
                blocked.add(ip)
                msg += "\n⛔ IP blocked"
            print(f"{RED}[{stamp}] {msg.replace(chr(10), ' | ')}{RST}")
            log_alert(ip, kind, reason, score)
            send_telegram(msg)


def main():
    ap = argparse.ArgumentParser(description="NetGuard Lite - live intrusion detection")
    ap.add_argument("mode", choices=["list", "learn", "detect"])
    ap.add_argument("--iface", help="interface name or index (see: list)")
    ap.add_argument("--minutes", type=float, default=3, help="learning time (learn mode)")
    ap.add_argument("--block", action="store_true", help="auto-block attackers (IPS mode)")
    a = ap.parse_args()
    if a.mode == "list":
        return cmd_list()
    if not a.iface:
        sys.exit("Please set --iface (run: python netguard.py list)")
    if a.iface.isdigit():  # accept the Index number from "list"
        a.iface = conf.ifaces.dev_from_index(int(a.iface))
    try:
        cmd_learn(a.iface, a.minutes) if a.mode == "learn" else cmd_detect(a.iface, a.block)
    except KeyboardInterrupt:
        print(f"\n{YEL}Stopped. Alerts are saved in alerts.csv{RST}")


if __name__ == "__main__":
    main()
