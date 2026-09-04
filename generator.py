import random
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from database.schema_setup import create_logs_table, validate_log_entry


DB_PATH = Path(__file__).resolve().parent / "database" / "siem_logs.db"

# sample data pools for simulated log entries
NORMAL_IPS = ["192.168.1.50", "192.168.1.105", "10.0.0.15"]
ATTACKER_IP = "203.0.113.42"

ENDPOINTS = ["/home", "/dashboard", "/login", "/api/data"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "python-requests/2.28.1"
]

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    create_logs_table(conn)
    return conn


def insert_log(conn, timestamp, source_ip, endpoint, user_agent, action_status):
    entry = validate_log_entry({
        "log_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source_ip": source_ip,
        "endpoint": endpoint,
        "user_agent": user_agent,
        "action_status": action_status,
    })
    conn.execute(
        """
        INSERT INTO logs
        (log_id, timestamp, source_ip, endpoint, user_agent, action_status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            entry["log_id"],
            entry["timestamp"],
            entry["source_ip"],
            entry["endpoint"],
            entry["user_agent"],
            entry["action_status"],
        ),
    )
    conn.commit()


def generate_traffic(cycles=3):
    conn = get_db_connection()
    print("[*] Starting log generation... Press Ctrl+C to stop.")

    try:
        for cycle in range(cycles):
            current_time = datetime.now(timezone.utc).isoformat()

            # 1. Simulate Normal Traffic
            normal_ip = random.choice(NORMAL_IPS)
            endpoint = random.choice(ENDPOINTS)
            user_agent = random.choice(USER_AGENTS)
            insert_log(conn, current_time, normal_ip, endpoint, user_agent, 200)
            print(f"[NORMAL] {normal_ip} -> {endpoint} (200)")

            # 2. Simulate Brute-Force Attack Burst (Rapid failed logins from attacker IP)
            if cycle % 2 == 0:
                print(f"[!] Simulating brute-force attack burst from {ATTACKER_IP}...")
                for _ in range(6):  # Triggers a rapid burst of failed attempts
                    attack_time = datetime.now(timezone.utc).isoformat()
                    insert_log(conn, attack_time, ATTACKER_IP, "/login", USER_AGENTS[0], 401)
                    time.sleep(0.2)  # Fast succession to mimic automated scripting
            
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Log generation stopped by user.")
    finally:
        conn.close()

if __name__ == "__main__":
    generate_traffic(cycles=5)
