
import hmac
import os
import ipaddress
import sqlite3
import subprocess
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, jsonify, request

firewall_api = Blueprint("firewall_api", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(BASE_DIR, "traffic.db")
TOKEN_FILE = os.path.join(BASE_DIR, ".firewall_token")
HELPER = "/usr/local/sbin/netwatch-firewall"


def db():
    connection = sqlite3.connect(DATABASE, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_audit_table():
    connection = db()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS firewall_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            action TEXT NOT NULL,
            reason TEXT,
            event_time TEXT NOT NULL,
            result TEXT NOT NULL
        )
    """)
    connection.commit()
    connection.close()


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                expected = f.read().strip()
        except OSError:
            return jsonify({"error": "Administrator token unavailable"}), 503

        supplied = request.headers.get("X-Admin-Token", "")

        if not expected or not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "Administrator authentication required"}), 401

        return fn(*args, **kwargs)
    return wrapper


def validate_ip(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise ValueError("Enter a valid IP address")

    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported")

    protected = {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("192.168.1.12"),
        ipaddress.ip_address("192.168.1.1"),
    }

    if address in protected or address.is_multicast or address.is_unspecified:
        raise ValueError("This address is protected or unsupported")

    return str(address)


def run_helper(action, ip=None):
    command = ["sudo", "-n", HELPER, action]

    if ip is not None:
        command.append(ip)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=8,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Firewall operation failed")

    return result.stdout.strip()


def record_event(ip, action, reason, result):
    connection = db()
    connection.execute("""
        INSERT INTO firewall_events
        (ip, action, reason, event_time, result)
        VALUES (?, ?, ?, ?, ?)
    """, (
        ip,
        action,
        reason,
        datetime.now(timezone.utc).isoformat(),
        result
    ))
    connection.commit()
    connection.close()


@firewall_api.get("/api/firewall/status")
@admin_required
def firewall_status():
    try:
        run_helper("status")
        output = run_helper("list")
        import re
        addresses = sorted(set(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output
        )))
        return jsonify({
            "available": True,
            "mode": "Kali machine only",
            "blocked_count": len(addresses)
        })
    except Exception as exc:
        return jsonify({
            "available": False,
            "error": str(exc)
        }), 503


@firewall_api.get("/api/firewall/blocked")
@admin_required
def blocked_ips():
    try:
        output = run_helper("list")
        import re
        addresses = sorted(set(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output
        )))
        return jsonify({"blocked_ips": addresses})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@firewall_api.post("/api/firewall/block")
@admin_required
def block_ip():
    data = request.get_json(silent=True) or {}

    try:
        ip = validate_ip(data.get("ip", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    reason = str(data.get("reason", "Manual administrator block")).strip()[:200]

    try:
        result = run_helper("block", ip)
        record_event(ip, "block", reason, result)
        return jsonify({"ip": ip, "result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@firewall_api.post("/api/firewall/unblock")
@admin_required
def unblock_ip():
    data = request.get_json(silent=True) or {}

    try:
        ip = validate_ip(data.get("ip", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    reason = str(data.get("reason", "Manual administrator unblock")).strip()[:200]

    try:
        result = run_helper("unblock", ip)
        record_event(ip, "unblock", reason, result)
        return jsonify({"ip": ip, "result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@firewall_api.get("/api/firewall/history")
@admin_required
def firewall_history():
    connection = db()
    rows = connection.execute("""
        SELECT id, ip, action, reason, event_time, result
        FROM firewall_events
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])


initialize_audit_table()
