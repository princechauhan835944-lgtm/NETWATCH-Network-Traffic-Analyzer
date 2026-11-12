from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import sqlite3
import os
import ipaddress
import urllib.request
import json
import time

from firewall_api import firewall_api

app = Flask(__name__)
CORS(app)
app.register_blueprint(firewall_api)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(BASE_DIR, "traffic.db")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# In-memory location cache
location_cache = {}
CACHE_DURATION = 86400


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def dashboard():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/packets")
def packets():
    connection = get_db_connection()
    rows = connection.execute("""
        SELECT * FROM packets
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/stats")
def stats():
    connection = get_db_connection()

    total = connection.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    protocols = connection.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
    """).fetchall()

    connection.close()

    return jsonify({
        "total_packets": total,
        "protocols": [dict(row) for row in protocols]
    })



@app.route("/api/geolocate")
def geolocate():
    ip = request.args.get("ip", "").strip()

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    if not address.is_global:
        return jsonify({
            "ip": ip,
            "city": "Local Network",
            "region": "",
            "country": "Private / Non-public IP",
            "isp": "Not available",
            "organization": "Local Network",
            "asn": "Not available",
            "domain": "Not available",
            "vpn": "Unknown",
            "proxy": "Unknown",
            "hosting": "Unknown",
            "cdn": "Unknown",
            "status": "private"
        })

    now = time.time()

    if ip in location_cache:
        saved_time, saved_data = location_cache[ip]
        if now - saved_time < CACHE_DURATION:
            return jsonify(saved_data)

    try:
        url = "https://ipwho.is/" + ip
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetworkTrafficAnalyzer/1.0"}
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        if not data.get("success"):
            return jsonify({
                "ip": ip,
                "status": "unavailable"
            })

        connection = data.get("connection") or {}
        org = connection.get("org") or "Unknown"
        domain = connection.get("domain") or "Unknown"

        # CDN is a heuristic, not confirmed VPN/proxy detection.
        cdn = (
            "Likely"
            if "cloudflare" in (org + " " + domain).lower()
            else "Unknown"
        )

        result = {
            "ip": ip,
            "city": data.get("city") or "Unknown",
            "region": data.get("region") or "Unknown",
            "country": data.get("country") or "Unknown",
            "isp": connection.get("isp") or "Unknown",
            "organization": org,
            "asn": (
                "AS" + str(connection["asn"])
                if connection.get("asn") else "Unknown"
            ),
            "domain": domain,
            "vpn": "Unknown",
            "proxy": "Unknown",
            "hosting": "Unknown",
            "cdn": cdn,
            "status": "success"
        }

        location_cache[ip] = (now, result)
        return jsonify(result)

    except Exception:
        return jsonify({
            "ip": ip,
            "status": "error",
            "message": "Geolocation service unavailable"
        }), 503

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
