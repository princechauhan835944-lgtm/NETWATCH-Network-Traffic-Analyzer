
import ipaddress
import subprocess

NFT = "/usr/sbin/nft"
TABLE = "netwatch"
SET_NAME = "blocked_ipv4"


def run_nft(arguments):
    """Run nftables without a shell."""
    result = subprocess.run(
        [NFT] + arguments,
        capture_output=True,
        text=True,
        timeout=5,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "nftables error")

    return result.stdout.strip()


def validate_ip(value):
    try:
        address = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        raise ValueError("Invalid IP address")

    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported")

    protected = {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("192.168.1.12"),
        ipaddress.ip_address("192.168.1.1"),
    }

    if address in protected or not address.is_global and not address.is_private:
        raise ValueError("This IP address cannot be blocked")

    return str(address)


def initialize_firewall():
    """Create only the dedicated NETWATCH firewall objects."""
    tables = run_nft(["list", "tables"])

    if "table inet netwatch" not in tables:
        run_nft(["add", "table", "inet", TABLE])

    sets = run_nft(["list", "sets", "inet", TABLE])

    if "set " + SET_NAME not in sets:
        run_nft([
            "add", "set", "inet", TABLE, SET_NAME,
            "{", "type", "ipv4_addr;", "}", 
        ])

    chains = run_nft(["list", "chains", "inet", TABLE])

    if "chain input" not in chains:
        run_nft([
            "add", "chain", "inet", TABLE, "input",
            "{", "type", "filter", "hook", "input",
            "priority", "-10;", "policy", "accept;", "}",
        ])

    rules = run_nft(["list", "chain", "inet", TABLE, "input"])

    if "@" + SET_NAME not in rules:
        run_nft([
            "add", "rule", "inet", TABLE, "input",
            "ip", "saddr", "@" + SET_NAME, "drop",
        ])

    return True


def block_ip(value):
    ip = validate_ip(value)
    initialize_firewall()

    existing = run_nft([
        "list", "set", "inet", TABLE, SET_NAME
    ])

    if ip in existing:
        return {"ip": ip, "status": "already_blocked"}

    run_nft([
        "add", "element", "inet", TABLE, SET_NAME,
        "{", ip, "}",
    ])

    return {"ip": ip, "status": "blocked"}


def unblock_ip(value):
    ip = validate_ip(value)
    initialize_firewall()

    existing = run_nft([
        "list", "set", "inet", TABLE, SET_NAME
    ])

    if ip not in existing:
        return {"ip": ip, "status": "not_blocked"}

    run_nft([
        "delete", "element", "inet", TABLE, SET_NAME,
        "{", ip, "}",
    ])

    return {"ip": ip, "status": "unblocked"}


def list_blocked_ips():
    initialize_firewall()

    output = run_nft([
        "list", "set", "inet", TABLE, SET_NAME
    ])

    # Extract IPv4 addresses from the nftables set output.
    import re
    return sorted(set(re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output
    )))


def firewall_status():
    try:
        initialize_firewall()
        return {
            "available": True,
            "table": TABLE,
            "blocked_count": len(list_blocked_ips())
        }
    except Exception:
        return {
            "available": False,
            "table": TABLE,
            "blocked_count": 0
        }
