"""Collect Windows netstat TCP connections, excluding remote loopback/unspecified IPs."""

import ipaddress
import subprocess


def _endpoint(value: str) -> tuple[str, str]:
    host, separator, port = value.rpartition(":")
    if not separator or not port.isascii() or not port.isdigit():
        raise ValueError("Invalid endpoint port")
    if not 0 <= int(port) <= 65535:
        raise ValueError("Endpoint port out of range")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    ipaddress.ip_address(host)
    return host, port


def parse_netstat(output: str) -> list[dict[str, str]]:
    connections = []
    for line in output.splitlines():
        columns = line.strip().split()
        if len(columns) != 5:
            continue
        protocol, local, remote, state, pid = columns
        if protocol != "TCP" or state != "ESTABLISHED":
            continue
        if not pid.isascii() or not pid.isdigit():
            continue
        try:
            local_ip, local_port = _endpoint(local)
            remote_ip, remote_port = _endpoint(remote)
            address = ipaddress.ip_address(remote_ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if address.is_loopback or address.is_unspecified:
                continue
        except ValueError:
            continue
        connections.append({
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
        })
    return connections


def scan_connections() -> list[dict[str, str]]:
    result = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True,
        errors="replace", check=True, timeout=15,
    )
    return parse_netstat(result.stdout)
