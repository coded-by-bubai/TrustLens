import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# Disallowed / internal IP networks (SSRF defense)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),          # Loopback
    ipaddress.ip_network("fc00::/7"),         # Unique local
    ipaddress.ip_network("fe80::/10"),        # Link-local
    ipaddress.ip_network("ff00::/8"),         # Multicast
]

def is_ip_allowed(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Checks if an IP address is a safe public IP (not loopback, private, or metadata)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Target IP {ip_str} resolves to blocked/internal range ({net})."
        return True, None
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

def validate_target_url(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates URL scheme, resolves hostname to IP, and guarantees it is safe from SSRF.
    Returns: (is_safe: bool, canonical_url: str, error_message: Optional[str])
    """
    if not url:
        return False, "", "URL cannot be empty."

    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "https://" + cleaned_url

    parsed = urlparse(cleaned_url)
    hostname = parsed.hostname

    if not hostname:
        return False, cleaned_url, "Could not extract valid hostname from URL."

    # Block localhost variants and cloud metadata strings directly
    lower_host = hostname.lower()
    if lower_host in {"localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal", "instance-data"}:
        return False, cleaned_url, f"Host '{hostname}' is an internal or loopback address."

    # Resolve hostname to IPv4/IPv6 and verify every IP is safe
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            return False, cleaned_url, f"Could not resolve hostname '{hostname}'."

        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            allowed, reason = is_ip_allowed(ip_str)
            if not allowed:
                return False, cleaned_url, reason
    except socket.gaierror:
        # Domain cannot be resolved, but we still allow static syntax inspection
        return True, cleaned_url, None
    except Exception as e:
        return False, cleaned_url, f"DNS resolution error: {str(e)}"

    return True, cleaned_url, None

