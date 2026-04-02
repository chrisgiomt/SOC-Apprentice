"""Simple network traffic log parser."""

from __future__ import annotations

import re
from typing import Dict, Optional


DEFAULT_FIELDS = {
    "protocol": None,
    "source_ip": None,
    "destination_ip": None,
    "source_port": None,
    "destination_port": None,
    "tcp_flags": None,
    "extra_info": None,
}

TCP_PATTERN = re.compile(
    r"^\s*"
    r"(?P<protocol>TCP)\s+"
    r"(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<source_port>\d+))?\s*"
    r"->\s*"
    r"(?P<destination_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<destination_port>\d+))?"
    r"(?:\s+(?P<tcp_flags>[A-Z]+(?:\s+[A-Z]+)*))?"
    r"\s*$",
    re.IGNORECASE,
)

UDP_PATTERN = re.compile(
    r"^\s*"
    r"(?P<protocol>UDP)\s+"
    r"(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<source_port>\d+))?\s*"
    r"->\s*"
    r"(?P<destination_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<destination_port>\d+))?"
    r"(?:\s+(?P<extra_info>[A-Z]+(?:\s+[A-Z]+)*))?"
    r"\s*$",
    re.IGNORECASE,
)

ICMP_PATTERN = re.compile(
    r"^\s*"
    r"(?P<protocol>ICMP)\s+"
    r"(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"\s*->\s*"
    r"(?P<destination_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:\s+(?P<extra_info>[A-Z][A-Z\s-]*))?"
    r"\s*$",
    re.IGNORECASE,
)

ARP_PATTERN = re.compile(
    r"^\s*"
    r"(?P<protocol>ARP)\s+"
    r"(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"\s*->\s*"
    r"(?P<destination_ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:\s+(?P<extra_info>[A-Z][A-Z\s-]*))?"
    r"\s*$",
    re.IGNORECASE,
)


def _empty_result() -> Dict[str, Optional[str]]:
    return dict(DEFAULT_FIELDS)


def _build_result(match: re.Match[str]) -> Dict[str, Optional[str]]:
    result = _empty_result()
    result["protocol"] = match.group("protocol").upper()
    result["source_ip"] = match.group("source_ip")
    result["destination_ip"] = match.group("destination_ip")
    group_names = match.re.groupindex
    result["source_port"] = match.group("source_port") if "source_port" in group_names else None
    result["destination_port"] = match.group("destination_port") if "destination_port" in group_names else None
    result["tcp_flags"] = match.group("tcp_flags") if "tcp_flags" in group_names else None
    result["extra_info"] = match.group("extra_info") if "extra_info" in group_names else None
    return result


def parse_log(log: str) -> Dict[str, Optional[str]]:
    """Parse a simple network traffic log into a dictionary.

    Missing fields are returned as None.
    """

    for pattern in (TCP_PATTERN, UDP_PATTERN, ICMP_PATTERN, ARP_PATTERN):
        match = pattern.match(log)
        if match:
            return _build_result(match)

    return _empty_result()
