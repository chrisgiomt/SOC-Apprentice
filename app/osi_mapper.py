"""Map parsed network logs to OSI layers."""

from __future__ import annotations

from typing import Any, Dict, Optional


OSI_LAYER_MAP = {
    "TCP": {
        "layer_number": 4,
        "layer_name": "Transport",
        "technical_explanation": "TCP is a transport-layer protocol responsible for reliable, ordered delivery of data between hosts.",
    },
    "UDP": {
        "layer_number": 4,
        "layer_name": "Transport",
        "technical_explanation": "UDP is a transport-layer protocol that provides lightweight, connectionless communication.",
    },
    "IP": {
        "layer_number": 3,
        "layer_name": "Network",
        "technical_explanation": "IP is a network-layer protocol used for logical addressing and routing packets between networks.",
    },
    "ICMP": {
        "layer_number": 3,
        "layer_name": "Network",
        "technical_explanation": "ICMP is a network-layer protocol used for control messages, diagnostics, and error reporting.",
    },
    "ARP": {
        "layer_number": 2,
        "layer_name": "Data Link",
        "technical_explanation": "ARP operates at the data-link layer to resolve network-layer addresses to hardware addresses on a local network.",
    },
}


def map_to_osi(parsed_log: dict) -> Dict[str, Optional[Any]]:
    """Map a parsed log dictionary to an OSI layer description."""

    protocol = parsed_log.get("protocol")
    if not protocol:
        return {
            "layer_number": None,
            "layer_name": None,
            "technical_explanation": None,
        }

    layer_info = OSI_LAYER_MAP.get(str(protocol).upper())
    if layer_info is None:
        return {
            "layer_number": None,
            "layer_name": None,
            "technical_explanation": None,
        }

    return dict(layer_info)
