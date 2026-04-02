"""Beginner-friendly traffic explanation helper."""

from __future__ import annotations

from typing import Any, Dict


TCP_FLAG_EXPLANATIONS = {
    "SYN": "SYN means a connection attempt is starting and the sender wants to begin a TCP session.",
    "ACK": "ACK means the sender is acknowledging received data or confirming a TCP handshake step.",
    "FIN": "FIN means the sender wants to close the TCP session gracefully.",
}


def _describe_tcp_flags(tcp_flags: Any) -> str:
    if not tcp_flags:
        return ""

    flags = str(tcp_flags).split()
    explanations = []
    for flag in flags:
        explanation = TCP_FLAG_EXPLANATIONS.get(flag.upper())
        if explanation:
            explanations.append(explanation)
        else:
            explanations.append(f"{flag.upper()} is a TCP control flag.")

    if len(explanations) == 1:
        return explanations[0]

    return " ".join(explanations)


def explain_traffic(parsed_log: Dict[str, Any], osi_info: Dict[str, Any]) -> str:
    """Explain parsed network traffic in CCNA-friendly language."""

    protocol = parsed_log.get("protocol") or "Unknown"
    source_ip = parsed_log.get("source_ip") or "unknown source"
    destination_ip = parsed_log.get("destination_ip") or "unknown destination"
    source_port = parsed_log.get("source_port")
    destination_port = parsed_log.get("destination_port")
    tcp_flags = parsed_log.get("tcp_flags")

    layer_number = osi_info.get("layer_number")
    layer_name = osi_info.get("layer_name") or "Unknown layer"
    technical_explanation = osi_info.get("technical_explanation") or (
        "The protocol could not be mapped to a known OSI layer from the provided rules."
    )

    if source_port and destination_port:
        flow = f"{source_ip}:{source_port} to {destination_ip}:{destination_port}"
    elif source_port:
        flow = f"{source_ip}:{source_port} to {destination_ip}"
    elif destination_port:
        flow = f"{source_ip} to {destination_ip}:{destination_port}"
    else:
        flow = f"{source_ip} to {destination_ip}"

    flags_text = ""
    if tcp_flags:
        flag_explanation = _describe_tcp_flags(tcp_flags)
        flags_text = f" The TCP flags seen are {tcp_flags}. {flag_explanation}"

    layer_text = (
        f"Layer {layer_number} ({layer_name})"
        if layer_number is not None
        else layer_name
    )

    ccna_tip = (
        "Always match the protocol to the OSI layer first, then use the ports and "
        "flags to understand whether the session is starting, established, or closing."
    )

    return (
        f"Protocol: {protocol}\n"
        f"OSI layer: {layer_text}\n"
        f"What is happening: Traffic is flowing from {flow}.{flags_text}\n"
        f"Technical why: {technical_explanation}\n"
        f"CCNA tip: {ccna_tip}"
    )
