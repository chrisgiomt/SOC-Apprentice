# SOC-Apprentice

AI-powered senior network engineer assistant that analyzes logs, maps issues to OSI layers, and explains traffic behavior for CCNA learners.

Current Version: 1

App Returns:
  1. Protocol identified
  2. OSI layer identified
  3. plain-English explanation
  4. technical reason
  5. CCNA learning note

Example:

Input:

```TCP 192.168.1.10:443 -> 10.0.0.5:52344 SYN ACK```

Output:

```
Protocol: TCP 
OSI Layer: Layer 4 (Transport)

Explanation:
This is part of the TCP three-way handshake.

Why:
SYN ACK means the destination acknowledges connection setup.

CCNA Note:
TCP uses reliability through sequence control.
```

# Roadmap

Planned updates:
- PCAP support
- Wireshark integration
- Routing protocol analysis
- VLAN troubleshooting
