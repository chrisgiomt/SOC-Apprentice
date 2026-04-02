"""Terminal entrypoint for parsing and explaining network logs."""

from __future__ import annotations

try:
    from .explainer import explain_traffic
    from .log_parser import parse_log
    from .osi_mapper import map_to_osi
except ImportError:
    from explainer import explain_traffic
    from log_parser import parse_log
    from osi_mapper import map_to_osi


def main() -> None:
    """Read a log from the terminal and print a plain-English explanation."""

    log = input("Enter a network traffic log: ").strip()
    parsed_log = parse_log(log)
    osi_info = map_to_osi(parsed_log)
    explanation = explain_traffic(parsed_log, osi_info)
    print(explanation)


if __name__ == "__main__":
    main()
