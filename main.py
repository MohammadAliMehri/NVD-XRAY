import argparse
import json
import re
from typing import Any

from agent import research
from schemas import VulnerabilityReport


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_TRACE_RESULT_LENGTH = 6000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search NVD and generate a validated vulnerability brief.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cve-id", help="Exact CVE identifier, for example CVE-2021-44228.")
    mode.add_argument("--query", help="Product or vulnerability keyword search.")
    parser.add_argument("--hide-trace", action="store_true", help="Do not print model tool calls and tool results.")
    return parser


def print_trace(messages: list[Any]) -> None:
    print("\n=== Agent Trace ===")
    for message in messages:
        tool_calls = getattr(message, "tool_calls", None) or []
        for call in tool_calls:
            print(f"TOOL CALL: {call.get('name')}")
            print(json.dumps(call.get("args", {}), indent=2, ensure_ascii=False))
        if type(message).__name__ == "ToolMessage":
            print(f"TOOL RESULT ({getattr(message, 'name', 'unknown')}):")
            content = str(message.content)
            print(content[:MAX_TRACE_RESULT_LENGTH])
            if len(content) > MAX_TRACE_RESULT_LENGTH:
                print(f"... [tool result truncated; {len(content)} characters total]")


def validated_report(result: dict[str, Any]) -> VulnerabilityReport:
    response = result.get("structured_response")
    if isinstance(response, VulnerabilityReport):
        return response
    if isinstance(response, dict):
        return VulnerabilityReport.model_validate(response)
    raise RuntimeError("The agent did not return a structured response.")


def main() -> int:
    args = build_parser().parse_args()
    cve_id = args.cve_id.strip() if args.cve_id else ""
    if cve_id and not CVE_PATTERN.fullmatch(cve_id):
        print("Invalid CVE identifier. Expected format: CVE-YYYY-NNNN or longer.")
        return 2

    query = f"Research exact CVE {cve_id}." if cve_id else f"Search NVD for: {args.query}"
    result = research(query)
    if not args.hide_trace:
        print_trace(result.get("messages", []))

    report = validated_report(result)
    print("\n=== Validated Report ===")
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
