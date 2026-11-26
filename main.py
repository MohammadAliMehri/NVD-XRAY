import argparse
import json
from typing import Any

from reporting import format_report
from service import ResearchInputError, research_report


MAX_TRACE_RESULT_LENGTH = 6000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Research NVD records and produce a concise vulnerability brief.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--cve-id", help="Exact CVE identifier, for example CVE-2021-44228.")
    mode.add_argument(
        "--query", help="Product or vulnerability keyword search.")
    parser.add_argument("--trace", action="store_true",
                        help="Include tool calls and NVD results for debugging.")
    parser.add_argument("--json", action="store_true",
                        help="Print the validated report as JSON.")
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
                print(
                    f"... [tool result truncated; {len(content)} characters total]")


def main() -> int:
    args = build_parser().parse_args()
    query = args.cve_id.strip() if args.cve_id else args.query.strip()
    try:
        report, result = research_report(query)
    except ResearchInputError as exc:
        print(f"Invalid request: {exc}")
        return 2
    except Exception as exc:
        print(f"NVD-XRAY could not complete the research: {exc}")
        return 1

    if args.trace:
        print_trace(result.get("messages", []))

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
