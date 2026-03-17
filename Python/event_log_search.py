#!/usr/bin/env python3
##################################################################################
#
# event_log_search.py - Search Windows Event Logs for usernames, hostnames,
# IPs, event IDs, or any text pattern. Supports JSON/CSV export and filtering
# by log, event type, event ID, and time window.
#
# Version: 1.0
#
# Requires: pip install pywin32
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: python event_log_search.py --help
#
##################################################################################
"""Windows Event Log Search Tool | By: UberGuidoZ"""

import argparse
import json
import csv
import sys
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import pywintypes
except ImportError:
    print("ERROR: pywin32 is required. Install with: pip install pywin32", file=sys.stderr)
    sys.exit(1)


# Event type/level mappings
EVENT_TYPES = {
    win32con.EVENTLOG_ERROR_TYPE: "ERROR",
    win32con.EVENTLOG_WARNING_TYPE: "WARNING",
    win32con.EVENTLOG_INFORMATION_TYPE: "INFORMATION",
    win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
    win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
}

COMMON_LOGS = ["Application", "System", "Security", "Setup"]


def get_event_type_name(event_type: int) -> str:
    """Convert event type code to human-readable name."""
    return EVENT_TYPES.get(event_type, f"UNKNOWN({event_type})")


def read_events(
    log_name: str,
    search_term: Optional[str] = None,
    event_id: Optional[int] = None,
    event_type: Optional[str] = None,
    hours_back: Optional[int] = None,
    max_results: int = 100,
    case_sensitive: bool = False,
) -> List[Dict[str, Any]]:
    """
    Read and filter events from a Windows Event Log.
    
    Args:
        log_name: Name of the log (e.g., 'Application', 'System', 'Security')
        search_term: Text to search for in event messages/data
        event_id: Filter by specific Event ID
        event_type: Filter by event type (ERROR, WARNING, INFORMATION, etc.)
        hours_back: Only include events from last N hours
        max_results: Maximum number of results to return
        case_sensitive: Whether search is case-sensitive
        
    Returns:
        List of matching event dictionaries
    """
    events = []
    
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
    except pywintypes.error as e:
        print(f"ERROR: Cannot open log '{log_name}': {e}", file=sys.stderr)
        return events
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    # Calculate time threshold if hours_back is specified
    time_threshold = None
    if hours_back is not None:
        time_threshold = datetime.now() - timedelta(hours=hours_back)
    
    # Compile search pattern
    search_pattern = None
    if search_term:
        flags_re = 0 if case_sensitive else re.IGNORECASE
        try:
            search_pattern = re.compile(re.escape(search_term), flags_re)
        except re.error as e:
            print(f"WARNING: Invalid search pattern: {e}", file=sys.stderr)
            search_pattern = None
    
    try:
        while len(events) < max_results:
            event_records = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if not event_records:
                break
            
            for event in event_records:
                # Apply time filter
                if time_threshold and event.TimeGenerated < time_threshold:
                    continue
                
                # Apply event ID filter
                if event_id is not None and event.EventID != event_id:
                    continue
                
                # Apply event type filter
                event_type_name = get_event_type_name(event.EventType)
                if event_type and event_type.upper() not in event_type_name:
                    continue
                
                # Get event message
                try:
                    message = win32evtlogutil.SafeFormatMessage(event, log_name)
                except Exception:
                    message = "Unable to format message"
                
                # Apply search term filter
                if search_pattern:
                    # Search in message, source name, and string data
                    searchable_text = message + " " + (event.SourceName or "")
                    if event.StringInserts:
                        searchable_text += " " + " ".join(str(s) for s in event.StringInserts if s)
                    
                    if not search_pattern.search(searchable_text):
                        continue
                
                # Build event dictionary
                event_dict = {
                    "log": log_name,
                    "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "source": event.SourceName,
                    "event_id": event.EventID,
                    "type": event_type_name,
                    "category": event.EventCategory,
                    "computer": event.ComputerName,
                    "message": message.strip() if message else "",
                }
                
                # Add string inserts if present
                if event.StringInserts:
                    event_dict["data"] = [str(s) for s in event.StringInserts if s]
                
                events.append(event_dict)
                
                if len(events) >= max_results:
                    break
    
    finally:
        win32evtlog.CloseEventLog(hand)
    
    return events


def format_event_console(event: Dict[str, Any], include_data: bool = True) -> str:
    """Format an event for console display."""
    lines = [
        "=" * 80,
        f"Time:     {event['time']}",
        f"Log:      {event['log']}",
        f"Source:   {event['source']}",
        f"Event ID: {event['event_id']}",
        f"Type:     {event['type']}",
        f"Computer: {event['computer']}",
        "-" * 80,
        f"Message:\n{event['message']}",
    ]
    
    if include_data and "data" in event and event["data"]:
        lines.append("-" * 80)
        lines.append("Additional Data:")
        for i, data_item in enumerate(event["data"], 1):
            lines.append(f"  [{i}] {data_item}")
    
    return "\n".join(lines)


def export_json(events: List[Dict[str, Any]], output_path: Path) -> None:
    """Export events to JSON file."""
    try:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
        print(f"Exported {len(events)} events to {output_path}")
    except Exception as e:
        print(f"ERROR: Failed to write JSON: {e}", file=sys.stderr)
        sys.exit(1)


def export_csv(events: List[Dict[str, Any]], output_path: Path) -> None:
    """Export events to CSV file."""
    if not events:
        print("No events to export")
        return
    
    try:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            # Get all possible fields
            fieldnames = ["log", "time", "source", "event_id", "type", "category", "computer", "message", "data"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            
            writer.writeheader()
            for event in events:
                # Convert data list to string if present
                if "data" in event:
                    event["data"] = " | ".join(event["data"])
                writer.writerow(event)
        
        print(f"Exported {len(events)} events to {output_path}")
    except Exception as e:
        print(f"ERROR: Failed to write CSV: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "event_log_search.py (UberGuidoZ) | https://github.com/UberGuidoZ/Scripts\n"
            "\n"
            "Search Windows Event Logs for usernames, hostnames, IPs, event IDs,\n"
            "or any text pattern. Iterates through matching events and displays\n"
            "results with full context (timestamp, source, event ID, message).\n"
            "Supports JSON and CSV export for further analysis.\n"
            "\n"
            "Must be run as Administrator to access the Security log.\n"
            "Requires: pip install pywin32"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PARAMETERS:
  --logs LOG [LOG ...]       Event log name(s) to search.
                             Default: Application System Security Setup
  --search, -s TERM         Text to search for in event messages and data.
                             Accepts usernames, hostnames, IPs, or any keyword.
  --event-id, -e ID         Filter by a specific Event ID (e.g., 4625).
  --type, -t TYPE           Filter by event type/level.
                             Choices: ERROR WARNING INFORMATION AUDIT_SUCCESS AUDIT_FAILURE
  --hours N                 Only include events from the last N hours.
  --max, -m N               Maximum results to return per log. Default: 100
  --case-sensitive          Make the --search match case-sensitive.
  --output, -o FILE         Export results to a file. Must end in .json or .csv
  --no-data                 Suppress additional data fields in console output.

OUTPUT:
  Console output per event includes:
    Time, Log, Source, Event ID, Type, Computer, Message, Additional Data
  JSON export  : array of event objects with all fields
  CSV export   : one row per event; data fields joined with ' | '

NOTES:
  - Must be run as Administrator to read the Security log
  - At least one filter must be specified: --search, --event-id, --type, or --hours
  - Events are sorted newest-first in both console and export output
  - Common Security Event IDs:
      4624  Successful logon       4625  Failed logon
      4648  Explicit credential logon    4720  User account created
      4740  Account locked out     4776  Credential validation

EXAMPLES:
  Search all common logs for a username
  python event_log_search.py --search "john.doe"

  Search Security log for failed logon attempts (Event ID 4625)
  python event_log_search.py --logs Security --event-id 4625

  Search Security log for an IP address in the last 24 hours
  python event_log_search.py --logs Security --search "192.168.1.50" --hours 24

  Search System log for a hostname in the last 48 hours
  python event_log_search.py --logs System --search "SERVER01" --hours 48

  Find all errors in Application log (limit 50)
  python event_log_search.py --logs Application --type ERROR --max 50

  Search multiple logs for authentication issues
  python event_log_search.py --logs Security System --search "authentication" --hours 24

  Export successful logon events to CSV
  python event_log_search.py --logs Security --event-id 4624 --hours 12 --output logon_events.csv

  Export error events to JSON
  python event_log_search.py --search "failure" --type ERROR --output results.json

  Case-sensitive search
  python event_log_search.py --search "CriticalError" --case-sensitive
""",
    )
    
    parser.add_argument(
        "--logs",
        nargs="+",
        default=COMMON_LOGS,
        help=f"Event log name(s) to search (default: {', '.join(COMMON_LOGS)})",
    )
    parser.add_argument(
        "--search",
        "-s",
        help="Search term (username, hostname, IP, keyword, etc.)",
    )
    parser.add_argument(
        "--event-id",
        "-e",
        type=int,
        help="Filter by Event ID",
    )
    parser.add_argument(
        "--type",
        "-t",
        choices=["ERROR", "WARNING", "INFORMATION", "AUDIT_SUCCESS", "AUDIT_FAILURE"],
        help="Filter by event type/level",
    )
    parser.add_argument(
        "--hours",
        type=int,
        help="Only show events from last N hours",
    )
    parser.add_argument(
        "--max",
        "-m",
        type=int,
        default=100,
        help="Maximum results per log (default: 100)",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Make search case-sensitive",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Export results to file (.json or .csv)",
    )
    parser.add_argument(
        "--no-data",
        action="store_true",
        help="Don't display additional data fields in console output",
    )
    
    args = parser.parse_args()
    
    # Validate: must have at least one search criterion
    if not any([args.search, args.event_id, args.type, args.hours]):
        print("ERROR: Must specify at least one search criterion (--search, --event-id, --type, or --hours)", 
              file=sys.stderr)
        return 1
    
    all_events = []
    
    print(f"Searching {len(args.logs)} log(s)...\n")
    
    for log_name in args.logs:
        print(f"Searching log: {log_name}")
        events = read_events(
            log_name=log_name,
            search_term=args.search,
            event_id=args.event_id,
            event_type=args.type,
            hours_back=args.hours,
            max_results=args.max,
            case_sensitive=args.case_sensitive,
        )
        
        print(f"  Found {len(events)} matching event(s)\n")
        all_events.extend(events)
    
    # Sort by time (newest first)
    all_events.sort(key=lambda x: x["time"], reverse=True)
    
    print(f"Total matching events: {len(all_events)}\n")
    
    if not all_events:
        print("No matching events found.")
        return 0
    
    # Export if requested
    if args.output:
        if args.output.suffix.lower() == ".json":
            export_json(all_events, args.output)
        elif args.output.suffix.lower() == ".csv":
            export_csv(all_events, args.output)
        else:
            print("ERROR: Output file must have .json or .csv extension", file=sys.stderr)
            return 1
    
    # Display to console
    print("\nEvent Details:")
    print("=" * 80)
    for event in all_events:
        print(format_event_console(event, include_data=not args.no_data))
    
    return 0


if __name__ == "__main__":
    sys.exit(main())