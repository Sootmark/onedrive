"""One TSV line per event plaso wrote (psort -o json_line), sorted.

Columns: kind, file, time (Unix milliseconds), then for sync engine logs
(onedrive_log) the source file, function, raw parameters in hexadecimal and
each decoded parameter; for SkyDrive text logs (text/skydrive_log_v1, _v2)
the level, module, source and detail. Version 2 details have their
whitespace collapsed: plaso joins a message's lines with spaces irregularly.
Control characters and backslashes are written as \\xNN.

Usage: python3 -I plaso_tsv.py out.jsonl > plaso.tsv
"""

import calendar
import json
import sys

KINDS = {
    "onedrive_log": "odl",
    "text/skydrive_log_v1": "v1",
    "text/skydrive_log_v2": "v2",
}


def escape(text):
    if text is None:
        return ""
    return "".join(
        f"\\x{ord(c):02x}" if ord(c) < 0x20 or c == "\\" else c for c in text
    )


def millis(date_time):
    if "timestamp" in date_time:
        return date_time["timestamp"]
    year, month, day, hour, minute, second, milli = date_time["time_elements_tuple"]
    seconds = calendar.timegm((year, month, day, hour, minute, second))
    return seconds * 1000 + milli


def row(event):
    kind = KINDS[event["parser"]]
    name = event["display_name"].rsplit("/", 1)[-1]
    columns = [kind, name, str(millis(event["date_time"]))]
    if kind == "odl":
        columns += [
            event["code_filename"],
            event["code_function_name"],
            event["raw_parameters"],
        ]
        columns += event["decoded_parameters"]
    else:
        detail = event.get("detail") or ""
        if kind == "v2":
            detail = " ".join(detail.split())
        columns += [
            event.get("log_level"),
            event.get("module"),
            event.get("source_code"),
            detail,
        ]
    return "\t".join(escape(c) for c in columns)


def main():
    with open(sys.argv[1], encoding="utf-8") as lines:
        rows = sorted(row(json.loads(line)) for line in lines)
    sys.stdout.write("".join(r + "\n" for r in rows))


if __name__ == "__main__":
    main()
