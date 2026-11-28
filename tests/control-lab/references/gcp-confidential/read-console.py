from pathlib import Path
import json
import re
import sys

schemas = {"saf-cs-cpu-reference/v1", "saf-cs-h100-reference/v1"}
serial = Path(sys.argv[1]).read_bytes()
# The serial device can splice a full, timestamped kernel line into an
# application record. Remove those independent lines without altering payloads.
serial = re.sub(rb"\[[ \t]*\d+\.\d{6}\][^\n]*\n", b"", serial)
text = serial.decode("utf-8", "replace")
decoder = json.JSONDecoder()
rows = []
for match in re.finditer(r'\{"schema":"saf-cs-(?:cpu|h100)-reference/v1"', text):
    try:
        row, _ = decoder.raw_decode(text[match.start():])
    except json.JSONDecodeError:
        continue
    if row.get("schema") in schemas:
        rows.append(row)
for row in rows:
    print(json.dumps(row, sort_keys=True, separators=(",", ":")))
