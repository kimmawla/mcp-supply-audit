# Tool-definition rules (input: a tools/list JSON snapshot)

| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| TD001 | Hidden Unicode: zero-width, bidi controls, tag characters in name/description/params | high | high |
| TD002 | Instruction-like phrasing aimed at the model ("ignore previous", "do not tell the user", "before using this tool...") | high | medium |
| TD003 | Description references other tools or servers by name | medium | medium |
| TD004 | URLs or "send/post to" exfil phrasing in a description | medium | medium |
| TD005 | Long encoded blobs (base64/hex runs) | medium | medium |
| TD006 | Excessive description length (threshold in config) | low | high |
| TD007 | Free-text parameters whose names invite conversation content ("notes", "context", "sidenote") | low | low |
| TD008 | Duplicate tool names within one snapshot | medium | high |

Each rule: pure function, one fixture file of positives, one of benign negatives.
Phrase lists live in data files, not code, so they can be reviewed and versioned.