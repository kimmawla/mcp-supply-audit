"""TD001-TD008: tool-definition rules over a parsed tools/list snapshot.

Rules live in docs/rules-tool-definitions.md; read it before changing this. Every rule is
a pure function from a snapshot to a list of Findings. Phrase lists and thresholds live in
data/*.yaml. Locations name tools and fields by index, never by their (hostile) text;
target text appears only as Finding.evidence, which to_dict() escapes under untrusted_text.
"""

import functools
import logging
import re
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.findings import (
    Confidence,
    Coverage,
    Finding,
    Report,
    Severity,
    SkippedCheck,
    SkipReason,
    build_report,
)
from mcp_supply_audit.hidden_chars import hidden_class
from mcp_supply_audit.validation import (
    TOOLS_LIST_NOT_CONTAINER,
    validate_tools_list_json,
)

logger = logging.getLogger(__name__)

Snapshot = Mapping[str, Any] | Sequence[Any]


# ---------------------------------------------------------------------------
# Rule metadata


@dataclass(frozen=True)
class RuleMeta:
    title: str
    severity: Severity
    confidence: Confidence
    owasp: tuple[str, ...]
    remediation: str


RULES_META: Final[Mapping[str, RuleMeta]] = {
    "TD001": RuleMeta(
        "Hidden characters",
        Severity.HIGH,
        Confidence.HIGH,
        ("MCP03:2025", "MCP06:2025"),
        "Remove the hidden characters; tool metadata should be plain visible text.",
    ),
    "TD002": RuleMeta(
        "Instruction-like phrasing aimed at the model",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("MCP03:2025", "MCP06:2025"),
        "Rewrite the text to describe what the tool does, without directives to the model.",
    ),
    "TD003": RuleMeta(
        "Reference to tools or servers outside this server",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("MCP03:2025",),
        "Describe only this tool; do not refer to tools or servers it does not provide.",
    ),
    "TD004": RuleMeta(
        "URL or exfiltration phrasing",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("MCP03:2025", "MCP10:2025"),
        "Remove the URL or send-to phrasing, or confirm the destination is expected.",
    ),
    "TD005": RuleMeta(
        "Long encoded blob",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("MCP03:2025", "MCP06:2025"),
        "Decode and review the blob, and remove it from the tool metadata.",
    ),
    "TD006": RuleMeta(
        "Excessive description length",
        Severity.LOW,
        Confidence.HIGH,
        ("MCP03:2025",),
        "Shorten the description and review the extra text for hidden instructions.",
    ),
    "TD007": RuleMeta(
        "Free-text parameter that invites conversation content",
        Severity.LOW,
        Confidence.LOW,
        ("MCP10:2025", "MCP03:2025"),
        "Confirm the parameter needs free text, and rename or constrain it if not.",
    ),
    "TD008": RuleMeta(
        "Duplicate tool name",
        Severity.MEDIUM,
        Confidence.HIGH,
        ("MCP03:2025",),
        "Give every tool a unique name; a duplicate can shadow the original.",
    ),
}


# ---------------------------------------------------------------------------
# Rule data (data/*.yaml)


class RuleDataError(ValueError):
    """A rule data file is malformed."""


@functools.cache
def load_rule_data(filename: str) -> Mapping[str, Any]:
    raw = (
        resources.files("mcp_supply_audit")
        .joinpath("data", filename)
        .read_text(encoding="utf-8")
    )
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or data.get("version") != 1:
        raise RuleDataError(f"{filename}: expected a mapping with version: 1")
    return data


def _string_list(filename: str, key: str) -> tuple[str, ...]:
    values = load_rule_data(filename).get(key)
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(v, str) and v.strip() for v in values)
    ):
        raise RuleDataError(f"{filename}: {key} must be a non-empty list of strings")
    return tuple(values)


def _positive_int(filename: str, key: str) -> int:
    value = load_rule_data(filename).get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuleDataError(f"{filename}: {key} must be a positive integer")
    return value


# ---------------------------------------------------------------------------
# Text normalization for phrase matching

# Class names from hidden_chars that render as blank space rather than nothing.
_BLANK_CLASSES: Final = frozenset({"braille_blank", "hangul_filler"})


@dataclass(frozen=True)
class _Normalized:
    text: str
    # origin[i] is the index in the source text that produced text[i].
    origin: tuple[int, ...]


def _normalize(text: str, *, casefold: bool) -> _Normalized:
    """NFKC per character, hidden characters dropped, whitespace collapsed to one space.

    Lets "ign<zero-width>ore" and fullwidth letters match a phrase, while keeping a map
    back to source offsets for evidence_start.
    """
    out: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        cls = hidden_class(ch)
        if ch.isspace() or cls in _BLANK_CLASSES:
            if out and out[-1] != " ":
                out.append(" ")
                origin.append(i)
            continue
        if cls is not None:
            continue
        mapped = unicodedata.normalize("NFKC", ch)
        if casefold:
            mapped = mapped.casefold()
        for m in mapped:
            out.append(m)
            origin.append(i)
    if out and out[-1] == " ":
        out.pop()
        origin.pop()
    return _Normalized("".join(out), tuple(origin))


_GAP: Final = r"(?:\S+ ){0,3}"


@functools.cache
def _phrase_regex(phrases: tuple[str, ...]) -> re.Pattern[str]:
    parts = []
    for phrase in phrases:
        words = _normalize(phrase, casefold=True).text.split(" ")
        if words[0] == "*" or words[-1] == "*":
            raise RuleDataError(f"phrase may not start or end with '*': {phrase!r}")
        pattern = ""
        for i, word in enumerate(words):
            if word == "*":
                pattern += _GAP
            else:
                pattern += re.escape(word) + (" " if i < len(words) - 1 else "")
        parts.append(pattern)
    parts.sort(key=len, reverse=True)
    return re.compile(rf"(?<!\w)(?:{'|'.join(parts)})(?!\w)")


# ---------------------------------------------------------------------------
# Snapshot traversal


@dataclass(frozen=True)
class _Field:
    tool_index: int
    path: tuple[str, ...]
    # tool_name, param_name, schema_key, description, title, value, value_key
    kind: str
    text: str
    section: str = "tool"  # tool, inputSchema, outputSchema
    schema: Any = None  # the property schema, for param_name fields

    @property
    def location(self) -> str:
        # Index segments attach without a dot: tools[0].enum[1], not enum.[1].
        out = f"tools[{self.tool_index}]"
        for seg in self.path:
            out += seg if seg.startswith("[") else "." + seg
        return out


_NAME_KINDS: Final = frozenset({"tool_name", "param_name", "schema_key"})
_DESCRIPTIVE_KINDS: Final = frozenset({"description", "title"})
_PROSE_KINDS: Final = frozenset({"description", "title", "value", "value_key"})

_KIND_LABELS: Final = {
    "tool_name": "tool name",
    "param_name": "parameter name",
    "schema_key": "schema key",
    "description": "description",
    "title": "title",
    "value": "schema value",
    "value_key": "schema value key",
}

# Schema keywords whose value is a single subschema / a list of them / a map of them.
_SUBSCHEMA: Final = (
    "items",
    "additionalProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
)
_SUBSCHEMA_LISTS: Final = ("items", "prefixItems", "anyOf", "oneOf", "allOf")
_SUBSCHEMA_MAPS: Final = ("patternProperties", "$defs", "definitions")
_VALUE_KEYWORDS: Final = ("enum", "default", "const", "examples")


def tool_entries(snapshot: Snapshot) -> list[tuple[int, Any]]:
    """Return (index, entry) for every entry in the snapshot's tools array.

    Accepts {"tools": [...]}, a JSON-RPC {"result": {"tools": [...]}}, or a bare list.
    Raises TypeError if there is no tools array.
    """
    tools: Any = None
    if isinstance(snapshot, list):
        tools = snapshot
    elif isinstance(snapshot, Mapping):
        tools = snapshot.get("tools")
        result = snapshot.get("result")
        if tools is None and isinstance(result, Mapping):
            tools = result.get("tools")
    if not isinstance(tools, list):
        raise TypeError("snapshot has no tools array")
    return list(enumerate(tools))


def _tools(snapshot: Snapshot) -> Iterator[tuple[int, Mapping[str, Any]]]:
    for i, tool in tool_entries(snapshot):
        if isinstance(tool, Mapping):
            yield i, tool


def _iter_values(
    value: Any, path: tuple[str, ...], tool_index: int, section: str
) -> Iterator[_Field]:
    stack = [(value, path)]
    while stack:
        node, p = stack.pop()
        if isinstance(node, str):
            yield _Field(tool_index, p, "value", node, section)
        elif isinstance(node, list):
            stack.extend((v, (*p, f"[{k}]")) for k, v in enumerate(node))
        elif isinstance(node, Mapping):
            for k, (key, v) in enumerate(node.items()):
                if isinstance(key, str):
                    yield _Field(
                        tool_index, (*p, f"[{k}]", "(key)"), "value_key", key, section
                    )
                stack.append((v, (*p, f"[{k}]")))


def _iter_schema(
    schema: Any, path: tuple[str, ...], tool_index: int, section: str
) -> Iterator[_Field]:
    stack = [(schema, path)]
    while stack:
        node, p = stack.pop()
        if not isinstance(node, Mapping):
            continue
        for key in ("description", "title"):
            if isinstance(node.get(key), str):
                yield _Field(tool_index, (*p, key), key, node[key], section)
        for key in _VALUE_KEYWORDS:
            if key in node:
                yield from _iter_values(node[key], (*p, key), tool_index, section)
        props = node.get("properties")
        if isinstance(props, Mapping):
            for k, (name, sub) in enumerate(props.items()):
                prop_path = (*p, f"properties[{k}]")
                if isinstance(name, str):
                    yield _Field(
                        tool_index,
                        (*prop_path, "(key)"),
                        "param_name",
                        name,
                        section,
                        sub,
                    )
                stack.append((sub, prop_path))
        for key in _SUBSCHEMA_MAPS:
            sub_map = node.get(key)
            if isinstance(sub_map, Mapping):
                for k, (name, sub) in enumerate(sub_map.items()):
                    sub_path = (*p, f"{key}[{k}]")
                    if isinstance(name, str):
                        yield _Field(
                            tool_index,
                            (*sub_path, "(key)"),
                            "schema_key",
                            name,
                            section,
                        )
                    stack.append((sub, sub_path))
        for key in _SUBSCHEMA:
            if isinstance(node.get(key), Mapping):
                stack.append((node[key], (*p, key)))
        for key in _SUBSCHEMA_LISTS:
            if isinstance(node.get(key), list):
                stack.extend(
                    (sub, (*p, f"{key}[{k}]")) for k, sub in enumerate(node[key])
                )


def iter_fields(snapshot: Snapshot) -> Iterator[_Field]:
    """Every string a client may show the model: names, descriptions, titles, and schema
    keys and values at any depth of inputSchema and outputSchema."""
    for i, tool in _tools(snapshot):
        for key, kind in (
            ("name", "tool_name"),
            ("title", "title"),
            ("description", "description"),
        ):
            if isinstance(tool.get(key), str):
                yield _Field(i, (key,), kind, tool[key])
        annotations = tool.get("annotations")
        if isinstance(annotations, Mapping) and isinstance(
            annotations.get("title"), str
        ):
            yield _Field(i, ("annotations", "title"), "title", annotations["title"])
        for section in ("inputSchema", "outputSchema"):
            yield from _iter_schema(tool.get(section), (section,), i, section)


def _finding(
    rule_id: str,
    field: _Field,
    start: int,
    title: str | None = None,
    location: str | None = None,
) -> Finding:
    meta = RULES_META[rule_id]
    return Finding(
        rule_id=rule_id,
        title=title or f"{meta.title} in {_KIND_LABELS[field.kind]}",
        severity=meta.severity,
        confidence=meta.confidence,
        owasp=meta.owasp,
        location=location or f"{field.location}@{start}",
        evidence=field.text,
        remediation=meta.remediation,
        evidence_start=start,
    )


# ---------------------------------------------------------------------------
# Rules


def td001_hidden_characters(snapshot: Snapshot) -> list[Finding]:
    """TD001: hidden characters, as classified by hidden_chars.hidden_class, in any field."""
    findings = []
    for field in iter_fields(snapshot):
        first: int | None = None
        classes: set[str] = set()
        for i, ch in enumerate(field.text):
            cls = hidden_class(ch)
            if cls is not None:
                classes.add(cls)
                if first is None:
                    first = i
        if first is not None:
            title = (
                f"{RULES_META['TD001'].title} in {_KIND_LABELS[field.kind]}: "
                + ", ".join(sorted(classes))
            )
            findings.append(_finding("TD001", field, first, title))
    return findings


def _phrase_rule(
    rule_id: str, snapshot: Snapshot, phrases: Sequence[str], kinds: frozenset[str]
) -> list[Finding]:
    pattern = _phrase_regex(tuple(phrases))
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in kinds:
            continue
        norm = _normalize(field.text, casefold=True)
        match = pattern.search(norm.text)
        if match:
            findings.append(_finding(rule_id, field, norm.origin[match.start()]))
    return findings


def td002_instruction_phrasing(
    snapshot: Snapshot, phrases: Sequence[str] | None = None
) -> list[Finding]:
    """TD002: phrasing that directs the model (override, concealment, ordering)."""
    if phrases is None:
        phrases = _string_list("td002_instruction_phrases.yaml", "phrases")
    return _phrase_rule("TD002", snapshot, phrases, _PROSE_KINDS)


# "send_email tool", "`get-forecast` tool", "tool named x_y", "server called 'x'".
_TOOL_REF_RE: Final = re.compile(
    r"(?<![\w.-])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?:\(\))? tool(?!\w)"
    r"|[`'\"]([a-z][\w.-]*)[`'\"] tool(?!\w)"
    r"|(?<!\w)tool (?:named|called) (?:[`'\"]([^`'\"\s]+)[`'\"]|([a-z0-9]+(?:[_.-][a-z0-9]+)+))"
)
_SERVER_REF_RE: Final = re.compile(
    r"(?<!\w)server (?:named|called) (?:[`'\"][^`'\"\s]+[`'\"]|[a-z0-9]+(?:[_.-][a-z0-9]+)+)"
)


def td003_cross_references(
    snapshot: Snapshot, phrases: Sequence[str] | None = None
) -> list[Finding]:
    """TD003: references to tools not in this snapshot, or to other servers."""
    if phrases is None:
        phrases = _string_list("td003_cross_references.yaml", "phrases")
    pattern = _phrase_regex(tuple(phrases))
    own_names = {
        _normalize(t["name"], casefold=True).text
        for _, t in _tools(snapshot)
        if isinstance(t.get("name"), str)
    }
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in _PROSE_KINDS:
            continue
        norm = _normalize(field.text, casefold=True)
        starts = []
        if m := pattern.search(norm.text):
            starts.append(m.start())
        if m := _SERVER_REF_RE.search(norm.text):
            starts.append(m.start())
        for m in _TOOL_REF_RE.finditer(norm.text):
            name = next(g for g in m.groups() if g is not None)
            if name not in own_names:
                starts.append(m.start())
                break
        if starts:
            findings.append(_finding("TD003", field, norm.origin[min(starts)]))
    return findings


_URL_RE: Final = re.compile(
    r"(?<!\w)(?:https?|ftp|wss?|file|gopher)://\S+|(?<!\w)(?:mailto|data):\S+"
)


def td004_exfiltration(
    snapshot: Snapshot, phrases: Sequence[str] | None = None
) -> list[Finding]:
    """TD004: URLs with a scheme, or send/post-to phrasing, in descriptions and titles."""
    if phrases is None:
        phrases = _string_list("td004_exfiltration.yaml", "phrases")
    pattern = _phrase_regex(tuple(phrases))
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in _DESCRIPTIVE_KINDS:
            continue
        norm = _normalize(field.text, casefold=True)
        starts = [
            m.start()
            for m in (pattern.search(norm.text), _URL_RE.search(norm.text))
            if m
        ]
        if starts:
            findings.append(_finding("TD004", field, norm.origin[min(starts)]))
    return findings


def _is_base64_blob(run: str) -> bool:
    return (
        any(c.isupper() for c in run)
        and any(c.islower() for c in run)
        and any(c.isdigit() for c in run)
    )


def _is_hex_blob(run: str) -> bool:
    body = run[2:] if run[:2].lower() == "0x" else run
    return any(c.isdigit() for c in body) and any(c in "abcdefABCDEF" for c in body)


def td005_encoded_blobs(
    snapshot: Snapshot,
    base64_min_length: int | None = None,
    hex_min_length: int | None = None,
) -> list[Finding]:
    """TD005: long base64 or hex runs in descriptions, titles, and schema values."""
    if base64_min_length is None:
        base64_min_length = _positive_int(
            "td005_encoded_blobs.yaml", "base64_min_length"
        )
    if hex_min_length is None:
        hex_min_length = _positive_int("td005_encoded_blobs.yaml", "hex_min_length")
    b64 = re.compile(
        rf"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{{{base64_min_length},}}={{0,2}}(?![A-Za-z0-9+/_=-])"
    )
    hexa = re.compile(
        rf"(?<![0-9A-Za-z])(?:0x)?[0-9a-fA-F]{{{hex_min_length},}}(?![0-9A-Za-z])"
    )
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in _PROSE_KINDS:
            continue
        # Case matters for base64, so no casefold; hidden characters inside a blob drop out.
        norm = _normalize(field.text, casefold=False)
        starts = [
            m.start() for m in hexa.finditer(norm.text) if _is_hex_blob(m.group())
        ]
        starts += [
            m.start() for m in b64.finditer(norm.text) if _is_base64_blob(m.group())
        ]
        if starts:
            findings.append(_finding("TD005", field, norm.origin[min(starts)]))
    return findings


def td006_description_length(
    snapshot: Snapshot, max_chars: int | None = None
) -> list[Finding]:
    """TD006: a description longer than the configured threshold."""
    if max_chars is None:
        max_chars = _positive_int(
            "td006_description_length.yaml", "max_description_chars"
        )
    findings = []
    for field in iter_fields(snapshot):
        if field.kind == "description" and len(field.text) > max_chars:
            title = (
                f"{RULES_META['TD006'].title}: {len(field.text)} characters "
                f"(threshold {max_chars})"
            )
            findings.append(_finding("TD006", field, max_chars, title))
    return findings


_CAMEL_RE: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _is_free_text(schema: Any) -> bool:
    if not isinstance(schema, Mapping):
        return schema is True  # a `true` schema accepts anything
    if "enum" in schema or "const" in schema:
        return False
    kind = schema.get("type")
    if kind is None:
        return not any(
            k in schema for k in ("properties", "items", "anyOf", "oneOf", "allOf")
        )
    return kind == "string" or (isinstance(kind, list) and "string" in kind)


def td007_conversation_params(
    snapshot: Snapshot,
    tokens: Sequence[str] | None = None,
    names: Sequence[str] | None = None,
) -> list[Finding]:
    """TD007: free-text input parameters named like conversation content."""
    if tokens is None:
        tokens = _string_list("td007_param_names.yaml", "tokens")
    if names is None:
        names = _string_list("td007_param_names.yaml", "names")
    token_set = {t.lower() for t in tokens}
    name_set = {n.lower() for n in names}
    findings = []
    for field in iter_fields(snapshot):
        if field.kind != "param_name" or field.section != "inputSchema":
            continue
        if not _is_free_text(field.schema):
            continue
        visible = _normalize(field.text, casefold=False).text
        parts = [
            p.lower() for p in re.split(r"[\s_.-]+", _CAMEL_RE.sub("_", visible)) if p
        ]
        if token_set.intersection(parts) or "".join(parts) in name_set:
            findings.append(_finding("TD007", field, 0))
    return findings


def td008_duplicate_names(snapshot: Snapshot) -> list[Finding]:
    """TD008: two tools whose names match exactly or after NFKC, case folding, and
    removal of hidden characters."""
    first_seen: dict[str, int] = {}
    findings = []
    for i, tool in _tools(snapshot):
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        key = _normalize(name, casefold=True).text
        if key in first_seen:
            field = _Field(i, ("name",), "tool_name", name)
            title = f"{RULES_META['TD008'].title} (same as tools[{first_seen[key]}])"
            findings.append(_finding("TD008", field, 0, title))
        else:
            first_seen[key] = i
    return findings


RULES: Final[tuple[tuple[str, Callable[[Snapshot], list[Finding]]], ...]] = (
    ("TD001", td001_hidden_characters),
    ("TD002", td002_instruction_phrasing),
    ("TD003", td003_cross_references),
    ("TD004", td004_exfiltration),
    ("TD005", td005_encoded_blobs),
    ("TD006", td006_description_length),
    ("TD007", td007_conversation_params),
    ("TD008", td008_duplicate_names),
)


# ---------------------------------------------------------------------------
# Entry point


def _skip_reason(exc: Exception) -> SkipReason:
    # Fixed reasons only: an exception message may quote hostile input.
    if isinstance(exc, OSError):  # rule data file missing or unreadable
        return SkipReason.NOT_DETERMINABLE
    if isinstance(exc, (RuleDataError, yaml.YAMLError)):  # rule data file malformed
        return SkipReason.SHAPE_MISMATCH
    return SkipReason.RULE_ERROR


def scan_tool_definitions(snapshot: object) -> Report:
    """Validate a tools/list snapshot, run TD001-TD008, and return a Report.

    A rule that raises is recorded in coverage as skipped with a reason, never as a pass.
    Raises ToolError only when nothing can run (invalid or oversized snapshot).
    """
    return scan_parsed_snapshot(validate_tools_list_json(snapshot))


def scan_parsed_snapshot(parsed: object) -> Report:
    """Run TD001-TD008 on a snapshot already parsed from size- and depth-checked JSON text
    (the scan_tool_definitions tool, via safe_json). Same report and errors as
    scan_tool_definitions, without validating (and re-encoding) the object again.
    """
    if not isinstance(parsed, (dict, list)):
        raise ToolError(TOOLS_LIST_NOT_CONTAINER)
    try:
        entries = tool_entries(parsed)
    except TypeError:
        raise ToolError(
            'tools/list snapshot has no tools array. Expected {"tools": [...]}.'
        ) from None

    skipped = [
        SkippedCheck(f"tools[{i}]", SkipReason.SHAPE_MISMATCH)
        for i, tool in entries
        if not isinstance(tool, Mapping)
    ]
    ran: list[str] = []
    findings: list[Finding] = []
    for rule_id, rule in RULES:
        try:
            results = rule(parsed)
        except Exception as exc:  # a crash must become a skipped check, never a pass
            logger.warning("%s skipped: %s", rule_id, type(exc).__name__, exc_info=True)
            skipped.append(SkippedCheck(rule_id, _skip_reason(exc)))
            continue
        ran.append(rule_id)
        findings.extend(results)
    return build_report(findings, Coverage(ran=tuple(ran), skipped=tuple(skipped)))
