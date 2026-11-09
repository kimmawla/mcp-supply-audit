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


# Between two phrase words: one space, optionally after a comma ("before planning, use").
_SEP: Final = ",? "
# "*": zero to three words, none holding clause punctuation, so a gap stays in one clause.
# Each word is a run of non-space characters followed by the separator, so there is one way
# to match it: no nested repetition, no catastrophic backtracking.
_GAP: Final = rf"(?:[^\s.;:!?,]+{_SEP}){{0,3}}"
_PHRASE_TOKEN_RE: Final = re.compile(r"\([^()]*\)\??|\S+")


def _words_regex(text: str) -> str:
    return _SEP.join(re.escape(w) for w in text.split(" "))


def _group_regex(token: str, phrase: str) -> str:
    body = token[1:-2] if token.endswith("?") else token[1:-1]
    alts = [a.strip() for a in body.split("|")]
    if not all(alts) or any("*" in a.split(" ") for a in alts):
        raise RuleDataError(f"empty or gapped alternative in phrase: {phrase!r}")
    alts.sort(key=len, reverse=True)
    return "(?:" + "|".join(_words_regex(a) for a in alts) + ")"


@functools.cache
def _phrase_regex(phrases: tuple[str, ...]) -> re.Pattern[str]:
    """One regex for a phrase list; syntax in docs/rules-tool-definitions.md."""
    parts = []
    for phrase in phrases:
        tokens = _PHRASE_TOKEN_RE.findall(_normalize(phrase, casefold=True).text)
        if not tokens:
            raise RuleDataError(f"empty phrase: {phrase!r}")
        for edge in (tokens[0], tokens[-1]):
            if edge == "*" or (edge.startswith("(") and edge.endswith("?")):
                raise RuleDataError(
                    f"phrase may not start or end with a gap: {phrase!r}"
                )
        pattern = ""
        for i, token in enumerate(tokens):
            last = i == len(tokens) - 1
            if token == "*":
                pattern += _GAP
            elif token.startswith("(") and token.endswith("?"):
                pattern += f"(?:{_group_regex(token, phrase)}{_SEP})?"
            elif token.startswith("("):
                pattern += _group_regex(token, phrase) + ("" if last else _SEP)
            else:
                pattern += re.escape(token) + ("" if last else _SEP)
        parts.append(pattern)
    parts.sort(key=len, reverse=True)
    # Whole words: an edge of the match that is a word character may not touch another
    # word character. An edge such as "<" or ":" needs no boundary ("<important>Do").
    start = r"(?:(?<!\w)|(?=\W))"
    end = r"(?:(?!\w)|(?<=\W))"
    return re.compile(rf"{start}(?:{'|'.join(parts)}){end}")


_IDENT_SEPARATORS: Final = frozenset("_-.")


def _identifier_words(text: str) -> _Normalized:
    """Normalized text with identifier separators read as spaces, case folded.

    `_`, `-` and `.` become a space, and a lower-case letter or digit followed by an
    upper-case letter starts a new word, so "doNotTell" and "do_not_tell" read "do not tell".
    """
    base = _normalize(text, casefold=False)
    out: list[str] = []
    origin: list[int] = []
    prev = ""
    for ch, src in zip(base.text, base.origin, strict=True):
        if ch in _IDENT_SEPARATORS or ch == " ":
            if out and out[-1] != " ":
                out.append(" ")
                origin.append(src)
        else:
            if (
                ch.isupper()
                and (prev.islower() or prev.isdigit())
                and out
                and out[-1] != " "
            ):
                out.append(" ")
                origin.append(src)
            for m in ch.casefold():
                out.append(m)
                origin.append(src)
        prev = ch
    if out and out[-1] == " ":
        out.pop()
        origin.pop()
    return _Normalized("".join(out), tuple(origin))


# ---------------------------------------------------------------------------
# Snapshot traversal


@dataclass(frozen=True)
class _Field:
    tool_index: int
    path: tuple[str, ...]
    # tool_name, param_name, schema_key, description, title, value, value_key, required,
    # annotation, annotation_key
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
    "required": "required entry",
    "annotation": "annotation text",
    "annotation_key": "annotation key",
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
    value: Any,
    path: tuple[str, ...],
    tool_index: int,
    section: str,
    kinds: tuple[str, str] = ("value", "value_key"),
) -> Iterator[_Field]:
    value_kind, key_kind = kinds
    stack = [(value, path)]
    while stack:
        node, p = stack.pop()
        if isinstance(node, str):
            yield _Field(tool_index, p, value_kind, node, section)
        elif isinstance(node, list):
            stack.extend((v, (*p, f"[{k}]")) for k, v in enumerate(node))
        elif isinstance(node, Mapping):
            for k, (key, v) in enumerate(node.items()):
                if isinstance(key, str):
                    yield _Field(
                        tool_index, (*p, f"[{k}]", "(key)"), key_kind, key, section
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
        required = node.get("required")
        if isinstance(required, list):
            for k, entry in enumerate(required):
                if isinstance(entry, str):
                    yield _Field(
                        tool_index, (*p, f"required[{k}]"), "required", entry, section
                    )
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
    """Every string a client may show the model: names, descriptions, titles, annotation
    text, and schema keys, values and required entries at any depth of inputSchema and
    outputSchema. The list is in docs/rules-tool-definitions.md (Fields scanned)."""
    for i, tool in _tools(snapshot):
        for key, kind in (
            ("name", "tool_name"),
            ("title", "title"),
            ("description", "description"),
        ):
            if isinstance(tool.get(key), str):
                yield _Field(i, (key,), kind, tool[key])
        annotations = tool.get("annotations")
        if isinstance(annotations, Mapping):
            for k, (key, value) in enumerate(annotations.items()):
                if key == "title" and isinstance(value, str):
                    yield _Field(i, ("annotations", "title"), "title", value)
                    continue
                if isinstance(key, str):
                    yield _Field(
                        i, ("annotations", f"[{k}]", "(key)"), "annotation_key", key
                    )
                yield from _iter_values(
                    value,
                    ("annotations", f"[{k}]"),
                    i,
                    "tool",
                    ("annotation", "annotation_key"),
                )
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


_ALL_KINDS: Final = frozenset(_KIND_LABELS)


def _html_comment_start(text: str, addressees: re.Pattern[str]) -> int | None:
    """Offset of the first HTML comment whose text holds an addressee word.

    A comment runs from "<!--" to "-->", or to the end of the text when unterminated.
    Scans forward with str.find only, so time is linear in the text length.
    """
    pos = 0
    while (start := text.find("<!--", pos)) != -1:
        end = text.find("-->", start + 4)
        body = text[start + 4 : len(text) if end == -1 else end]
        if addressees.search(body):
            return start
        if end == -1:
            return None
        pos = end + 3
    return None


def td002_instruction_phrasing(
    snapshot: Snapshot,
    phrases: Sequence[str] | None = None,
    addressees: Sequence[str] | None = None,
) -> list[Finding]:
    """TD002: phrasing that directs the model (override, concealment, HTML comments,
    preference steering, covert data movement), in every scanned field."""
    if phrases is None:
        phrases = _string_list("td002_instruction_phrases.yaml", "phrases")
    if addressees is None:
        addressees = _string_list(
            "td002_instruction_phrases.yaml", "html_comment_addressees"
        )
    pattern = _phrase_regex(tuple(phrases))
    addressee_re = _phrase_regex(tuple(addressees))
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in _ALL_KINDS:
            continue
        norm = _normalize(field.text, casefold=True)
        starts = []
        if m := pattern.search(norm.text):
            starts.append(norm.origin[m.start()])
        if (c := _html_comment_start(norm.text, addressee_re)) is not None:
            starts.append(norm.origin[c])
        split = _identifier_words(field.text)
        if split.text != norm.text and (m := pattern.search(split.text)):
            starts.append(split.origin[m.start()])
        if starts:
            findings.append(_finding("TD002", field, min(starts)))
    return findings


_SERVER_REF_RE: Final = re.compile(
    r"(?<!\w)server (?:named|called) (?:[`'\"][^`'\"\s]+[`'\"]|[a-z0-9]+(?:[_.-][a-z0-9]+)+)"
)

# A tool name: snake_case, kebab-case or dotted (any mix of the three separators), or
# camelCase. Matched on normalized text that keeps its case. Each repetition starts at a
# separator or an upper-case letter, so there is one way to match.
_IDENT: Final = (
    r"[A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)+|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+"
)
_IDENT_RE: Final = re.compile(rf"(?:{_IDENT})")
_NAME_RE: Final = re.compile(
    rf"(?<![\w.-])(?:(?P<q>[`'\"])(?P<qname>[A-Za-z][\w.-]*)(?P=q)|(?P<name>{_IDENT}))"
    r"(?![\w-])"
)
_SUFFIX_RE: Final = re.compile(
    r"(?:\(\))?(?: (?:tool|function)(?!\w))|\(\)", re.IGNORECASE
)
_NAMED_FORM_RE: Final = re.compile(r"(?<!\w)tool (?:named|called) $", re.IGNORECASE)
_GENERIC_DETERMINERS: Final = frozenset(
    {"a", "an", "any", "another", "some", "each", "every"}
)
_SENTENCE_END_RE: Final = re.compile(r"[.;!?](?: |$)")
_CONTEXT_WINDOW: Final = 200  # characters, before the words are counted
_WORDS_BEFORE: Final = 4
_WORDS_AFTER: Final = 6


def _clause_before(text: str, start: int) -> list[str]:
    window = text[max(0, start - _CONTEXT_WINDOW) : start]
    return _SENTENCE_END_RE.split(window)[-1].split()


def _clause_after(text: str, end: int) -> list[str]:
    window = text[end : end + _CONTEXT_WINDOW]
    return _SENTENCE_END_RE.split(window)[0].split()


def _tool_reference_start(
    text: str,
    own_tools: frozenset[str],
    declared: frozenset[str],
    context_before: re.Pattern[str],
    passive: re.Pattern[str],
) -> int | None:
    """Offset of the first reference to a tool outside the snapshot, in a call, prefer,
    avoid or run context (docs/rules-tool-definitions.md, TD003 detail)."""
    for m in _NAME_RE.finditer(text):
        quoted = m.group("q") is not None
        name = m.group("qname") if quoted else m.group("name")
        suffix = _SUFFIX_RE.match(text, m.end())
        named_form = bool(
            _NAMED_FORM_RE.search(text, max(0, m.start() - 16), m.start())
        )
        shaped = _IDENT_RE.fullmatch(name) is not None
        if not (suffix or named_form or (quoted and shaped)):
            continue
        before = _clause_before(text, m.start())
        if before and before[-1].casefold() in _GENERIC_DETERMINERS:
            continue
        folded = _normalize(name, casefold=True).text
        if folded in own_tools:
            continue
        if not (suffix or named_form) and folded in declared:
            continue
        ref_end = suffix.end() if suffix else m.end()
        after = _clause_after(text, ref_end)[:_WORDS_AFTER]
        lead = " ".join(before[-_WORDS_BEFORE:]).casefold()
        if context_before.search(lead) or passive.search(" ".join(after).casefold()):
            return m.start()
    return None


def td003_cross_references(
    snapshot: Snapshot, phrases: Sequence[str] | None = None
) -> list[Finding]:
    """TD003: references to tools not in this snapshot, in a context that tells the model
    to call, prefer, avoid or run them, or to other servers."""
    data = "td003_cross_references.yaml"
    if phrases is None:
        phrases = _string_list(data, "phrases")
    pattern = _phrase_regex(tuple(phrases))
    context_before = _phrase_regex(_string_list(data, "context_before"))
    aux = "|".join(re.escape(w) for w in _string_list(data, "passive_aux"))
    verbs = "|".join(re.escape(w) for w in _string_list(data, "passive_verbs"))
    passive = re.compile(rf"(?<!\w)(?:{aux}) (?:\S+ )?(?:{verbs})(?!\w)")
    own_tools = frozenset(
        _normalize(t["name"], casefold=True).text
        for _, t in _tools(snapshot)
        if isinstance(t.get("name"), str)
    )
    declared = frozenset(
        _normalize(f.text, casefold=True).text
        for f in iter_fields(snapshot)
        if f.kind in ("param_name", "schema_key")
    )
    findings = []
    for field in iter_fields(snapshot):
        if field.kind not in _PROSE_KINDS:
            continue
        norm = _normalize(field.text, casefold=True)
        starts = []
        if m := pattern.search(norm.text):
            starts.append(norm.origin[m.start()])
        if m := _SERVER_REF_RE.search(norm.text):
            starts.append(norm.origin[m.start()])
        cased = _normalize(field.text, casefold=False)
        ref = _tool_reference_start(
            cased.text, own_tools, declared, context_before, passive
        )
        if ref is not None:
            starts.append(cased.origin[ref])
        if starts:
            findings.append(_finding("TD003", field, min(starts)))
    return findings


_URL_RE: Final = re.compile(
    r"(?<!\w)(?:https?|ftp|wss?|file|gopher)://\S+|(?<!\w)(?:mailto|data):\S+"
)


# After a send-to match, which ends at "to": a space, then a destination word.
_DESTINATION_RE: Final = re.compile(r" [^\s.;:!?,]")


def _send_to_start(text: str, send_to: re.Pattern[str]) -> int | None:
    """Offset of the first send-to construction that has a destination after "to"."""
    for m in send_to.finditer(text):
        if _DESTINATION_RE.match(text, m.end()):
            return m.start()
    return None


def td004_exfiltration(
    snapshot: Snapshot, phrases: Sequence[str] | None = None
) -> list[Finding]:
    """TD004: URLs with a scheme, phrasing that moves conversation content or secrets, or a
    send-to construction, in descriptions and titles."""
    data = "td004_exfiltration.yaml"
    if phrases is None:
        phrases = _string_list(data, "phrases")
    pattern = _phrase_regex(tuple(phrases))
    verbs = "|".join(_string_list(data, "send_verbs"))
    objects = "|".join(_string_list(data, "send_objects"))
    send_to = _phrase_regex((f"({verbs}) * ({objects}) * to",))
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
        if (send := _send_to_start(norm.text, send_to)) is not None:
            starts.append(send)
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
