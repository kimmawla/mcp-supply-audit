"""Sanitization for hostile text read from scan targets (tool descriptions, READMEs, metadata)."""

import unicodedata

from mcp_supply_audit.hidden_chars import hidden_class

TRUNCATION_MARKER = " …[truncated]"

# Cc: control, Cf: format (zero-width, bidi overrides), Cs: surrogates, Co: private use.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})


def clean_untrusted(text: str | None, max_len: int = 1500) -> str:
    """Strip control/format characters, collapse whitespace, and cap length.

    The result is at most max_len characters, including the truncation marker.
    """
    if max_len <= 0:
        raise ValueError("max_len must be positive")
    if not text:
        return ""

    chars = []
    for ch in text:
        if ch.isspace():
            chars.append(" ")
        elif unicodedata.category(ch) not in _STRIP_CATEGORIES:
            chars.append(ch)
    cleaned = " ".join("".join(chars).split())

    if len(cleaned) <= max_len:
        return cleaned
    if max_len <= len(TRUNCATION_MARKER):
        return cleaned[:max_len]
    return cleaned[: max_len - len(TRUNCATION_MARKER)].rstrip() + TRUNCATION_MARKER


_BACKSLASH = chr(92)


def _escape_char(ch: str) -> str:
    # A literal backslash doubles, so source text that already reads like an escape
    # cannot pass for one of ours.
    if ch == _BACKSLASH:
        return _BACKSLASH * 2
    if hidden_class(ch) is None:
        return ch
    cp = ord(ch)
    return f"{_BACKSLASH}u{cp:04x}" if cp <= 0xFFFF else f"{_BACKSLASH}U{cp:08x}"


def visible_escapes(text: str) -> str:
    """Render hidden characters as literal \\uXXXX (\\UXXXXXXXX above the BMP) escapes.

    Escapes every class in hidden_chars (zero-width, bidi, tag, variation selectors,
    fillers, controls except newline and tab, format, surrogates, non-ASCII spaces), and
    doubles a literal backslash. Every other character is untouched. Unlike
    clean_untrusted, nothing is dropped.
    """
    return "".join(_escape_char(ch) for ch in text)


def evidence_snippet(text: str, start: int, length: int = 120) -> str:
    """Excerpt text around offset start, escape hidden characters, collapse whitespace, cap length.

    Escaping happens before whitespace collapsing and capping, so a hidden character is
    never dropped before it is shown. Leading context is limited to a quarter of length,
    measured after escaping, so the character at start always fits. The result is at most
    length characters including the truncation marker, and never ends mid-escape.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    if isinstance(start, bool) or not isinstance(start, int):
        raise TypeError("start must be an int")
    if length <= len(TRUNCATION_MARKER):
        raise ValueError("length must be longer than the truncation marker")
    start = min(max(start, 0), len(text))

    lead, budget = start, length // 4
    while lead > 0:
        width = len(_escape_char(text[lead - 1]))
        if width > budget:
            break
        budget -= width
        lead -= 1

    pieces: list[str] = []
    width = 0
    pending_space = False
    truncated = False
    for i in range(lead, len(text)):
        token = _escape_char(text[i])
        if token.isspace():
            pending_space = bool(pieces)
            continue
        piece = " " + token if pending_space else token
        pending_space = False
        if width + len(piece) > length:
            truncated = True
            break
        pieces.append(piece)
        width += len(piece)

    if truncated:
        while pieces and width + len(TRUNCATION_MARKER) > length:
            width -= len(pieces.pop())
        return "".join(pieces).rstrip() + TRUNCATION_MARKER
    return "".join(pieces)
