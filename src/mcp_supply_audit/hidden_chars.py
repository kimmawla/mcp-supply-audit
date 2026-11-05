"""Hidden-character classes: the one table read by visible_escapes and the TD001 detector.

Built from integer code points and Unicode categories only. This file must never contain
the characters themselves (tests/test_sanitize.py scans for them).
"""

import unicodedata
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

_SPACE: Final = 0x20
_NEWLINE: Final = 0x0A
_TAB: Final = 0x09

# Classes defined by explicit code points. Checked before the category classes, so a
# zero-width space reports as "zero_width" rather than the generic "format".
CODE_POINT_CLASSES: Final[Mapping[str, tuple[range, ...]]] = MappingProxyType(
    {
        "zero_width": (
            range(0x180E, 0x180F),
            range(0x200B, 0x200E),
            range(0x2060, 0x2065),
            range(0xFEFF, 0xFF00),
        ),
        "bidi_control": (
            range(0x061C, 0x061D),
            range(0x200E, 0x2010),
            range(0x202A, 0x202F),
            range(0x2066, 0x206A),
        ),
        "tag": (range(0xE0000, 0xE0080),),
        "variation_selector": (range(0xFE00, 0xFE10), range(0xE0100, 0xE01F0)),
        "mongolian_variation_selector": (range(0x180B, 0x180E), range(0x180F, 0x1810)),
        "hangul_filler": (
            range(0x115F, 0x1161),
            range(0x3164, 0x3165),
            range(0xFFA0, 0xFFA1),
        ),
        "braille_blank": (range(0x2800, 0x2801),),
        "combining_grapheme_joiner": (range(0x034F, 0x0350),),
        "khmer_inherent_vowel": (range(0x17B4, 0x17B6),),
    }
)

# Classes defined by Unicode general category, with the code points each one exempts.
# A str holds no valid surrogate pairs (a pair decodes to one astral character), so every
# Cs code point is unpaired. Cn follows the Python runtime's Unicode version, so a
# character newer than that version is escaped as unassigned (the safe direction).
CATEGORY_CLASSES: Final[Mapping[str, tuple[str, frozenset[int]]]] = MappingProxyType(
    {
        "control": ("Cc", frozenset({_NEWLINE, _TAB})),
        "format": ("Cf", frozenset()),
        "surrogate": ("Cs", frozenset()),
        "space_separator": ("Zs", frozenset({_SPACE})),
        "line_separator": ("Zl", frozenset()),
        "paragraph_separator": ("Zp", frozenset()),
        "private_use": ("Co", frozenset()),
        "unassigned": ("Cn", frozenset()),
    }
)

_BY_CODE_POINT: Final[Mapping[int, str]] = MappingProxyType(
    {
        cp: name
        for name, ranges in CODE_POINT_CLASSES.items()
        for r in ranges
        for cp in r
    }
)
_BY_CATEGORY: Final[Mapping[str, tuple[str, frozenset[int]]]] = MappingProxyType(
    {category: (name, exempt) for name, (category, exempt) in CATEGORY_CLASSES.items()}
)


def hidden_class(ch: str) -> str | None:
    """Return the hidden-character class name of ch, or None if ch renders visibly."""
    cp = ord(ch)
    name = _BY_CODE_POINT.get(cp)
    if name is not None:
        return name
    entry = _BY_CATEGORY.get(unicodedata.category(ch))
    if entry is not None and cp not in entry[1]:
        return entry[0]
    return None
