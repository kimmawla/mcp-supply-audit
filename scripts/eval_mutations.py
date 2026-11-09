"""Mutations of the tool-definition eval positives, generated in memory and never written.

Dev-only: imported by scripts/eval_tool_defs.py and tests/test_eval_corpus.py. Never imported
by src/. No network, no randomness: the same manifest and fixtures always give the same
mutants in the same order.

Each positive in tests/fixtures/eval/MANIFEST.yaml with a key_phrase gets one mutant per
mutation type below that applies to it. The mutated field is the last string (or object key)
in document order that contains the key_phrase. The text mutations rewrite that whole field,
so no untouched copy of the phrase stays behind in it; other fields are left as they are.

  case                    the field upper-cased
  whitespace_runs         every space between words becomes a space-tab-newline run
  whitespace_split_words  a space inserted in the middle of every word of 6+ letters
  split_fields            a description field cut in the middle of the key phrase: the first
                          part stays in "description", the rest goes to "title" on the same
                          object (tool or parameter). Only for description fields.
  synonym                 whole words replaced from SYNONYMS (a fixed list). Only when at least
                          one word is replaced.
  param_move              a tool-level description moved into a parameter description (the
                          first parameter's, appended, or a new boolean parameter's), the tool
                          description replaced by NEUTRAL_DESCRIPTION. Only for tool-level
                          descriptions.
  unicode_homoglyph       Latin letters replaced by Cyrillic look-alikes from HOMOGLYPHS, built
                          with chr() (NFKC does not fold these).

A mutation that leaves the snapshot unchanged, or does not apply to the field's kind, yields
no mutant. Hidden characters are only ever built with chr(); this file holds none.
"""

import copy
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "tests/fixtures/eval"
MANIFEST = EVAL_DIR / "MANIFEST.yaml"
POSITIVES = EVAL_DIR / "positives"

MUTATIONS: Final = (
    "case",
    "whitespace_runs",
    "whitespace_split_words",
    "split_fields",
    "synonym",
    "param_move",
    "unicode_homoglyph",
)

# Fixed list, chosen as plain English synonyms of words common in the research patterns.
SYNONYMS: Final[Mapping[str, str]] = {
    "all": "every",
    "always": "invariably",
    "before": "ahead of",
    "call": "invoke",
    "chat": "dialogue",
    "choose": "pick",
    "contents": "data",
    "conversation": "dialogue",
    "decode": "unpack",
    "disregard": "overlook",
    "earlier": "preceding",
    "file": "document",
    "first": "initially",
    "forward": "relay",
    "hidden": "concealed",
    "hide": "conceal",
    "ignore": "overlook",
    "important": "critical",
    "instructions": "directions",
    "message": "note",
    "must": "shall",
    "previous": "earlier",
    "prior": "earlier",
    "quiet": "silent",
    "read": "open",
    "recipient": "addressee",
    "run": "execute",
    "secret": "confidential",
    "send": "transmit",
    "show": "display",
    "tell": "inform",
    "telling": "informing",
    "told": "informed",
    "upload": "transfer",
    "use": "employ",
    "user": "person",
    "without": "minus",
}

# Latin -> Cyrillic look-alikes, as code points.
HOMOGLYPHS: Final[Mapping[str, str]] = {
    "a": chr(0x0430),
    "c": chr(0x0441),
    "e": chr(0x0435),
    "i": chr(0x0456),
    "o": chr(0x043E),
    "p": chr(0x0440),
    "x": chr(0x0445),
    "y": chr(0x0443),
}

NEUTRAL_DESCRIPTION: Final = "Inert zqvex evaluation tool."
MOVED_PARAM: Final = "zqvex_option"

_WORD_RE: Final = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")
_LONG_WORD_RE: Final = re.compile(r"[A-Za-z]{6,}")

# Path segments: str keys, int indexes, ("key", name) for an object key.
Path_ = tuple[Any, ...]


@dataclass(frozen=True)
class Mutant:
    pattern_id: str
    mutation: str
    snapshot: dict[str, Any]
    expected: tuple[str, ...]


# --- loading


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="ascii"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("MANIFEST.yaml: expected a mapping with version: 1")
    return data


def fixture_path(pattern_id: str, positives: Path = POSITIVES) -> Path:
    return positives / f"{pattern_id}.json"


def load_fixture(pattern_id: str, positives: Path = POSITIVES) -> dict[str, Any]:
    return json.loads(fixture_path(pattern_id, positives).read_text(encoding="ascii"))


# --- locating and rewriting one field


def _walk(node: Any, path: Path = ()) -> Iterator[tuple[Path, str]]:
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, (*path, i))
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield (*path, ("key", k)), k
            yield from _walk(v, (*path, k))


def locate(doc: Any, phrase: str) -> Path | None:
    """Path of the last string or object key in document order that contains phrase."""
    found = None
    for path, text in _walk(doc):
        if phrase in text:
            found = path
    return found


def _parent(doc: Any, path: Path) -> Any:
    node = doc
    for seg in path[:-1]:
        node = node[seg]
    return node


def _get(doc: Any, path: Path) -> str:
    last = path[-1]
    if isinstance(last, tuple):
        return last[1]
    return _parent(doc, path)[last]


def _set(doc: Any, path: Path, value: str) -> None:
    parent = _parent(doc, path)
    last = path[-1]
    if isinstance(last, tuple):  # rename an object key, keeping order
        items = [(value if k == last[1] else k, v) for k, v in parent.items()]
        parent.clear()
        parent.update(items)
    else:
        parent[last] = value


# --- text mutations


def mutate_case(text: str) -> str:
    return text.upper()


def mutate_whitespace_runs(text: str) -> str:
    return text.replace(" ", " \t\n  ")


def mutate_whitespace_split_words(text: str) -> str:
    return _LONG_WORD_RE.sub(
        lambda m: m[0][: len(m[0]) // 2] + " " + m[0][len(m[0]) // 2 :], text
    )


def mutate_synonym(text: str) -> str:
    def swap(m: re.Match[str]) -> str:
        word = m[0]
        repl = SYNONYMS.get(word.lower())
        if repl is None:
            return word
        if word.isupper() and len(word) > 1:
            return repl.upper()
        if word[0].isupper():
            return repl[0].upper() + repl[1:]
        return repl

    return _WORD_RE.sub(swap, text)


def mutate_unicode_homoglyph(text: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


_TEXT_MUTATIONS: Final = {
    "case": mutate_case,
    "whitespace_runs": mutate_whitespace_runs,
    "whitespace_split_words": mutate_whitespace_split_words,
    "synonym": mutate_synonym,
    "unicode_homoglyph": mutate_unicode_homoglyph,
}


# --- structural mutations


def split_point(text: str, phrase: str) -> int:
    """Offset in text after the first half of phrase's words (at least one word)."""
    start = text.index(phrase)
    words = list(re.finditer(r"\S+", phrase))
    keep = max(1, len(words) // 2)
    return start + words[keep - 1].end()


def _split_fields(doc: dict[str, Any], path: Path, phrase: str) -> bool:
    if path[-1] != "description" or len(phrase.split()) < 2:
        return False
    owner = _parent(doc, path)
    if "title" in owner:
        return False
    text = owner["description"]
    cut = split_point(text, phrase)
    owner["description"] = text[:cut].rstrip()
    owner["title"] = text[cut:].lstrip()
    return True


def _param_move(doc: dict[str, Any], path: Path) -> bool:
    # Tool-level description only: ("tools", i, "description").
    if len(path) != 3 or path[0] != "tools" or path[2] != "description":
        return False
    tool = doc["tools"][path[1]]
    moved = tool["description"]
    tool["description"] = NEUTRAL_DESCRIPTION
    schema = tool.setdefault("inputSchema", {"type": "object"})
    props = schema.setdefault("properties", {})
    if props:
        first = next(iter(props.values()))
        before = first.get("description")
        first["description"] = f"{before} {moved}" if before else moved
    else:
        props[MOVED_PARAM] = {"type": "boolean", "description": moved}
    return True


# --- generation


def mutate(doc: dict[str, Any], phrase: str, mutation: str) -> dict[str, Any] | None:
    """A mutated deep copy of doc, or None when the mutation does not apply."""
    if mutation not in MUTATIONS:
        raise ValueError(f"unknown mutation: {mutation}")
    path = locate(doc, phrase)
    if path is None:
        raise ValueError("key_phrase not found in fixture")
    out = copy.deepcopy(doc)
    if mutation in _TEXT_MUTATIONS:
        old = _get(out, path)
        new = _TEXT_MUTATIONS[mutation](old)
        if new == old:
            return None
        _set(out, path, new)
    elif mutation == "split_fields":
        if not _split_fields(out, path, phrase):
            return None
    elif mutation == "param_move":
        if not _param_move(out, path):
            return None
    return None if out == doc else out


def generate(
    manifest: Mapping[str, Any] | None = None, positives: Path = POSITIVES
) -> list[Mutant]:
    """Every applicable mutant, in manifest order then MUTATIONS order."""
    if manifest is None:
        manifest = load_manifest()
    mutants = []
    for entry in manifest["patterns"]:
        phrase = entry.get("key_phrase")
        if not phrase:
            continue
        doc = load_fixture(entry["id"], positives)
        for mutation in MUTATIONS:
            snapshot = mutate(doc, phrase, mutation)
            if snapshot is not None:
                mutants.append(
                    Mutant(entry["id"], mutation, snapshot, tuple(entry["expected"]))
                )
    return mutants
