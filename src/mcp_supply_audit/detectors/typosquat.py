"""TS001-TS006: pure functions over a validated, normalized name and a set of reference names.
Rules live in docs/rules-typosquat.md; read it before changing this.

No network and no file reading of reference data here: typosquat_check.py loads the dated
reference file and passes the entries in. The confusable map, the affix lists and the platform
namespaces are rule data files (data/confusables.yaml, data/typosquat_affixes.yaml,
data/platform_namespaces.yaml) read through load_rule_data.

The registry tier has its own tuning (A-E in docs/rules-typosquat.md), one named constant each,
collected in REGISTRY_TUNING. Rules take the tuning as a parameter so the precision report can
run the same functions with UNTUNED for its before counts. pypi and npm never read it.

Findings say "similar to", never "typosquat of". Titles and locations never contain text from
the input or a reference entry; the matched reference name appears only in evidence, which
Finding.to_dict() renders through evidence_snippet.
"""

import functools
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from mcp_supply_audit.detectors.tool_defs import RuleDataError, load_rule_data
from mcp_supply_audit.findings import Confidence, Finding, Severity, SkipDetail
from mcp_supply_audit.secrets import scrub

ECOSYSTEMS: Final = ("pypi", "npm", "registry")
RULE_IDS: Final = ("TS001", "TS002", "TS003", "TS004", "TS005", "TS006")

# OWASP MCP Top 10 per rule; docs/rules-typosquat.md has the same table.
RULE_OWASP: Final[Mapping[str, tuple[str, ...]]] = {
    rule_id: ("MCP04:2025",) for rule_id in RULE_IDS
}

MIN_NAME_LEN: Final = 5
LONG_NAME_LEN: Final = 9  # from this length, TS003 and TS006 allow distance 2

# Source types (docs/rules-typosquat.md). Only listed-not-curated entries are uncurated, and
# they feed the registry ecosystem only.
REFERENCE_SERVER: Final = "reference-server"
DEPENDENCY: Final = "dependency"
LISTED_NOT_CURATED: Final = "listed-not-curated"
SOURCE_TYPES: Final = frozenset({REFERENCE_SERVER, DEPENDENCY, LISTED_NOT_CURATED})

# Registry tuning (docs/rules-typosquat.md, "Registry tier tuning").
# A: a same-namespace pair is one publisher's family of names, so TS001, TS003, TS004 and TS005
# do not fire on it, unless the namespace is a platform namespace (but see E).
REGISTRY_EXEMPT_SAME_NAMESPACE: Final = True
# B: TS005 is not used on the registry tier.
REGISTRY_DROP_TS005: Final = True
# C: a namespace that differs only in case never produces a finding.
REGISTRY_IGNORE_NAMESPACE_CASE: Final = True
# D: TS006 fires on scope distance 1, a tld-variant, or lookalike characters, and on distance 2
# only when both namespaces start with io.github.; low severity, low confidence.
REGISTRY_TS006_MAX_DISTANCE: Final = 1
REGISTRY_TS006_DISTANCE_2_PREFIX: Final = "io.github."
REGISTRY_TS006_TLD_VARIANT: Final = True
REGISTRY_TS006_SEVERITY: Final = Severity.LOW
REGISTRY_TS006_CONFIDENCE: Final = Confidence.LOW
# E: in a platform namespace, the first hyphen-separated token of the name part is the owner
# token; a pair with equal owner tokens does not fire TS003 or TS004.
REGISTRY_PLATFORM_OWNER_TOKEN: Final = True

_PYPI_SEPARATORS_RE = re.compile(r"[-_.]+")
_TOKEN_SPLIT_RE = re.compile(r"[-_.]+")
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


# ---------------------------------------------------------------------------
# Normalization


@dataclass(frozen=True)
class Name:
    """A validated name split into scope (npm scope or registry namespace) and part.

    `scope` and `part` are normalized; `raw_scope` and `raw_part` are as written, which the
    confusable skeleton needs (uppercase I is only visible before lowercasing).
    """

    ecosystem: str
    raw: str
    raw_scope: str | None
    raw_part: str
    scope: str | None
    part: str


def _normalize_part(text: str, ecosystem: str) -> str:
    lowered = text.lower()
    if ecosystem == "pypi":
        return _PYPI_SEPARATORS_RE.sub("-", lowered)
    return lowered


def normalize(name: str, ecosystem: str) -> Name:
    """Split and normalize a name that already passed its validator in validation.py."""
    if ecosystem not in ECOSYSTEMS:
        raise ValueError("unknown ecosystem")
    raw_scope: str | None = None
    raw_part = name
    if ecosystem == "npm" and name.startswith("@"):
        raw_scope, raw_part = name[1:].split("/", 1)
    elif ecosystem == "registry":
        raw_scope, raw_part = name.split("/", 1)
    return Name(
        ecosystem=ecosystem,
        raw=name,
        raw_scope=raw_scope,
        raw_part=raw_part,
        scope=None if raw_scope is None else _normalize_part(raw_scope, ecosystem),
        part=_normalize_part(raw_part, ecosystem),
    )


@dataclass(frozen=True)
class Reference:
    name: Name
    source: str
    source_type: str

    @property
    def curated(self) -> bool:
        return self.source_type != LISTED_NOT_CURATED


@dataclass(frozen=True)
class RegistryTuning:
    exempt_same_namespace: bool
    drop_ts005: bool
    ignore_namespace_case: bool
    # None: the length-based limit (1, or 2 from 9 characters)
    ts006_max_distance: int | None
    # Both namespaces starting with this keep the length-based limit; None: no exception
    ts006_distance_2_prefix: str | None
    ts006_tld_variant: bool
    ts006_severity: Severity | None  # None: the rule's own
    ts006_confidence: Confidence | None
    platform_owner_token: bool


REGISTRY_TUNING: Final = RegistryTuning(
    exempt_same_namespace=REGISTRY_EXEMPT_SAME_NAMESPACE,
    drop_ts005=REGISTRY_DROP_TS005,
    ignore_namespace_case=REGISTRY_IGNORE_NAMESPACE_CASE,
    ts006_max_distance=REGISTRY_TS006_MAX_DISTANCE,
    ts006_distance_2_prefix=REGISTRY_TS006_DISTANCE_2_PREFIX,
    ts006_tld_variant=REGISTRY_TS006_TLD_VARIANT,
    ts006_severity=REGISTRY_TS006_SEVERITY,
    ts006_confidence=REGISTRY_TS006_CONFIDENCE,
    platform_owner_token=REGISTRY_PLATFORM_OWNER_TOKEN,
)
# The rules as they were before A-E; the precision report's before counts.
UNTUNED: Final = RegistryTuning(
    exempt_same_namespace=False,
    drop_ts005=False,
    ignore_namespace_case=False,
    ts006_max_distance=None,
    ts006_distance_2_prefix=None,
    ts006_tld_variant=False,
    ts006_severity=None,
    ts006_confidence=None,
    platform_owner_token=False,
)


# ---------------------------------------------------------------------------
# Rule data (data/confusables.yaml, data/typosquat_affixes.yaml,
# data/platform_namespaces.yaml)


def _entries(
    filename: str, key: str, fields: tuple[str, ...]
) -> list[Mapping[str, str]]:
    entries = load_rule_data(filename).get(key)
    if not isinstance(entries, list) or not entries:
        raise RuleDataError(f"{filename}: {key} must be a non-empty list")
    for entry in entries:
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(f), str) and entry[f] for f in (*fields, "comment")
        ):
            raise RuleDataError(
                f"{filename}: each {key} entry needs {', '.join(fields)} and a comment"
            )
        if not all(entry[f].isascii() for f in fields):
            raise RuleDataError(f"{filename}: {key} entries must be ASCII")
    return entries


@functools.cache
def load_confusables() -> tuple[tuple[str, str], ...]:
    return tuple(
        (e["from"], e["to"])
        for e in _entries("confusables.yaml", "mappings", ("from", "to"))
    )


@dataclass(frozen=True)
class Affixes:
    prefixes: tuple[str, ...]
    suffixes: tuple[str, ...]


@functools.cache
def load_affixes() -> Affixes:
    def affixes(key: str) -> tuple[str, ...]:
        return tuple(
            e["affix"].lower()
            for e in _entries("typosquat_affixes.yaml", key, ("affix",))
        )

    return Affixes(prefixes=affixes("prefixes"), suffixes=affixes("suffixes"))


@functools.cache
def load_platform_namespaces() -> frozenset[str]:
    """Lowercased registry namespaces that publish for many owners; each entry needs a
    namespace, an ISO checked_at date and non-empty evidence."""
    filename = "platform_namespaces.yaml"
    entries = load_rule_data(filename).get("namespaces")
    if not isinstance(entries, list) or not entries:
        raise RuleDataError(f"{filename}: namespaces must be a non-empty list")
    namespaces = set()
    for entry in entries:
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("namespace"), str)
            and entry["namespace"].isascii()
            and "/" not in entry["namespace"]
            and isinstance(entry.get("checked_at"), str)
            and _ISO_DATE_RE.fullmatch(entry["checked_at"])
            and isinstance(entry.get("evidence"), list)
            and entry["evidence"]
            and all(isinstance(e, str) and e.strip() for e in entry["evidence"])
        ):
            raise RuleDataError(
                f"{filename}: each entry needs an ASCII namespace, checked_at and evidence"
            )
        namespaces.add(entry["namespace"].lower())
    return frozenset(namespaces)


# ---------------------------------------------------------------------------
# Distance and skeleton


def edit_distance(a: str, b: str, limit: int) -> int | None:
    """Damerau-Levenshtein distance (optimal string alignment: adjacent transpositions, no
    edits of a transposed pair), or None as soon as it must exceed limit.

    Exits early on a length difference over limit, and when every cell of a row is over
    limit (a transposition reads two rows back, but the cell beside it in the row between is
    never larger, so a row over limit means every later row is too).
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if abs(len(a) - len(b)) > limit:
        return None
    if a == b:
        return 0
    before: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                value = min(value, before[j - 2] + 1)
            current[j] = value
        if min(current) > limit:
            return None
        before, previous = previous, current
    return previous[-1] if previous[-1] <= limit else None


def _limit(text: str) -> int:
    return 2 if len(text) >= LONG_NAME_LEN else 1


def skeleton(raw: str, ecosystem: str, confusables: Sequence[tuple[str, str]]) -> str:
    """Replace confusables in the name as written, then normalize as for the ecosystem."""
    for source, target in confusables:
        raw = raw.replace(source, target)
    return _normalize_part(raw, ecosystem)


def _tokens(part: str) -> tuple[str, ...]:
    return tuple(t for t in _TOKEN_SPLIT_RE.split(part) if t)


def owner_token(part: str) -> str:
    """E: the first hyphen-separated token of a platform name part (`alice` in alice-widget).
    It cannot tell owner foo-bar from owner foo: both give foo."""
    return part.split("-", 1)[0]


def same_owner_token(a: Name, b: Name) -> bool:
    return owner_token(a.part) == owner_token(b.part)


def is_tld_variant(a: str, b: str) -> bool:
    """Two namespaces equal but for the first label (com.x and io.x)."""
    labels_a, labels_b = a.split("."), b.split(".")
    return (
        len(labels_a) == len(labels_b) >= 2
        and labels_a[0] != labels_b[0]
        and labels_a[1:] == labels_b[1:]
    )


# ---------------------------------------------------------------------------
# Applicability


def skip_detail(
    rule_id: str, name: Name, tuning: RegistryTuning = REGISTRY_TUNING
) -> SkipDetail | None:
    """Why a rule does not apply to this name, or None if it does. Recorded as
    not_applicable. TS001 always applies; length is measured on the package or name part."""
    if rule_id == "TS005" and name.ecosystem == "registry" and tuning.drop_ts005:
        return SkipDetail.NOT_USED_FOR_REGISTRY
    if rule_id == "TS001":
        return None
    if len(name.part) < MIN_NAME_LEN:
        return SkipDetail.NAME_TOO_SHORT
    if rule_id == "TS006" and name.scope is None:
        return SkipDetail.NO_SCOPE
    return None


# ---------------------------------------------------------------------------
# Rules


@dataclass(frozen=True)
class Match:
    """A finding and the reference entry it names (the tool layer caps distinct names)."""

    finding: Finding
    reference: Reference


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    remediation: str


_RULES: Final[Mapping[str, _Rule]] = {
    r.rule_id: r
    for r in (
        _Rule(
            "TS001",
            "Name matches a reference name written differently",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Use the reference name exactly as published, unless this spelling is the one "
            "you verified.",
        ),
        _Rule(
            "TS002",
            "Name looks like a reference name when lookalike characters are swapped",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Compare the name with the reference name character by character before "
            "installing.",
        ),
        _Rule(
            "TS003",
            "Name is a small edit away from a reference name",
            Severity.LOW,
            Confidence.LOW,
            "Check whether you meant the reference name before installing.",
        ),
        _Rule(
            "TS004",
            "Name is a reference name with a common affix added or removed",
            Severity.LOW,
            Confidence.LOW,
            "Confirm the publisher is the reference name's publisher before installing.",
        ),
        _Rule(
            "TS005",
            "Name has the same words as a reference name in a different order",
            Severity.LOW,
            Confidence.LOW,
            "Check whether you meant the reference name before installing.",
        ),
        _Rule(
            "TS006",
            "Scope or namespace is close to a reference one, with the same package name",
            Severity.MEDIUM,
            Confidence.LOW,
            "Confirm the scope or namespace belongs to the reference name's publisher "
            "before installing.",
        ),
    )
}

# The part a rule compared, by ecosystem. Locations never contain the name itself.
_PART_LOCATION: Final = {"pypi": "name", "npm": "name.package", "registry": "name.name"}
_SCOPE_LOCATION: Final = {"npm": "name.scope", "registry": "name.namespace"}


def _source_tag(reference: Reference) -> str:
    if reference.curated:
        return f"source {reference.source_type}"
    return f"source {LISTED_NOT_CURATED} (MCP Registry listing, not reviewed)"


def _match(
    rule_id: str,
    location: str,
    method: str,
    reference: Reference,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
) -> Match:
    rule = _RULES[rule_id]
    # Source and method first, so a long reference name is what truncation cuts.
    evidence, _ = scrub(
        f"{_source_tag(reference)}; {method}; similar to {reference.name.raw}"
    )
    finding = Finding(
        rule_id=rule_id,
        title=rule.title,
        severity=severity or rule.severity,
        confidence=confidence or rule.confidence,
        owasp=RULE_OWASP[rule_id],
        location=location,
        evidence=evidence,
        remediation=rule.remediation,
    )
    return Match(finding=finding, reference=reference)


def _nearest(
    rule_id: str,
    location: str,
    candidates: list[tuple[int, Reference, str]],
    severity: Severity | None = None,
    confidence: Confidence | None = None,
) -> list[Match]:
    """At most one match per rule: lowest rank, curated before listed, then by name."""
    if not candidates:
        return []
    _rank, reference, method = min(
        candidates, key=lambda c: (c[0], not c[1].curated, c[1].name.raw)
    )
    return [_match(rule_id, location, method, reference, severity, confidence)]


def _same_scope(name: Name, references: Sequence[Reference]) -> list[Reference]:
    return [
        r
        for r in references
        if r.name.ecosystem == name.ecosystem and r.name.scope == name.scope
    ]


def _registry(name: Name, tuning: RegistryTuning) -> RegistryTuning:
    return tuning if name.ecosystem == "registry" else UNTUNED


def _same_namespace_exempt(
    name: Name, tuning: RegistryTuning, platforms: frozenset[str]
) -> bool:
    """A: every reference a same-namespace rule compares with is the same publisher's,
    unless the namespace is a platform namespace. Namespaces are compared lowercased."""
    return _registry(name, tuning).exempt_same_namespace and name.scope not in platforms


def _owner_token_exempt(
    name: Name, reference: Reference, tuning: RegistryTuning, platforms: frozenset[str]
) -> bool:
    """E: in a platform namespace, a reference with the same owner token is the same owner's."""
    return (
        _registry(name, tuning).platform_owner_token
        and name.scope in platforms
        and same_owner_token(name, reference.name)
    )


def ts001_normalized_equal(
    name: Name,
    references: Sequence[Reference],
    tuning: RegistryTuning = REGISTRY_TUNING,
    platforms: frozenset[str] = frozenset(),
) -> list[Match]:
    """TS001: equal to a reference name after normalization, but written differently."""
    if _same_namespace_exempt(name, tuning, platforms):
        return []
    # C: when only the namespace's case differs, there is nothing to report.
    ignore_scope = _registry(name, tuning).ignore_namespace_case
    candidates = [
        (0, r, "same name after normalization, written differently")
        for r in references
        if r.name.ecosystem == name.ecosystem
        and (r.name.scope, r.name.part) == (name.scope, name.part)
        and (
            r.name.raw_part != name.raw_part if ignore_scope else r.name.raw != name.raw
        )
    ]
    return _nearest("TS001", "name", candidates)


def ts002_confusable(
    name: Name,
    references: Sequence[Reference],
    confusables: Sequence[tuple[str, str]],
) -> list[Match]:
    """TS002: same confusable skeleton as a reference name, different normalized form."""
    own = skeleton(name.raw_part, name.ecosystem, confusables)
    candidates = [
        (0, r, "lookalike characters")
        for r in _same_scope(name, references)
        if r.name.part != name.part
        and skeleton(r.name.raw_part, name.ecosystem, confusables) == own
    ]
    return _nearest("TS002", _PART_LOCATION[name.ecosystem], candidates)


def ts003_edit_distance(
    name: Name,
    references: Sequence[Reference],
    tuning: RegistryTuning = REGISTRY_TUNING,
    platforms: frozenset[str] = frozenset(),
) -> list[Match]:
    """TS003: Damerau-Levenshtein distance 1 (2 from 9 characters) from a reference name."""
    if _same_namespace_exempt(name, tuning, platforms):
        return []
    limit = _limit(name.part)
    candidates = []
    for r in _same_scope(name, references):
        if _owner_token_exempt(name, r, tuning, platforms):
            continue
        distance = edit_distance(name.part, r.name.part, limit)
        if distance:  # 0 is TS001's case; None is over the limit
            candidates.append((distance, r, f"edit distance {distance}"))
    return _nearest("TS003", _PART_LOCATION[name.ecosystem], candidates)


def ts004_affix(
    name: Name,
    references: Sequence[Reference],
    affixes: Affixes,
    tuning: RegistryTuning = REGISTRY_TUNING,
    platforms: frozenset[str] = frozenset(),
) -> list[Match]:
    """TS004: a reference name with a listed prefix or suffix added or removed."""
    if _same_namespace_exempt(name, tuning, platforms):
        return []
    candidates = []
    for r in _same_scope(name, references):
        if _owner_token_exempt(name, r, tuning, platforms):
            continue
        ref = r.name.part
        for affix in affixes.prefixes:
            if name.part == affix + ref:
                candidates.append((0, r, f"prefix {affix} added"))
            elif ref == affix + name.part:
                candidates.append((0, r, f"prefix {affix} removed"))
        for affix in affixes.suffixes:
            if name.part == ref + affix:
                candidates.append((0, r, f"suffix {affix} added"))
            elif ref == name.part + affix:
                candidates.append((0, r, f"suffix {affix} removed"))
    return _nearest("TS004", _PART_LOCATION[name.ecosystem], candidates)


def ts005_reordered(
    name: Name,
    references: Sequence[Reference],
    tuning: RegistryTuning = REGISTRY_TUNING,
    platforms: frozenset[str] = frozenset(),
) -> list[Match]:
    """TS005: the same tokens as a reference name, in a different order. Not used on the
    registry tier (B; skip_detail records it), but exempt as A says if run there."""
    if _same_namespace_exempt(name, tuning, platforms):
        return []
    tokens = _tokens(name.part)
    if len(tokens) < 2:
        return []
    candidates = [
        (0, r, "same words in a different order")
        for r in _same_scope(name, references)
        if _tokens(r.name.part) != tokens
        and sorted(_tokens(r.name.part)) == sorted(tokens)
    ]
    return _nearest("TS005", _PART_LOCATION[name.ecosystem], candidates)


def ts006_scope(
    name: Name,
    references: Sequence[Reference],
    confusables: Sequence[tuple[str, str]],
    tuning: RegistryTuning = REGISTRY_TUNING,
) -> list[Match]:
    """TS006: npm scope or registry namespace close to a reference one, same package part.
    A scope differing only in case is the same scope after normalization, so never fires (C)."""
    if name.scope is None or name.raw_scope is None:
        return []
    tuned = _registry(name, tuning)
    length_limit = _limit(name.scope)
    prefix = tuned.ts006_distance_2_prefix
    own = skeleton(name.raw_scope, name.ecosystem, confusables)
    candidates = []
    for r in references:
        if (
            r.name.ecosystem != name.ecosystem
            or r.name.scope is None
            or r.name.raw_scope is None
            or r.name.part != name.part
            or r.name.scope == name.scope
        ):
            continue
        limit = tuned.ts006_max_distance or length_limit
        if prefix and name.scope.startswith(prefix) and r.name.scope.startswith(prefix):
            limit = length_limit
        distance = edit_distance(name.scope, r.name.scope, limit)
        if tuned.ts006_tld_variant and is_tld_variant(name.scope, r.name.scope):
            candidates.append((1, r, "namespace differs only in its first label"))
        elif distance is not None:
            candidates.append((distance, r, f"scope edit distance {distance}"))
        elif skeleton(r.name.raw_scope, name.ecosystem, confusables) == own:
            candidates.append((0, r, "scope has lookalike characters"))
    return _nearest(
        "TS006",
        _SCOPE_LOCATION[name.ecosystem],
        candidates,
        tuned.ts006_severity,
        tuned.ts006_confidence,
    )


def _platforms(name: Name, tuning: RegistryTuning) -> frozenset[str]:
    # Only a tuned registry check reads the platform file, so pypi and npm never depend on it.
    if _registry(name, tuning).exempt_same_namespace:
        return load_platform_namespaces()
    return frozenset()


def rules(
    tuning: RegistryTuning = REGISTRY_TUNING,
) -> tuple[tuple[str, Callable[[Name, Sequence[Reference]], list[Match]]], ...]:
    """(rule id, rule) pairs with their data files and tuning bound. Loading happens per
    call, so a malformed data file fails only the rules that read it."""
    t = tuning
    return (
        (
            "TS001",
            lambda n, refs: ts001_normalized_equal(n, refs, t, _platforms(n, t)),
        ),
        ("TS002", lambda n, refs: ts002_confusable(n, refs, load_confusables())),
        ("TS003", lambda n, refs: ts003_edit_distance(n, refs, t, _platforms(n, t))),
        (
            "TS004",
            lambda n, refs: ts004_affix(n, refs, load_affixes(), t, _platforms(n, t)),
        ),
        ("TS005", lambda n, refs: ts005_reordered(n, refs, t, _platforms(n, t))),
        ("TS006", lambda n, refs: ts006_scope(n, refs, load_confusables(), t)),
    )
