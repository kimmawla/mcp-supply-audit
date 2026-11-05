"""Precision report: run TS001-TS006 for every registry reference name against the rest.

Dev-only: run by hand after refreshing data/reference_names.json. Never imported by src/.
Loads the packaged reference file through the same loader check_typosquat uses, and for each
registry name calls typosquat_check.run_rules (the rules check_typosquat runs) against the rest of the
list, as the precision test does. Prints to stderr only and writes nothing.

To avoid a full pairwise comparison, each name is run against a candidate list built from
indexes over (normalized namespace, ...). The rules only ever fire on references in these
buckets, so the candidate list is a superset of every reference that could match, and each
rule's nearest match is the same as against the whole list:
  TS001  same namespace and same name part
  TS002  same namespace and same confusable skeleton
  TS003  same namespace and a name part within 2 characters in length (the rule's largest
         distance; edit_distance gives up on a larger length difference)
  TS004  same namespace and the name part with one listed affix added or removed (exact lookups)
  TS005  same namespace and the same sorted tokens
  TS006  same name part in any namespace (also covers tld-variant and lookalike namespaces)
The registry tuning (A-E) only removes matches from these buckets, never adds one outside them.

Counts are unordered pairs per rule and part: A ~ B and B ~ A count once. Like run_rules, each
rule reports at most its nearest match per name.

Every name runs three times through the same typosquat_check.run_rules that check_typosquat
uses: with ts.UNTUNED (before the registry tuning), with ts.REGISTRY_TUNING (after), and with
REGISTRY_TUNING minus E (the owner-token exemption). Counts per rule and class are printed for
before and after. "Exempted by owner token" counts the platform pairs of the run without E whose
owner tokens are equal: the pairs E removes. They are counted, not hidden, because the first
token cannot tell owner foo-bar from owner foo. The rest of the report is for after.

Each pair is classed by namespace (normalized, as the rules compare them):
  platform-namespace   either namespace is in data/platform_namespaces.yaml (a host that
                       publishes for many owners, so a shared namespace is no shared publisher),
                       read through ts.load_platform_namespaces as the rules read it
  same-namespace       both names in one namespace
  different-namespace  otherwise
The report prints per-rule counts per class, the top namespaces by pair count (a pair counts
once for each distinct namespace in it), and a seeded random sample of each rule's
different-namespace and platform pairs. TS006 pairs are tagged tld-variant (namespaces equal
but for the first label, e.g. com.x and io.x), else distance-1 or distance-2, else lookalike
(confusable skeletons equal, distance over the limit), plus series when the name part is
shared by SERIES_MIN_NAMESPACES or more near namespaces. Near means ts.ts006_scope fires between
the two names under the run's tuning, and a series is a connected group of near namespaces with
the same name part. A series pair is tagged and counted, never exempted.

Usage: uv run scripts/precision_report.py [--seed S] [--sample N]
Exit status: 0 printed, 1 reference file or platform file unreadable or malformed.
"""

import argparse
import random
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

import yaml

from mcp_supply_audit import typosquat_check as tc
from mcp_supply_audit.clients._http import ShapeMismatch
from mcp_supply_audit.detectors import typosquat as ts
from mcp_supply_audit.detectors.tool_defs import RuleDataError

ECOSYSTEM = "registry"
DEFAULT_SAMPLE = 40
DEFAULT_SEED = 0
TOP_NAMESPACES = 10
MAX_LENGTH_DELTA = 2  # TS003 allows distance 2 from 9 characters
PARTS = {"name.namespace": "namespace", "name.name": "name", "name": "whole name"}

SAME = "same-namespace"
DIFFERENT = "different-namespace"
PLATFORM = "platform-namespace"
CLASSES = (SAME, DIFFERENT, PLATFORM)
SAMPLED = (DIFFERENT, PLATFORM)
TS006_TAGS = ("distance-1", "distance-2", "tld-variant", "lookalike")
SERIES_MIN_NAMESPACES = 3
OWNER_TOKEN_RULES = ("TS003", "TS004")


def log(message: str = "") -> None:
    print(message, file=sys.stderr, flush=True)


class CandidateIndex:
    """Buckets of registry references; candidates() is a superset of what any rule can match."""

    def __init__(self, references: Iterable[ts.Reference]) -> None:
        self.confusables = ts.load_confusables()
        self.affixes = ts.load_affixes()
        self.by_part_in_scope: dict[tuple, list[ts.Reference]] = defaultdict(list)
        self.by_length: dict[tuple, list[ts.Reference]] = defaultdict(list)
        self.by_skeleton: dict[tuple, list[ts.Reference]] = defaultdict(list)
        self.by_tokens: dict[tuple, list[ts.Reference]] = defaultdict(list)
        self.by_part: dict[str, list[ts.Reference]] = defaultdict(list)
        for r in references:
            n = r.name
            self.by_part_in_scope[(n.scope, n.part)].append(r)
            self.by_length[(n.scope, len(n.part))].append(r)
            self.by_skeleton[(n.scope, self._skeleton(n))].append(r)
            self.by_tokens[(n.scope, self._token_key(n))].append(r)
            self.by_part[n.part].append(r)

    def _skeleton(self, name: ts.Name) -> str:
        return ts.skeleton(name.raw_part, name.ecosystem, self.confusables)

    @staticmethod
    def _token_key(name: ts.Name) -> tuple[str, ...]:
        return tuple(sorted(ts._tokens(name.part)))

    def _affix_neighbours(self, part: str) -> list[str]:
        parts = []
        for affix in self.affixes.prefixes:
            parts.append(affix + part)
            if part.startswith(affix):
                parts.append(part[len(affix) :])
        for affix in self.affixes.suffixes:
            parts.append(part + affix)
            if part.endswith(affix):
                parts.append(part[: -len(affix)])
        return parts

    def candidates(self, ref: ts.Reference) -> list[ts.Reference]:
        n = ref.name
        buckets = [
            self.by_part_in_scope[(n.scope, n.part)],
            self.by_skeleton[(n.scope, self._skeleton(n))],
            self.by_tokens[(n.scope, self._token_key(n))],
            self.by_part[n.part],
        ]
        for length in range(
            len(n.part) - MAX_LENGTH_DELTA, len(n.part) + MAX_LENGTH_DELTA + 1
        ):
            buckets.append(self.by_length.get((n.scope, length), []))
        for part in self._affix_neighbours(n.part):
            buckets.append(self.by_part_in_scope.get((n.scope, part), []))
        seen: dict[int, ts.Reference] = {}
        for bucket in buckets:
            for r in bucket:
                if r is not ref:
                    seen[id(r)] = r
        return list(seen.values())


# (rule, location, unordered pair) -> the two names.
Pairs = dict[tuple[str, str, frozenset[str]], tuple[ts.Name, ts.Name]]


@dataclass
class Run:
    pairs: Pairs = field(default_factory=dict)
    compared: int = 0
    errors: Counter[str] = field(default_factory=Counter)


def collect_pairs(
    refs: Iterable[ts.Reference], index: CandidateIndex, tuning: ts.RegistryTuning
) -> Run:
    """Each name against its candidates, through the rules check_typosquat runs."""
    run = Run()
    for ref in refs:
        candidates = index.candidates(ref)
        run.compared += len(candidates)
        matches, coverage = tc.run_rules(ref.name, candidates, tuning)
        for skipped in coverage.skipped:
            if skipped.reason is not tc.SkipReason.NOT_APPLICABLE:
                run.errors[f"{skipped.check} {skipped.reason.value}"] += 1
        for m in matches:
            other = m.reference.name
            key = (
                m.finding.rule_id,
                m.finding.location,
                frozenset((ref.name.raw, other.raw)),
            )
            run.pairs.setdefault(key, (ref.name, other))
    return run


def classify(a: ts.Name, b: ts.Name, platforms: frozenset[str]) -> str:
    if a.scope in platforms or b.scope in platforms:
        return PLATFORM
    return SAME if a.scope == b.scope else DIFFERENT


def class_counts(pairs: Pairs, platforms: frozenset[str]) -> dict[str, Counter[str]]:
    counts: dict[str, Counter[str]] = {r: Counter() for r in ts.RULE_IDS}
    for (rule_id, _, _), (a, b) in pairs.items():
        counts[rule_id][classify(a, b, platforms)] += 1
    return counts


def ts006_tag(a: ts.Name, b: ts.Name) -> str:
    """tld-variant before distance: com.x and io.x is a distance-2 pair worth telling apart."""
    assert a.scope is not None and b.scope is not None
    if ts.is_tld_variant(a.scope, b.scope):
        return "tld-variant"
    distance = ts.edit_distance(a.scope, b.scope, MAX_LENGTH_DELTA)
    return f"distance-{distance}" if distance in (1, 2) else "lookalike"


def ts006_tags(pairs: Pairs) -> Counter[str]:
    return Counter(
        ts006_tag(a, b) for (r, _, _), (a, b) in pairs.items() if r == "TS006"
    )


def _root(parent: list[int], i: int) -> int:
    """Union-find root, halving the path on the way."""
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def series_pairs(
    pairs: Pairs, index: CandidateIndex, tuning: ts.RegistryTuning
) -> set[tuple[str, str, frozenset[str]]]:
    """TS006 pairs whose name part is shared by SERIES_MIN_NAMESPACES or more near namespaces."""
    confusables = ts.load_confusables()
    series = set()
    for part in {a.part for (r, _, _), (a, _) in pairs.items() if r == "TS006"}:
        group = index.by_part[part]
        parent = list(range(len(group)))
        for i, a in enumerate(group):
            for j in range(i + 1, len(group)):
                if ts.ts006_scope(a.name, [group[j]], confusables, tuning):
                    parent[_root(parent, i)] = _root(parent, j)
        sizes = Counter(_root(parent, i) for i in range(len(group)))
        component = {r.name.raw: _root(parent, i) for i, r in enumerate(group)}
        for key in pairs:
            rule_id, _, raw_pair = key
            if rule_id != "TS006":
                continue
            raws = list(raw_pair)
            if raws[0] in component and raws[1] in component:
                c = component[raws[0]]
                if c == component[raws[1]] and sizes[c] >= SERIES_MIN_NAMESPACES:
                    series.add(key)
    return series


def owner_token_exempted(pairs: Pairs, platforms: frozenset[str]) -> Counter[str]:
    """E: platform pairs with equal owner tokens, in a run without E (the pairs E removes)."""
    counts: Counter[str] = Counter()
    for (rule_id, _, _), (a, b) in pairs.items():
        if (
            rule_id in OWNER_TOKEN_RULES
            and classify(a, b, platforms) == PLATFORM
            and a.scope == b.scope
            and ts.same_owner_token(a, b)
        ):
            counts[rule_id] += 1
    return counts


def top_namespaces(pairs: Iterable[tuple[ts.Name, ts.Name]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for a, b in pairs:
        counts.update({a.scope, b.scope} - {None})
    return counts


def sample_pairs(
    pairs: Iterable[tuple[str, str]], n: int, seed: int, rule_id: str
) -> list[tuple[str, str]]:
    """Up to n pairs, the same for the same pairs and seed. Seeded per rule, so a change in one
    rule's pairs leaves the other rules' samples alone."""
    pool = sorted(pairs)
    picked = random.Random(f"{seed}:{rule_id}").sample(pool, min(n, len(pool)))
    return sorted(picked)


def pair_detail(rule_id: str, a: ts.Name, b: ts.Name, series: bool = False) -> str:
    if rule_id == "TS003":
        return f", distance {ts.edit_distance(a.part, b.part, MAX_LENGTH_DELTA)}"
    if rule_id == "TS006":
        return f", {ts006_tag(a, b)}" + (", series" if series else "")
    return ""


def non_negative(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--sample", type=non_negative, default=DEFAULT_SAMPLE)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    try:
        platforms = ts.load_platform_namespaces()
    except (OSError, yaml.YAMLError, RuleDataError) as exc:
        log(f"data/platform_namespaces.yaml is unreadable or malformed: {exc}")
        return 1
    try:
        reference = tc.parse_reference_names(tc.read_reference_bytes())
    except OSError:
        log(f"cannot read {tc.REFERENCE_SOURCE_NAME}; build it first")
        return 1
    except (tc.ReferenceFileError, ShapeMismatch) as exc:
        log(f"{tc.REFERENCE_SOURCE_NAME} is malformed: {exc}")
        return 1

    refs = reference.by_ecosystem[ECOSYSTEM]
    index = CandidateIndex(refs)
    log(
        f"{tc.REFERENCE_SOURCE_NAME}: dated {reference.generated_at.isoformat()}, "
        f"{reference.entry_count} entries, partial {str(reference.partial).lower()}; "
        f"{len(refs)} registry names"
    )

    before = collect_pairs(refs, index, ts.UNTUNED)
    after = collect_pairs(refs, index, ts.REGISTRY_TUNING)
    without_e = collect_pairs(
        refs, index, replace(ts.REGISTRY_TUNING, platform_owner_token=False)
    )
    pairs = after.pairs

    full = len(refs) * max(len(refs) - 1, 0)
    log(
        f"index: {after.compared} comparisons per run instead of {full} "
        f"({after.compared / full:.2%} of a full pairwise run)"
        if full
        else "index: nothing to compare"
    )
    for label, run in (("before", before), ("after", after), ("without E", without_e)):
        if run.errors:
            log(
                f"{label}: rules skipped other than not_applicable (see stderr logging):"
            )
            for error, count in sorted(run.errors.items()):
                log(f"  {error}: {count}")

    log()
    log(
        "pairs per rule by namespace class, before -> after the registry tuning "
        f"(platform namespaces: {', '.join(sorted(platforms))}):"
    )
    log(f"  {'rule':6} {'same':>14} {'different':>14} {'platform':>14} {'total':>14}")
    counts_before = class_counts(before.pairs, platforms)
    counts_after = class_counts(pairs, platforms)
    for rule_id in ts.RULE_IDS:
        b, a = counts_before[rule_id], counts_after[rule_id]
        cells = [f"{b[c]} -> {a[c]}" for c in CLASSES] + [
            f"{sum(b.values())} -> {sum(a.values())}"
        ]
        log(f"  {rule_id:6} " + " ".join(f"{cell:>14}" for cell in cells))

    case_only: Counter[str] = Counter()
    for (rule_id, _, _), (a, b) in before.pairs.items():
        if a.scope == b.scope and a.raw_scope != b.raw_scope:
            case_only[rule_id] += 1
    log(
        "  before: same-namespace pairs whose namespaces differ only in case: "
        + ", ".join(f"{r}={case_only[r]}" for r in ts.RULE_IDS)
    )

    exempted = owner_token_exempted(without_e.pairs, platforms)
    log(
        "  exempted by owner token (E, platform pairs with equal first tokens): "
        + ", ".join(f"{r}={exempted[r]}" for r in ts.RULE_IDS)
    )

    log()
    series_after: set = set()
    for label, run, tuning in (
        ("before", before, ts.UNTUNED),
        ("after", after, ts.REGISTRY_TUNING),
    ):
        tags = ts006_tags(run.pairs)
        series = series_pairs(run.pairs, index, tuning)
        if run is after:
            series_after = series
        log(
            f"TS006 pairs by tag, {label}: "
            + ", ".join(f"{t}={tags[t]}" for t in TS006_TAGS)
            + f"; series (name part shared by {SERIES_MIN_NAMESPACES}+ near namespaces)="
            + f"{len(series)}"
        )

    for rule_id in ts.RULE_IDS:
        rule = ts._RULES[rule_id]
        severity, confidence = rule.severity, rule.confidence
        if rule_id == "TS006":
            severity = ts.REGISTRY_TUNING.ts006_severity or severity
            confidence = ts.REGISTRY_TUNING.ts006_confidence or confidence
        rule_pairs = {
            tuple(sorted((a.raw, b.raw))): (a, b, location)
            for (r, location, _), (a, b) in pairs.items()
            if r == rule_id
        }
        log()
        log(
            f"{rule_id} ({confidence.value} confidence, {severity.value} on the registry "
            f"tier): {len(rule_pairs)} pairs after tuning"
        )
        top = top_namespaces((a, b) for a, b, _ in rule_pairs.values())
        log(f"  top {min(TOP_NAMESPACES, len(top))} namespaces by pair count:")
        for namespace, count in top.most_common(TOP_NAMESPACES):
            platform = " (platform)" if namespace in platforms else ""
            log(f"    {count:>6}  {namespace}{platform}")
        pool = [
            key
            for key, (a, b, _) in rule_pairs.items()
            if classify(a, b, platforms) in SAMPLED
        ]
        sample = sample_pairs(pool, args.sample, args.seed, rule_id)
        log(
            f"  sample of {len(sample)} from {len(pool)} different-namespace and platform "
            f"pairs (seed {args.seed}):"
        )
        for key in sample:
            a, b, location = rule_pairs[key]
            log(
                f"    {key[0]} ~ {key[1]} ({PARTS.get(location, location)}, "
                f"{classify(a, b, platforms)}"
                f"{pair_detail(rule_id, a, b, (rule_id, location, frozenset(key)) in series_after)})"
            )

    log()
    log(f"elapsed {time.perf_counter() - started:.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
