# Typosquat rules (source of truth)

Tool: `check_typosquat(name, ecosystem)`. Input is a name already validated by `validation.py` and an
ecosystem of `pypi`, `npm`, or `registry`. **No network access at runtime.** All comparison is against a
dated reference-names file shipped inside the package.

Findings say "similar to X". They never say "typosquat of X", "malicious", or "impersonating".
A match is a reason to look closer, not a verdict. Legitimate near-name pairs exist.

## Reference names
- File: `data/reference_names.json`. ASCII only, sorted keys, loaded through `importlib.resources` and `safe_json`.
- Compact format. Top-level fields, exactly:
  - `sources`: the source table, a list of `{id, name, type, url}` with unique `id`s and `https` URLs.
  - `curated`: hand-curated entries, a list of `{checked_at, ecosystem, name, source}`. `source` is
    the `id` of a source whose `type` is curated; `checked_at` is the ISO date the entry was checked
    against its source.
  - `listed`: crawled names, one block per ecosystem (only `registry` is allowed):
    `{"registry": {"names": [...], "page_cap", "page_size", "pages_fetched", "partial", "source"}}`.
    `names` is sorted with no repeats; `source` is the `id` of a `listed-not-curated` source and is
    recorded once for the whole list. The crawl date is `generated_at`. `listed` is `{}` when the
    file was built without a crawl.
  - `generated_at`: ISO date.
- `partial` is true only when the crawl stopped at its page cap; then `pages_fetched` equals
  `page_cap`. A crawl that stops because the server returned no next cursor is not partial. A crawl
  that reaches its time limit (exit 3) or gets a cursor the server already returned (exit 4) aborts:
  it writes no file, leaves an existing file untouched, and states the stop reason on stderr.
- Each name appears once per ecosystem across `curated` and `listed`; a crawled name that is also
  curated is kept only as the curated entry.
- A source `type` is one of: `reference-server` (an MCP reference server, from its own manifest in the
  modelcontextprotocol/servers repo), `dependency` (a runtime dependency of this project), or
  `listed-not-curated` (a server name listed by the MCP Registry crawl, not reviewed by hand).
- "Reference names" are names worth protecting: a curated list plus names from a registry crawl. They are
  NOT ranked by popularity, because none of the allowed hosts provides usage data.
- Tiers: `pypi` and `npm` comparisons use only curated entries (`reference-server`, `dependency`).
  Registry-crawl names (`listed-not-curated`) feed only the `registry` ecosystem, and a finding against
  one says so in its evidence. The `registry` tier also has its own tuning (below); `pypi` and `npm`
  never use it and never read the platform namespaces file.
- Every curated entry has a source URL that was checked by hand or fetched, never written from memory.
  The curated list is `scripts/curated_names.yaml`; the build script refuses an entry without a source URL.
- The file is built by `scripts/build_reference_names.py` (dev only, never imported by `src/`) and refreshed
  deliberately. The report always records the file's date, entry count (curated entries plus listed
  names), and `partial` under `data_sources`.
- If the file is older than 120 days, the report adds an info note saying the reference data may be stale.
- If the file is partial, a `registry` report adds an info note with the number of listed names and
  pages fetched. The note never appears when `partial` is false, and never on a `pypi` or `npm`
  report (their comparisons do not use the crawled list); `data_sources` still carries `partial`.
- A malformed reference file is a `shape_mismatch` skip for every rule, with detail "reference file
  malformed". An unreadable one is `not_determinable` with detail "reference file unreadable". An
  ecosystem with no reference entries is `not_determinable` with detail "no reference names for this
  ecosystem". `rule_error` is kept for crashes. None of these is ever a pass.

## Normalization
- PyPI: lowercase, and each run of `-`, `_`, `.` collapses to one `-`.
- npm: lowercase. A scoped name is split into scope and package, and each part is compared separately.
- registry: split into namespace and name at the `/`, and lowercase both parts. Namespace and name are
  compared separately.
- Comparisons are only made between names of the same ecosystem. TS002-TS005 compare the package or name
  part against references with the same normalized scope or namespace (or none); TS006 compares the scope
  or namespace when the package or name part is equal.
- TS002 skeletons apply `data/confusables.yaml` to the name as written (so uppercase `I` is still visible),
  then normalize as above.

## Rules

| Rule | Detects | Severity | Confidence | OWASP |
|---|---|---|---|---|
| TS001 | Name equals a reference name after normalization but is written differently (case, or `-`/`_`/`.` variants for PyPI) | medium | high | MCP04 |
| TS002 | ASCII-confusable skeleton equals a reference name's skeleton (`l`/`1`/`I`, `O`/`0`, `rn`/`m`, `vv`/`w`) | medium | medium | MCP04 |
| TS003 | Damerau-Levenshtein distance 1 from a reference name (distance 2 when the name has 9 or more characters) | low | low | MCP04 |
| TS004 | A reference name with a common affix added or removed (`-mcp`, `mcp-`, `-server`, `-official`, `-py`, `-js`) | low | low | MCP04 |
| TS005 | Same tokens as a reference name in a different order | low | low | MCP04 |
| TS006 | npm scope or registry namespace is close to a reference scope or namespace while the package part matches | medium | low | MCP04 |

The table gives each rule's own severity and confidence, which `pypi` and `npm` use. On the
`registry` tier TS005 does not run, and TS006 is low severity, low confidence (tuning B and D).

OWASP IDs are checked by a test against the table in `owasp.py` (MCP04 is "Software Supply Chain Attacks &
Dependency Tampering" in the table fetched on 2026-11-02).

## Registry tier tuning
Applies to `registry` names only. Each item is one named constant in `detectors/typosquat.py`,
collected in `REGISTRY_TUNING`. `UNTUNED` is the same rules with every item off; only the
precision report uses it, for its before counts.

- **A. Same namespace is one publisher** (`REGISTRY_EXEMPT_SAME_NAMESPACE`). A reference in the
  same namespace as the name never produces TS001, TS003, TS004 or TS005. The registry grants a
  namespace only to its owner, so names inside one namespace are one publisher's family.
  Namespaces are compared lowercased, so owners that differ only in case are the same namespace.
  Since these rules compare only within the namespace, on the registry tier they fire only in a
  platform namespace. The rules are still recorded as ran.
  - **Platform namespaces are not exempt**, except as E says. `data/platform_namespaces.yaml` lists namespaces that
    publish for many unrelated owners, with the owner inside the name part (the file lists them). Each
    entry has a `namespace`, a quoted ISO `checked_at` and non-empty `evidence`, taken from the
    registry API or the registry repository. A malformed file is `shape_mismatch` for TS001, TS003
    and TS004 on registry names; TS005 is not used there (B).
- **B. TS005 is not used** (`REGISTRY_DROP_TS005`). It is recorded as `not_applicable` with detail
  "rule not used for registry names". `pypi` and `npm` keep it.
- **C. Case-only namespace differences never produce a finding** (`REGISTRY_IGNORE_NAMESPACE_CASE`),
  on any rule, platform namespaces included. TS001 fires only when the name parts are written
  differently; TS006 already treats such namespaces as the same. The registry compares
  `io.github.<owner>` permission case-sensitively (a byte prefix match against the login; see
  docs/api-notes.md, "Publishing and verification rules"). GitHub logins are case-insensitive.
  That last statement is the maintainer's; GitHub's username policy and "Changing your username"
  pages say nothing about case (checked 2026-11-04). The 2026-11-03 reference file has 5 pairs of
  names that differ only in the case of an `io.github` owner.
- **D. TS006 is narrowed** (`REGISTRY_TS006_MAX_DISTANCE`, `REGISTRY_TS006_DISTANCE_2_PREFIX`,
  `REGISTRY_TS006_TLD_VARIANT`, `REGISTRY_TS006_SEVERITY`, `REGISTRY_TS006_CONFIDENCE`). With the
  package part equal, it fires when the namespaces are:
  - **distance 1** (Damerau-Levenshtein; inserting or removing a hyphen is one edit, so
    `zqvex-lab` and `zqvexlab` match), for all namespaces;
  - **distance 2**, only when both namespaces start with `io.github.` (owner names one or two
    edits apart). A pair with one `io.github.` namespace and one other is held to distance 1;
  - a **tld-variant**: the same number of labels, equal except the first one (`com.x` and `io.x`),
    whatever the distance between the first labels;
  - or written with **lookalike characters**: equal confusable skeletons.

  A finding is low severity, low confidence, and still says "similar to X". Methods in evidence
  are `scope edit distance 1` (or `2`), `namespace differs only in its first label`, and
  `scope has lookalike characters`.

  The precision report also tags a TS006 pair as a **series** when its name part is shared by 3
  or more near namespaces (a connected group in which `ts006_scope` fires between neighbours,
  e.g. one name part published under several country domains). A series is tagged and counted
  only. It is never exempted, because the same shape is what a set of lookalike namespaces would
  produce.
- **E. Owner token in platform namespaces** (`REGISTRY_PLATFORM_OWNER_TOKEN`). In a platform
  namespace the first hyphen-separated token of the name part is taken as the owner token
  (`zqvex` in `ai.example/zqvex-widget`, lowercased like the rest of the name). A pair with equal
  owner tokens does not fire TS003 or TS004: it is read as one owner's family of names. A pair
  with different owner tokens still fires and is reviewed. TS001 and TS002 are unaffected.
  - **Limit:** the first token cannot tell owner `foo-bar` from owner `foo`. The names
    `foo-bar-tool` (owner `foo-bar`, server `tool`) and `foo-bar-tools` (owner `foo`, server
    `bar-tools`) both give `foo`, so a lookalike from a different owner who shares the first
    token is exempted too. That is why the precision report prints an "exempted by owner token"
    count per rule instead of hiding these pairs.

## Behavior
- A name shorter than 5 characters skips TS002 through TS006. Record `not_applicable` with the detail
  "name too short". Length is measured on the package part (scoped npm) or the name part (registry).
  TS001 still runs.
- TS006 on a PyPI or unscoped npm name is `not_applicable` with detail "name has no scope or namespace".
- If the name exactly equals a reference name, report no findings and add an info note that it is a
  reference entry; every rule is `not_applicable` with detail "name is a reference entry". A reference
  name never produces a finding against itself or against another entry of the same normalized form that
  is also a reference name.
- Distance, confusable, and affix rules never fire against a name that is itself a reference entry.
- Evidence for a finding is: the nearest reference name, the rule's method, and the entry's source tag.
  Never return more than three reference names, and never echo the list. Each rule reports at most its
  nearest match; when findings would name more than three distinct reference names, the rest are left out
  and an info note gives their count.
- Confusable mappings live in `data/confusables.yaml`, each entry with a comment explaining it.
- Affix lists live in a data file, not code.
- Every rule is a pure function over `(normalized name, reference set)`, plus its rule data, the
  registry tuning and the platform namespaces passed in.
- A rule that raises is recorded as `rule_error` in coverage. A crash never looks like a pass. A malformed
  confusable or affix data file is `shape_mismatch` for the rules that read it, as for other rule data.
- Report coverage lists each rule as ran, or skipped with one of the eight fixed reasons plus a detail.

## Notes (fixed set)
check_typosquat adds only these info notes, in this wording; `N`, `P` and the date are the only
variable parts. Notes never change the assessment.

- `The reference names are dated YYYY-MM-DD, more than 120 days ago, so the reference data may be stale.`
- `The registry reference list is partial: N entries from the first P pages.` (registry reports only)
- `The name is itself an entry in the reference names, so the similarity rules do not apply to it.`
- `N further match(es) against other reference names are not shown, so the reference list is never echoed.`

## Known limits (quoted by the README)
- The reference list is incomplete by nature. No match does not mean a name is safe.
- Legitimate near-name pairs exist and will produce findings. Review them.
- Non-ASCII and homoglyph names are rejected earlier by validation, so Unicode lookalikes are out of scope.
- Recall can only be measured on synthetic mutations of reference names, not on real attacks.
- The tool never names a real package as malicious.