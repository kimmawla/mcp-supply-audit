# Tool-definition rules (input: a tools/list JSON snapshot)

| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| TD001 | Hidden Unicode: zero-width, bidi controls, tag characters in any scanned field (see Fields scanned) | high | high |
| TD002 | Instruction-like phrasing aimed at the model, in any scanned field (see TD002 detail) | high | medium |
| TD003 | Description references tools outside this snapshot, in a call/prefer/avoid/run context, or other servers (see TD003 detail) | medium | medium |
| TD004 | URLs with a scheme, or phrasing that moves conversation content or secrets somewhere, with or without a stated destination ("send the contents", "forward all", "include the full conversation", "to this webhook"), in a description or title (tool `title`, `annotations.title`, and schema `description`/`title` at any depth; see TD004 detail) | medium | medium |
| TD005 | Long encoded blobs (base64/hex runs) | medium | medium |
| TD006 | Excessive description length (threshold in config) | low | high |
| TD007 | Free-text parameters whose names invite conversation content ("notes", "context", "sidenote") | low | low |
| TD008 | Duplicate tool names within one snapshot | medium | high |

Each rule: pure function, one fixture file of positives (`tests/fixtures/tool_defs/suspicious/`).
The benign negatives are shared across rules: every rule runs on every file in
`tests/fixtures/tool_defs/benign/` and on the benign eval corpus below, and the results are
counted per rule (findings, and snapshots with at least one finding).
Phrase lists live in data files, not code, so they can be reviewed and versioned.

## Fields scanned

Every rule reads the same field walk; each rule then picks the field kinds it checks.

- Tool level: `name` (tool name), `title`, `description`, `annotations.title` (title), and every
  other string under `annotations`, keys included, at any depth (annotation text).
- In `inputSchema` and `outputSchema`, at any depth (`properties`, `items`, `prefixItems`,
  `additionalProperties`, `anyOf`/`oneOf`/`allOf`, `not`/`if`/`then`/`else`, `contains`,
  `patternProperties`, `$defs`, `definitions`): `description`, `title`, property names
  (parameter names), `$defs`/`definitions`/`patternProperties` keys (schema keys), the values
  and keys under `enum`, `default`, `const` and `examples` (schema values), and the string
  entries of `required` (required entries).
- Not read: `$comment`, `pattern`, `format`, `$ref`, `type`, `_meta`, unknown keywords.

Kinds checked per rule: TD001 all; TD002 all; TD003 descriptions, titles and schema values;
TD004 descriptions and titles; TD005 descriptions, titles and schema values; TD006 tool and
schema descriptions; TD007 input parameter names; TD008 tool names.

## Phrase matching (TD002, TD003, TD004 data files)

Text is normalized first: NFKC per character, hidden characters dropped, whitespace collapsed
to one space, case folded. A phrase matches on whole words: an edge of the match that is a
letter, digit or `_` may not touch another one, and an edge such as `<` or `:` needs no
boundary (`<important>Do this`). Syntax:

- Words separated by spaces. Between two words the text may also carry one comma
  ("before planning, use").
- `*` stands for zero to three words. A word inside the gap may not contain `.`, `;`, `:`,
  `!` or `?`, so a gap stays inside one clause.
- `(a|b c|d)` is one of the alternatives, each one or more words. `(a|b)?` is optional.
- A phrase may not start or end with `*` or an optional group.

Every pattern is a fixed sequence of words, alternations and bounded gaps, with no nested
repetition, so matching time grows linearly with the text. A test runs every rule on a
snapshot at the size cap filled with hostile repetitions.

## TD002 detail

TD002 checks every kind in the field walk, names included. Each field is matched twice: as
normalized, and with identifier separators split into words (`_`, `-` and `.` become spaces
and a lower-case-to-upper-case step starts a new word), so `doNotTellTheUser` and
`keep_this_hidden_from_the_user` read as phrases. One finding per field, at the first match.

Pattern classes. The phrase families in `td002_instruction_phrases.yaml` are written from these
descriptions and grouped by class:

1. Override of prior instructions: a verb that discards (ignore, disregard, forget, overlook,
   override) aimed at earlier instructions, requests or rules ("previous", "prior", "earlier",
   "preceding", "above", "original", "system"), or at what the user asked ("whatever the user
   gave", "regardless of what the user said", "instead of what the user asked").
2. Hidden or "do not tell the user" instructions: a negated disclosure verb aimed at the user
   ("do not show ... the user", "never mention ... to the user"), the user as subject of a
   negated knowing or seeing ("the user must not be told", "the user should not see"),
   withholding from the user ("keep ... hidden from the user", "leave ... out of anything you
   show the user"), keeping quiet ("keep this quiet", "stay silent"), acting without telling
   ("without informing the user"), covert action ("silently change", "quietly add"), and
   notes addressed to the model ("note for the assistant", "assistant:", emphasis tags such
   as `<important>`). Ordering that jumps the line also belongs here ("before using this
   tool", "call this tool first", "before answering, read ...").
3. Instructions embedded in HTML comments: an HTML comment (`<!--` up to `-->`, or to the end
   of the field when unterminated) whose text contains an addressee word from
   `html_comment_addressees` (assistant, AI, model, LLM, agent, system, you, your). Found by
   code, not by the phrase list, scanning forward with no backtracking.
4. Preference or ranking manipulation: choosing this tool over all others ("choose this tool
   over alternatives", "use this tool instead of any other"), forbidding other tools ("never
   use other tools"), ranking this tool or its results first, or calling this tool the best,
   only or recommended choice.
5. Reading sensitive paths or sending data to another party: a directive cue (first, also,
   then, must, secretly) before a read or find verb aimed at a credential, key file, secret
   path or the system prompt; a send, forward or upload verb aimed at a credential, the whole
   conversation, the chat history, the contact list or the system prompt; redirecting a
   recipient or destination ("change the recipient to", "every message must go to").

Plain guidance to the model ("never report this as safe", "Prefer another tool when ...") is
normal and is not a target. A tool description in the imperative mood ("Read a file") is
normal, so the read and send families need a cue word or a sensitive object.

## TD003 detail

TD003 reports a field when it holds a phrase from `td003_cross_references.yaml` ("another
server", "any other tool"), a server reference ("server named x"), or a tool reference that
meets all of the following:

- Name shape: snake_case (`zqvex_send`), kebab-case (`zqvex-send`), dotted (`zqvex.send`), or
  camelCase (`zqvexSend`), unquoted or in backticks, single or double quotes. A quoted name
  may also be a single word.
- Reference form: the name is followed by "tool", "function" or `()`, or follows "tool named"
  / "tool called", or is a quoted snake/kebab/dotted/camel name. An unquoted name with none of
  these is not a reference ("read-only mode").
- Not generic: the word right before the name is not "a", "an", "any", "another", "some",
  "each" or "every" ("use a read-only tool" names a kind of tool, not a tool).
- Context: in the same sentence, one of the `context_before` words in the four words before
  the name (call, invoke, use, using, employ, run, execute, trigger, consult, query, prefer,
  choose, pick, select, favor, prioritize, avoid, skip, through, via, instead of, rather
  than, in place of), or a passive form in the six words after the reference (`passive_aux`
  then `passive_verbs`, with at most one word between: "is called", "is later used").
- Outside the snapshot: the name, case folded, is not the name of a tool in the same
  snapshot (a reference to a sibling tool is routing). A quoted name with no "tool"/`()`
  suffix is also exempt when it is a parameter name or schema key declared in the snapshot
  ("use `page_token` from the last response").

The context lists live in `td003_cross_references.yaml`. A name reference without context
("works like the zqvex_send tool") is not a finding.

## TD004 detail

TD004 checks tool and schema descriptions and titles. It reports a field that holds any of:

- A URL with a scheme (`http`, `https`, `ftp`, `ws`, `wss`, `file`, `gopher`) or a `mailto:` /
  `data:` URI. Bare domains are not flagged.
- A phrase from `phrases` in `td004_exfiltration.yaml`: conversation content or secrets moved
  somewhere, with or without a stated destination ("send the contents", "include the full
  conversation", "to this webhook").
- A send-to construction, built from `send_verbs` and `send_objects` in the same file, with
  the phrase matching rules above: a send verb (send, forward, post; base form only, so a tool
  describing itself, "Posts the output to a channel", is not matched), up to three words, a
  conversation-like or secret-like object (conversation, chat, history, context, output,
  credentials, tokens, system prompt, and their plurals), up to three words, then "to"
  followed by a destination. The destination is the next word, whatever it is: a URL, a
  placeholder or any noun phrase. "to" at the end of a clause is not a destination.

One finding per field, at the first match.

## Evaluation corpus

Separate from the per-rule fixtures above. It measures the rules and is never used to tune them.

- Positives: `tests/fixtures/eval/positives/`, one inert fixture per pattern from public
  research. `tests/fixtures/eval/MANIFEST.yaml` holds each pattern's source URL, a one-line
  description, the rule ids the spec expects (set before scanning; `[]` with
  `scope: outside` when one snapshot cannot show the pattern) and the key phrase that
  mutations target.
- Mutations: `scripts/eval_mutations.py`, generated in memory and never committed. Types:
  case, whitespace runs, whitespace inside words, split across description and title,
  synonym (fixed list), moved into a parameter description, Cyrillic homoglyphs.
- Benign: real `tools/list` snapshots collected by hand in a locked-down container, as set out
  in `docs/benign-corpus.md`.
- Report: `uv run scripts/eval_tool_defs.py`. It is offline and deterministic, and its output
  stays local.
- Denominators: positive counts (at least one expected rule fired, exact match, extra rules
  fired) are taken over the counted patterns only: `scope: static` and a source with
  `fetched: true`. Patterns with `scope: outside` and static patterns from an unfetched source
  are listed by id and left out of every count, including the mutation rates.
- Mutation artifacts: a (pattern, mutation, rule) cell where the mutation removes what the
  rule looks for is listed in `MUTATION_ARTIFACTS` in the report script, left out of the rates
  and shown separately. Two today: upper-casing a base64 blob (p20, case, TD005) and the
  synonym list renaming a duplicated tool name (p18, synonym, TD008).
- Out of documented scope: a (pattern, rule) expectation that the rule's documented scope
  does not cover is listed in `OUT_OF_SCOPE` in the report script with its reason. The
  manifest keeps the expectation. The report shows it, leaves its mutant cells out of that
  rule's rates, and leaves the pattern out of the exact-match denominator; the "at least one
  expected rule fired" and "extra rules fired" counts still use every counted pattern. Four
  today, all TD004: p02 and p04 (recipient redirect, no URL or send/post-to phrasing), p21 (a
  secret routed into another tool's argument), p23 (no destination; the free-text context
  parameter is what TD007 covers).
- Miss causes: `MISS_CAUSES` in the report script records the hand-classified cause of a
  remaining miss on a pattern left out of the counts, shown under the unfetched list. One
  today: p14, TD002, cause (b).
- Baseline: `docs/eval-baseline.md` records the counts measured before any rule change.
- Held-out set: `tests/fixtures/heldout/` (`MANIFEST.yaml`, `positives/`, `benign/`), with the
  same manifest schema as the eval corpus, scored by `uv run scripts/eval_heldout.py`. It prints
  counts only: over the counted patterns, at least one expected rule fired, exact match and
  extra rules fired (no `OUT_OF_SCOPE` or artifact cells); for benign, snapshots with any
  finding and findings per rule. Each benign finding (file, rule, tool name, hidden and
  non-ASCII characters escaped) goes to `local_fixtures/heldout-findings.tsv`, overwritten each
  run, and only the row count is printed. Exit 1 when the corpus is missing.

## Known gaps

Recorded so the evaluation is read against what the rules can see today. Not yet addressed.

- Field walk (all rules): `$comment`, `pattern`, `format`, `$ref`, `type`, `_meta` and unknown
  schema keywords are not read (see Fields scanned).
- TD002 matches word sequences: a word split by a space ("ign ore"), a synonym outside the
  families, or a Cyrillic homoglyph is not matched. Read and send families need a cue word or
  a sensitive object, so "read the file at <path>" with an ordinary path is not matched.
- TD003 needs a reference form and a context: a bare unquoted name with no "tool" suffix
  ("call zqvex_send"), or a reference with its verb more than four words before it, is not
  matched. PascalCase names are not a name shape.
- TD004 does not cover a secret routed into another tool's argument, redirecting a recipient
  without send-to wording, or a send verb other than send, forward and post ("email",
  "upload", "relay").
