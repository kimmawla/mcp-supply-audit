# Benign corpus for the tool-definition rules

The benign side of the TD001-TD008 evaluation (`scripts/eval_tool_defs.py`, section 3): real
`tools/list` snapshots from servers trusted enough to count a finding on them as a false
positive. The positives live in `tests/fixtures/eval/` (see `MANIFEST.yaml` there).

The scanner never runs a target. Collecting a snapshot does run one, so it is a manual step,
done by the maintainer, in a container, in two separate phases. Nothing here is automated in
CI, and nothing in this procedure was run while writing it.

## Candidates

Only these servers, nothing else:

1. The reference servers listed in the "Reference Servers" section of the
   modelcontextprotocol servers README, checked on 2026-11-07:
   <https://github.com/modelcontextprotocol/servers#reference-servers>. The archived servers
   (moved to `modelcontextprotocol/servers-archived`) are not candidates.
2. The maintainer's own two servers.

Versions are the latest published on 2026-11-07, read from the npm registry and PyPI JSON
APIs. Pin these exact versions; re-check before a new collection.

| Slug | Package | Ecosystem | Version | Entry point (run phase) | Source |
|---|---|---|---|---|---|
| everything | `@modelcontextprotocol/server-everything` | npm | 2.2.1 | `dist/index.js` | <https://github.com/modelcontextprotocol/servers/tree/main/src/everything> |
| fetch | `mcp-server-fetch` | pypi | 2026.11.4 | `mcp-server-fetch` | <https://github.com/modelcontextprotocol/servers/tree/main/src/fetch> |
| filesystem | `@modelcontextprotocol/server-filesystem` | npm | 2.2.0 | `dist/index.js /tmp` | <https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem> |
| git | `mcp-server-git` | pypi | 2026.11.4 | `mcp-server-git` | <https://github.com/modelcontextprotocol/servers/tree/main/src/git> |
| memory | `@modelcontextprotocol/server-memory` | npm | 2.1.0 | `dist/index.js` | <https://github.com/modelcontextprotocol/servers/tree/main/src/memory> |
| sequential-thinking | `@modelcontextprotocol/server-sequential-thinking` | npm | 2.1.1 | `dist/index.js` | <https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking> |
| time | `mcp-server-time` | pypi | 2026.11.4 | `mcp-server-time` | <https://github.com/modelcontextprotocol/servers/tree/main/src/time> |
| vuln-triage-mcp | `vuln-triage-mcp` | pypi | 0.1.0 | `vuln-triage-mcp` | <https://github.com/kimmawla/vuln-triage-mcp> |
| mcp-supply-audit | this repo, `git archive HEAD` | source | 0.1.0 | `mcp-supply-audit` | <https://github.com/kimmawla/mcp-supply-audit> |

`tests/fixtures/tool_defs/benign/vuln_triage_mcp.json` and the own-tools test in
`tests/test_tool_defs.py` already cover the last two. They were used while writing the rules,
so they are development negatives and say little about false positives elsewhere. They stay
in the corpus for completeness.
`scripts/dump_tools.py` refreshes those two snapshots outside the container: it runs only
`vuln-triage-mcp` and `mcp-supply-audit`, each with a fixed command, writes to
`local_fixtures/` by default, and refuses any other server or argument with a pointer to
`scripts/collect_tools_list.py`.

## Licenses: which snapshots may be committed

A snapshot copies the server's tool names, descriptions and schemas, so it is a copy of part
of the work, and the work's license decides. The licenses were read on 2026-11-07:

| Slug | License found | Where | Commit? |
|---|---|---|---|
| fetch, git | MIT | package metadata (`license = {text = "MIT"}`) and `src/<dir>/LICENSE` ("Copyright (c) 2024 Anthropic, PBC.") | yes, with the MIT notice |
| time | MIT | package metadata; no `LICENSE` in `src/time/`, so the repo root applies too | yes, with the MIT and root notices |
| everything, filesystem, memory, sequential-thinking | "SEE LICENSE IN LICENSE", meaning the repo root `LICENSE`: Apache-2.0 for new and relicensed contributions, MIT for contributions not yet relicensed, CC-BY-4.0 for documentation other than specifications | <https://github.com/modelcontextprotocol/servers/blob/main/LICENSE> | yes, with the root `LICENSE` text and a note that the snapshot is a modified extract (Apache-2.0 section 4) |
| vuln-triage-mcp | MIT (PyPI `license_expression`) | your own | yes |
| mcp-supply-audit | MIT (`pyproject.toml`, `LICENSE`) | this repo | yes |

So every candidate's license allows committing a snapshot, provided the notice travels with it.
For a committed snapshot, add `tests/fixtures/eval/benign/LICENSES/<slug>.txt` with the license
text and copyright line that apply, and an entry in `tests/fixtures/eval/benign/MANIFEST.yaml`.

This is a reading of the license files, not legal advice. Two points to check:

- The npm tarballs contain no `LICENSE` file (the memory 2.1.0 tarball holds only
  `dist/index.js`, `dist/version.js`, `package.json` and `README.md`). "SEE LICENSE IN LICENSE"
  therefore points at a file that is not shipped, and the license comes from the repository at
  the release commit. Record that URL as `source_url`.
- Before committing, re-read the license in what was actually installed (`package.json`
  `license`, or `METADATA` `License-Expression` / `License`) and in the repo at that version. If
  it is not MIT, Apache-2.0 or CC-BY-4.0, or cannot be determined, keep the snapshot in
  `local_fixtures/benign/` only. The report shows local snapshots as counts only.

Committing these snapshots puts real third-party tool names and text under `tests/`. The
repo-hygiene rule in `CLAUDE.md` says tests use invented `zqvex-*` names. Decide before
committing whether the benign corpus is an exception to that rule. If it is, add the
exception to `CLAUDE.md`. If not, keep every snapshot local.

## Procedure

Requirements: Docker, and `uv` for the helper. Run from the repository root. Each server has
two phases:

1. **Install**, with network, writing only into a named volume. No server code runs:
   `npm install --ignore-scripts`, and `pip install` from wheels where they exist.
2. **Run**, with no network, a read-only root filesystem and a read-only volume, no
   environment variables, no capabilities, and an unprivileged user. The container gets no
   `-e`, and the server is started through `env -i` with an absolute path, so not even the
   image's own `ENV` (such as `PATH`) reaches it. `scripts/collect_tools_list.py` talks to it
   over stdio, calls `initialize` and `tools/list`, and writes
   `local_fixtures/benign/<slug>.json` plus a `MANIFEST.yaml` entry (package, ecosystem,
   version, source URL, license, date, image digest). The helper refuses a `docker run` that
   lacks `--network none`, `--read-only`, `--cap-drop ALL` or
   `--security-opt no-new-privileges`, that passes any `-e`/`--env`/`--env-file`, or that
   mounts a volume without `:ro`.

Pull the two images once and record their digests. Use the same image for both phases, so
the interpreter paths in the volume match:

```sh
docker pull node:24-bookworm-slim
docker pull python:3.12-bookworm
NODE_IMAGE=$(docker image inspect --format '{{index .RepoDigests 0}}' node:24-bookworm-slim)
PY_IMAGE=$(docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-bookworm)
echo "$NODE_IMAGE"; echo "$PY_IMAGE"
```

`python:3.12-bookworm` (not `-slim`) is used because it includes `git`, which `mcp-server-git`
looks for at import time. With no `PATH`, Python's subprocess falls back to `/bin:/usr/bin`,
where `git` is.

The run-phase flags shared by every server:

```sh
RUN_FLAGS="-i --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --memory 512m --pids-limit 128 \
  --entrypoint /usr/bin/env"
```

### npm servers

For each row (slug, package, version):

```sh
SLUG=everything PKG=@modelcontextprotocol/server-everything VER=2.2.1
# 1. install (network on)
docker volume create "mcp-eval-$SLUG"
docker run --rm -v "mcp-eval-$SLUG":/opt/srv "$NODE_IMAGE" \
  npm install --prefix /opt/srv --ignore-scripts --no-audit --no-fund "$PKG@$VER"
docker run --rm -v "mcp-eval-$SLUG":/opt/srv:ro "$NODE_IMAGE" \
  node -p "require('/opt/srv/node_modules/$PKG/package.json').license"
# 2. run (network off) and collect
uv run scripts/collect_tools_list.py --slug "$SLUG" --package "$PKG" --ecosystem npm \
  --version "$VER" --image "$NODE_IMAGE" --license "SEE LICENSE IN LICENSE" \
  --source-url https://github.com/modelcontextprotocol/servers/blob/main/LICENSE \
  -- docker run $RUN_FLAGS -v "mcp-eval-$SLUG":/opt/srv:ro "$NODE_IMAGE" \
  -i /usr/local/bin/node "/opt/srv/node_modules/$PKG/dist/index.js"
```

Repeat with:

```sh
SLUG=memory PKG=@modelcontextprotocol/server-memory VER=2.1.0
SLUG=sequential-thinking PKG=@modelcontextprotocol/server-sequential-thinking VER=2.1.1
```

For filesystem, the server needs an allowed directory argument; give it the empty tmpfs:

```sh
SLUG=filesystem PKG=@modelcontextprotocol/server-filesystem VER=2.2.0
# install as above, then:
uv run scripts/collect_tools_list.py --slug "$SLUG" --package "$PKG" --ecosystem npm \
  --version "$VER" --image "$NODE_IMAGE" --license "SEE LICENSE IN LICENSE" \
  --source-url https://github.com/modelcontextprotocol/servers/blob/main/LICENSE \
  -- docker run $RUN_FLAGS -v "mcp-eval-$SLUG":/opt/srv:ro "$NODE_IMAGE" \
  -i /usr/local/bin/node "/opt/srv/node_modules/$PKG/dist/index.js" /tmp
```

Replace `blob/main` in `--source-url` with the release tag or commit once you know it. The
npm packument for these versions has no `gitHead`.

### PyPI servers

```sh
SLUG=time PKG=mcp-server-time VER=2026.11.4 LIC=MIT
SRC=https://github.com/modelcontextprotocol/servers/tree/main/src/time
# 1. install (network on)
docker volume create "mcp-eval-$SLUG"
docker run --rm -v "mcp-eval-$SLUG":/opt/venv "$PY_IMAGE" sh -c \
  "python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --only-binary=:all: $PKG==$VER"
docker run --rm -v "mcp-eval-$SLUG":/opt/venv:ro "$PY_IMAGE" \
  /opt/venv/bin/python -I -c "import importlib.metadata as m; d=m.metadata('$PKG'); print(d.get('License-Expression') or d.get('License'))"
# 2. run (network off) and collect
uv run scripts/collect_tools_list.py --slug "$SLUG" --package "$PKG" --ecosystem pypi \
  --version "$VER" --image "$PY_IMAGE" --license "$LIC" --source-url "$SRC" \
  -- docker run $RUN_FLAGS -v "mcp-eval-$SLUG":/opt/venv:ro "$PY_IMAGE" \
  -i "/opt/venv/bin/$PKG"
```

Repeat with:

```sh
SLUG=fetch PKG=mcp-server-fetch VER=2026.11.4 LIC=MIT SRC=https://github.com/modelcontextprotocol/servers/tree/main/src/fetch
SLUG=git PKG=mcp-server-git VER=2026.11.4 LIC=MIT SRC=https://github.com/modelcontextprotocol/servers/tree/main/src/git
SLUG=vuln-triage-mcp PKG=vuln-triage-mcp VER=0.1.0 LIC=MIT SRC=https://github.com/kimmawla/vuln-triage-mcp
```

If a package publishes no wheel for a dependency, `--only-binary=:all:` fails. Then drop it
for that one install and note in the manifest that a build backend ran in the install phase.

### mcp-supply-audit (from this checkout)

Not on PyPI yet, so the install phase builds from `git archive HEAD` (committed files only),
streamed in on stdin:

```sh
SLUG=mcp-supply-audit PKG=mcp-supply-audit VER=0.1.0 LIC=MIT
docker volume create "mcp-eval-$SLUG"
git archive --format=tar HEAD | docker run -i --rm -v "mcp-eval-$SLUG":/opt/venv "$PY_IMAGE" sh -c \
  "mkdir /tmp/src && tar -x -C /tmp/src && python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir /tmp/src"
uv run scripts/collect_tools_list.py --slug "$SLUG" --package "$PKG" --ecosystem source \
  --version "$VER+$(git rev-parse --short HEAD)" --image "$PY_IMAGE" --license "$LIC" \
  --source-url https://github.com/kimmawla/mcp-supply-audit \
  -- docker run $RUN_FLAGS -v "mcp-eval-$SLUG":/opt/venv:ro "$PY_IMAGE" \
  -i "/opt/venv/bin/$PKG"
```

### After collecting

```sh
uv run scripts/eval_tool_defs.py              # committed + local snapshots
docker volume rm mcp-eval-everything mcp-eval-fetch mcp-eval-filesystem mcp-eval-git \
  mcp-eval-memory mcp-eval-sequential-thinking mcp-eval-time mcp-eval-vuln-triage-mcp \
  mcp-eval-mcp-supply-audit
```

To commit a snapshot after the license check above, copy it with its manifest entry from
`local_fixtures/benign/` to `tests/fixtures/eval/benign/` and add its `LICENSES/<slug>.txt`.
Run `uv run pytest` before committing: the ASCII, hidden-character, token-literal,
personal-data and real-name guards cover `tests/fixtures/eval/`.

If a server exits or fails to start with no network or no environment (for example, a
server that needs a writable home directory or a key at startup), the helper prints only the
exception type. Record it as not collected. Do not loosen the run flags.

## What the report shows for benign snapshots

Per rule: the number of findings and the number of snapshots with at least one. Also the
total snapshots (committed and local), tools, and unscannable files. It prints no evidence
text, no server, tool or file names, and no per-snapshot rows. Benchmark output stays local
(CLAUDE.md). Treat a benign finding as a precision question about the rule, never as a
statement about the server.
