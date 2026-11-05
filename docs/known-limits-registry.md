# Known limits: registry checks

mcp-supply-audit only contacts four hosts: registry.modelcontextprotocol.io, pypi.org,
registry.npmjs.org and api.osv.dev. It never downloads or runs a server's code, and never opens a
URL taken from a listing. The checks below need data from other hosts, so they never run. Each
report lists them as skipped, with the reason, so their absence is never a pass.

| Check that cannot run | Why | What you lose |
|---|---|---|
| Ownership of Docker/OCI images | The marker is a label inside the image, on docker.io, ghcr.io, quay.io and others | No proof that an image belongs to the server it is listed under |
| Ownership of NuGet and Cargo packages | The marker is in the README on api.nuget.org or crates.io | Same, for .NET and Rust packages |
| Whether NuGet, Cargo and OCI packages and versions exist | Their indexes are not on the allowed hosts | A listing can name a package that was never published, or was removed |
| MCPB download: hash and reachability | The file is on github.com or gitlab.com | The published SHA-256 is never compared with the file, and a dead link is not detected. (The registry does not check the hash either; MCP clients are expected to.) |
| Repository checks | GitHub and GitLab are not allowed hosts | Repository URLs are compared as text only. Nothing confirms the repository exists, who owns it, or that the package is built from it |
| Domain ownership for names like `com.example/...` | The registry proves it with DNS or a file on the domain | The namespace is taken on trust. Remote hosts are compared with the namespace by name only (RG010, info level) |
| Ownership or publisher changes over time (RG007) | PyPI shows only current owners, with no dates; npm's publish history is in a document too large to fetch | A recent takeover of a package is not detected |
| Remote servers' actual behaviour | Remote URLs are never contacted | Only the URL text is checked: https, credentials in the URL, unusual ports, host vs namespace |
| Package downloads and age | No allowed source reports downloads; package age needs project-level documents above the size caps | No popularity or age signal |

Other limits:

- Registry name lookups are case-sensitive. Use the exact name the registry shows; a name in
  another case is reported as not found.
- The registry runs its ownership checks only when its own `EnableRegistryValidation` setting is
  on, and that setting is not visible from outside. RG005 therefore reports that a package does not
  match the registry's published ownership check (verifier commit `01e5c936`); it cannot tell you
  whether the registry ran that check when the entry was published.
- `fileSha256` on a package that is not mcpb, and a `registryBaseUrl` other than the official one
  for its package type, are not checked. The registry's verifier rejects both, but they are not
  ownership signals.
- An mcpb URL written with an explicit port, such as `https://github.com:443/...`, fails RG005 by
  design: the verifier compares the host including the port, so it would not match either.
- Credential detection in remote URLs uses a reviewed list of parameter names
  (`src/mcp_supply_audit/data/rg011_credential_params.yaml`) and the documented token formats of
  GitHub, GitLab, Slack, Stripe and AWS (`src/mcp_supply_audit/secrets.py`). A secret in an
  unlisted parameter or a path segment is found only if it matches one of those formats. Google's
  `?key=` values, npm tokens and PyPI tokens are not detected (no documented prefix was found for
  npm or PyPI).
