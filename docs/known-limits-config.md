# Known limits: config checks

`scan_mcp_config` reads only the config text you paste. It never opens a file, never contacts a
host, and never runs a command. The checks below cannot run for that reason, or because the
client's or runner's documentation does not say what the config means. Undocumented forms are
skipped checks in the report (`not_determinable`), so their absence is never a pass.

| Check that cannot run | Why | What you lose |
|---|---|---|
| Contents of `envFile` (Cursor, VS Code) | The file is named by path; the tool reads no files | Secrets and risky variables in that file are not seen by CF003 or CF007 |
| What a `headersHelper` runs | CF004 flags the field's presence; its value is never read | A helper is reported the same way whether it reads a token file or downloads and runs code |
| VS Code `inputs` of type `command` | They run an editor command ID (not a shell command) at the top level of `mcp.json`, not in a server | An extension command that supplies a value is not reported |
| VS Code `dev.debug` | The docs do not say what the debugger launches | A debug setup is not reported |
| Runner calls inside a shell string (`cmd /c npx ...`, `bash -c "uvx ..."`) | The string is not split into a runner and its arguments | CF004 flags the shell wrapper, but CF001 and CF006 do not check the package inside it |
| bunx version pins | Bun's docs show `@3.14.0` and `@2` but do not say either pins | Only no version and `@latest` are reported; any other bunx version is skipped |
| Runner options the docs read do not list (`uvx --python`, `npx --registry`, ...) | Their effect on which argument is the package is not documented | CF001 and CF006 are skipped for that server |
| `yarn dlx`, `bun x`, `docker run`, and other runners | Not in `config_runners.yaml` | Unpinned images and packages they run are not reported |
| Whether a pinned version is safe | No network access | Use `audit_package` for a package's advisories and supply-chain signals |
| Values filled in at start-up (`${VAR}`, `${input:id}`) | Their values are not in the config | A placeholder is never reported as a secret; a `${...}` URL or package spec is skipped |

Other limits:

- Secret detection by value shape covers the documented token formats in `secrets.py` (GitHub,
  GitLab, Slack, Stripe, AWS access key ids). By key name it uses
  `src/mcp_supply_audit/data/rg011_credential_params.yaml`, matched as the whole key or its last
  `_`/`-` part. A secret under an unlisted key name in an unlisted format is not found.
- A credential-named key with any literal value is reported, even a non-secret one
  (`ENABLE_TOKEN: "true"`): the rule cannot tell, so confidence is medium.
- CF005 knows roots, drive roots and home directories (`/`, `C:\`, `~`, `/Users/<name>`,
  `/home/<name>`, `${userHome}`, `%USERPROFILE%`). Other broad paths (`/etc`, a whole data disk) are
  not reported.
- bash, zsh, dash, ksh and fish are treated as POSIX `sh` for `-c`; their own manuals were not read.
- Shell detection uses the command's basename, so a shell renamed or reached through `env`
  (`/usr/bin/env bash -c ...`) is not detected.
