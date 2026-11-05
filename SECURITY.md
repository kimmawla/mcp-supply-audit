# Security policy

This policy covers vulnerabilities in mcp-supply-audit itself. To report a finding about a
server this tool scanned, contact that server's maintainers, not this project.

## Reporting a vulnerability
Report it privately through GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/kimmawla/mcp-supply-audit/security/advisories/new)
(the repository's **Security** tab, then **Report a vulnerability**).

Please do not open a public issue, pull request or discussion for a vulnerability.

Useful details:
- the version (`pip show mcp-supply-audit`, or the version the server reports on `initialize`)
- the tool and the input that triggers it, with secrets removed
- what happened and what you expected

Examples of what is in scope:
- a way to make a tool read a local file, run or install code, or send a request to a host
  outside its allowlist (registry.modelcontextprotocol.io, pypi.org, registry.npmjs.org,
  api.osv.dev)
- input text that reaches a report outside `untrusted_text`, or hidden characters that reach
  a report without being escaped
- a secret or credential value echoed in a report, error or log
- anything written to stdout other than the MCP protocol

A check that misses something, or a finding you think is wrong, is a detection limit, not a
vulnerability. Open a regular issue for it.

## Supported versions
Only the latest release gets security fixes. The project is pre-release.

## What to expect
This is a single-maintainer project with no guaranteed response time. Reports are handled
through the GitHub advisory, with the aim of releasing a fix before details are made public.
