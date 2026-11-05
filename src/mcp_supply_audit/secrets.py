"""Detectors for well-known credential formats, by documented prefix.

Each prefix comes from the provider's own documentation, fetched 2026-11-02 and cited per
detector. None of these pages documents a token length or alphabet (GitHub only notes that
older installation tokens were 40 characters), so the minimum body length after each prefix is
ours, chosen to keep short words and identifiers from matching. Hits report where a secret is
and what kind it is, never the value. Shared by the RG rules and, later, scan_mcp_config.

Fixtures must never contain token-shaped literals: build them by concatenation in test code
(tests/test_secrets.py scans src/ and tests/ with these patterns).
"""

import re
from dataclasses import dataclass
from typing import Final

# A token starts where no token character precedes it.
_START: Final = r"(?<![A-Za-z0-9_.\-])"
_END: Final = r"(?![A-Za-z0-9_.\-])"


@dataclass(frozen=True)
class SecretFormat:
    kind: str  # shown in findings, e.g. "GitHub token"
    doc_url: str
    pattern: re.Pattern[str]


def _fmt(kind: str, doc_url: str, prefixes: tuple[str, ...], body: str) -> SecretFormat:
    alternatives = "|".join(re.escape(p) for p in prefixes)
    return SecretFormat(
        kind, doc_url, re.compile(f"{_START}(?:{alternatives}){body}{_END}")
    )


SECRET_FORMATS: Final[tuple[SecretFormat, ...]] = (
    # GitHub, "GitHub's token formats": ghp_ (classic PAT), github_pat_ (fine-grained PAT),
    # gho_ (OAuth), ghu_ (GitHub App user), ghs_ (installation; may be ghs_APPID_JWT, so "."
    # and "-" are allowed in the body), ghr_ (refresh).
    _fmt(
        "GitHub token",
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        r"[A-Za-z0-9_.\-]{20,}",
    ),
    # GitLab, "Token prefixes" table. Session cookies (_gitlab_session=) are not a token
    # value and are left out.
    _fmt(
        "GitLab token",
        "https://docs.gitlab.com/security/tokens/",
        (
            "glpat-",
            "gloas-",
            "gldt-",
            "glrtr-",
            "glrt-",
            "glcbt-",
            "glptt-",
            "glft-",
            "glimt-",
            "glagent-",
            "glwt-",
            "glsoat-",
            "glffct-",
        ),
        r"[A-Za-z0-9_.\-]{16,}",
    ),
    # Slack, token types: xoxb- (bot), xoxp- (user), xapp- (app-level), xoxe.xapp-
    # (rotating app-level), xwfp- (workflow).
    _fmt(
        "Slack token",
        "https://docs.slack.dev/authentication/tokens",
        ("xoxe.xapp-", "xoxb-", "xoxp-", "xapp-", "xwfp-"),
        r"[A-Za-z0-9\-]{10,}",
    ),
    # Stripe, "API keys": secret sk_, restricted rk_ (live and test), organization sk_org_.
    # Publishable keys (pk_) are documented as safe to expose and are not flagged.
    _fmt(
        "Stripe secret key",
        "https://docs.stripe.com/keys",
        ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "sk_org_"),
        r"[A-Za-z0-9_]{10,}",
    ),
    # AWS IAM, "Understanding unique ID prefixes": AKIA (access key), ASIA (temporary STS
    # access key id), ABIA (STS service bearer token), ACCA (context-specific credential).
    # The documented examples are upper-case letters and digits.
    _fmt(
        "AWS access key id",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
        ("AKIA", "ASIA", "ABIA", "ACCA"),
        r"[A-Z0-9]{12,}",
    ),
)
# Not covered: npm documents tokens only as "a hexadecimal string" with no prefix
# (https://docs.npmjs.com/about-access-tokens), and no current PyPI page states a token
# prefix (https://docs.pypi.org/ checked 2026-11-02).


@dataclass(frozen=True)
class SecretHit:
    kind: str
    start: int
    end: int


def find_secrets(text: str) -> list[SecretHit]:
    """Every span of text shaped like a documented credential, without the value."""
    hits = [
        SecretHit(fmt.kind, m.start(), m.end())
        for fmt in SECRET_FORMATS
        for m in fmt.pattern.finditer(text)
    ]
    return sorted(hits, key=lambda h: h.start)


REDACTED: Final = "<redacted>"


def scrub(text: str, offset: int = 0) -> tuple[str, int]:
    """Replace secret-shaped spans with <redacted>; map offset into the scrubbed text."""
    out: list[str] = []
    last = 0
    new_offset = offset
    for hit in find_secrets(text):
        if hit.start < last:
            continue  # overlapping match
        out.append(text[last : hit.start])
        out.append(REDACTED)
        if hit.end <= offset:
            new_offset -= (hit.end - hit.start) - len(REDACTED)
        elif hit.start < offset:
            new_offset = len("".join(out)) - len(REDACTED)
        last = hit.end
    out.append(text[last:])
    return "".join(out), max(new_offset, 0)
