"""Strip site chrome from connector-fetched article markdown, plus the tier
planner that decides where a relationship's text comes from.

The cleaning functions below (`normalise`, `article_text`, `description_text`,
`title_similarity`) are ported verbatim from opencti-docker/octigeo/clean.py.
This is a correctness requirement, not an optimisation. The markdown the
ImportExternalReference connector produces is mostly navigation: a 26KB
Bleeping Computer capture carries ~4-6KB of article and fills the rest with
headline lists for *other* stories. Extracting geography from that raw would
read the sidebar instead of the article.

The approach is readability-style but adapted to markdown: score each line by
how much of it is link furniture, then keep the densest contiguous block of
genuine prose.
"""

from __future__ import annotations

import re

from .config import TextCfg

IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
DATA_URI_RE = re.compile(r"data:[a-z/+.-]+;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)
BULLET_RE = re.compile(r"^\s*([*+\-]|\d+\.)\s")
HEADING_RE = re.compile(r"^\s*#{1,6}\s")

# Lines matching these are furniture regardless of length.
CHROME_RE = re.compile(
    r"^\s*(share|tweet|follow us|subscribe|sign in|log in|advertisement|"
    r"related articles?|popular stories|latest news|read more|cookie|"
    r"privacy policy|terms of (use|service)|all rights reserved|"
    r"copyright\b|home\s*»|\d+\s*comments?)\b",
    re.IGNORECASE,
)

# Cookie-consent inventories are the worst case for a density-based scorer:
# they are long, link-free running prose, so they outscore the actual article.
# Securelist's banner reduced all six of its captures to tracker listings
# before this existed. Any line naming these is consent furniture, never body.
COOKIE_RE = re.compile(
    r"(maximum storage duration|html local storage|http cookie|pixel tracker|"
    r"indexeddb|learn more about this provider|registers (data|statistical data) on|"
    r"cookies? (are|is) used to|this cookie is used|consent (id|manager)|"
    r"used to track visitors|advertisement (products|networks)|"
    r"necessary for the implementation and functionality)",
    re.IGNORECASE,
)

# Publisher-specific widgets that survive the density test because they are
# link-free running text. Matched anywhere in the line, not just at the start.
WIDGET_RE = re.compile(
    r"(continue watching\s*after the ad|visit advertiser website|go to page|"
    r"your browser does not support|enable javascript|"
    r"sign up for (our|the) newsletter)",
    re.IGNORECASE,
)

MIN_PROSE_CHARS = 60
# Title tokens shorter than this are noise ("the", "v6", "AI").
MIN_TITLE_TOKEN_LEN = 2
MAX_LINK_DENSITY = 0.4
# Number of consecutive non-prose lines tolerated inside one article block.
GAP_TOLERANCE = 8


DANGLING_LINK_RE = re.compile(r"^[^\[]*\]\(\s*\S+\s*\)")


def normalise(markdown: str) -> str:
    """Rejoin markdown links that the publisher split across lines.

    Bleeping Computer emits navigation as::

        + [
        Cisco warns of max severity ISE zero-day exploited in attacks](https://…)

    The opening bracket sits on its own line, so a single-line link regex sees
    no link at all and scores the headline as clean prose. Six of fifteen
    captures were reduced to pure navigation by exactly this. Joining a line
    that ends in "[" to the one after it restores the link so density scoring
    can see it.
    """
    out: list[str] = []
    for line in markdown.splitlines():
        if out and out[-1].rstrip().endswith("["):
            out[-1] = out[-1].rstrip() + line.lstrip()
        else:
            out.append(line)
    return "\n".join(out)


def _link_density(line: str) -> float:
    if not line.strip():
        return 0.0
    link_chars = sum(len(m.group(0)) for m in LINK_RE.finditer(line))
    return link_chars / max(len(line), 1)


def _is_furniture(stripped: str) -> bool:
    """Site chrome, publisher widgets and cookie inventories -- never body."""
    return bool(
        CHROME_RE.match(stripped) or WIDGET_RE.search(stripped) or COOKIE_RE.search(stripped)
    )


def _is_link_structure(line: str, stripped: str) -> bool:
    """Navigation and headline teasers, judged by how much is link furniture."""
    if BULLET_RE.match(line) or HEADING_RE.match(line):
        return True
    if _link_density(line) > MAX_LINK_DENSITY:
        return True
    if DANGLING_LINK_RE.match(stripped):
        return True
    # A line that is one big link and nothing else is a headline teaser.
    return len(LINK_RE.sub("", line).strip()) < MIN_PROSE_CHARS // 2


def _is_prose(line: str) -> bool:
    stripped = line.strip()
    if len(stripped) < MIN_PROSE_CHARS:
        return False
    return not (_is_furniture(stripped) or _is_link_structure(line, stripped))


def _strip_inline(line: str) -> str:
    """Flatten markdown links to their text and drop images."""
    line = IMAGE_RE.sub("", line)
    line = DATA_URI_RE.sub("", line)
    line = LINK_RE.sub(lambda m: m.group(1), line)
    return re.sub(r"\s+", " ", line).strip()


def article_text(markdown: str, max_chars: int = 20000) -> str:
    """Return the article body, with navigation and teaser blocks removed."""
    lines = normalise(markdown).splitlines()
    prose_idx = [i for i, line in enumerate(lines) if _is_prose(line)]
    if not prose_idx:
        # Nothing looked like an article; fall back to flattened text so the
        # caller still gets something reviewable rather than an empty string.
        return _truncate(_strip_inline(" ".join(lines)), max_chars)

    blocks: list[list[int]] = [[prose_idx[0]]]
    for idx in prose_idx[1:]:
        if idx - blocks[-1][-1] <= GAP_TOLERANCE:
            blocks[-1].append(idx)
        else:
            blocks.append([idx])

    def score(block: list[int]) -> int:
        return sum(len(lines[i].strip()) for i in block)

    best = max(blocks, key=score)
    out = [_strip_inline(lines[i]) for i in range(best[0], best[-1] + 1)]
    return _truncate("\n".join(p for p in out if p), max_chars)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + " […truncated]"


def description_text(description: str, max_chars: int = 20000) -> str:
    """Clean a report description that already carries the article body."""
    lines = [_strip_inline(line) for line in (description or "").splitlines()]
    return _truncate("\n".join(line for line in lines if line), max_chars)


_WORD_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    ["a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is", "it", "its", "of", "on", "or", "that", "the", "to", "was", "were", "will", "with", "new", "now", "how", "what", "which", "who", "why", "when"]
)


def _title_tokens(text: str) -> set[str]:
    return {w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS and len(w) > MIN_TITLE_TOKEN_LEN}


def title_similarity(report_title: str, markdown: str) -> float:
    """How well a fetched capture's own title matches the report it belongs to.

    The connector resolves a URL, and a publisher can serve something else --
    one Bleeping Computer capture for an Entra ID passkeys URL came back as an
    Excel copy-and-paste story. Attaching that article's geography to this
    report would be silently wrong, so captures that do not match are held back
    rather than extracted from.
    """
    page_title = next((ln for ln in markdown.splitlines() if ln.strip()), "")
    a, b = _title_tokens(report_title), _title_tokens(page_title)
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


# -- tier planner ------------------------------------------------------------

# The only values plan_text_tier() may return, checked in this exact order.
TEXT_TIERS: tuple[str, ...] = ("description", "stored-file", "cache", "fetch", "none")


def plan_text_tier(
    *, description_chars: int, has_stored_file: bool, cached: bool, cfg: TextCfg
) -> str:
    """Decide where a relationship's text should come from.

    Strict priority order: a report description that is already long enough
    beats a stored file, which beats a cached fetch, which beats a fresh
    fetch -- and fetching only happens at all when `cfg.fetch_enabled`. This
    mirrors the cost of each source: description text is free (already on
    the report), a stored file is a disk read, cache is a disk read plus a
    freshness check, and fetch is a network call subject to
    `max_fetch_per_run`.
    """
    if description_chars < 0:
        raise ValueError("plan_text_tier: description_chars must be >= 0")
    if description_chars >= cfg.fulltext_min_chars:
        tier = "description"
    elif has_stored_file:
        tier = "stored-file"
    elif cached:
        tier = "cache"
    elif cfg.fetch_enabled:
        tier = "fetch"
    else:
        tier = "none"
    if tier not in TEXT_TIERS:
        raise ValueError(f"plan_text_tier: produced an invalid tier {tier!r}")
    return tier
