from octirb.config import TextCfg
from octirb.text import article_text, plan_text_tier, title_similarity


def cfg(**kw):
    return TextCfg(**kw)


def test_tier_description_first():
    assert plan_text_tier(description_chars=5000, has_stored_file=True, cached=True,
                          cfg=cfg()) == "description"


def test_tier_stored_file_before_cache():
    assert plan_text_tier(description_chars=100, has_stored_file=True, cached=True,
                          cfg=cfg()) == "stored-file"


def test_tier_cache_before_fetch():
    assert plan_text_tier(description_chars=100, has_stored_file=False, cached=True,
                          cfg=cfg()) == "cache"


def test_tier_fetch_last():
    assert plan_text_tier(description_chars=100, has_stored_file=False, cached=False,
                          cfg=cfg()) == "fetch"


def test_tier_none_when_fetch_disabled():
    assert plan_text_tier(description_chars=100, has_stored_file=False, cached=False,
                          cfg=cfg(fetch_enabled=False)) == "none"


def test_title_similarity_identical():
    assert title_similarity("Attack on X", "# Attack on X\nbody") > 0.9


def test_article_text_strips_link_nav():
    nav = "\n".join(f"+ [story {i}](https://x/{i})" for i in range(30))
    body = "One long paragraph of prose. " * 40
    out = article_text(nav + "\n\n" + body + "\n\n" + nav)
    assert "story 3" not in out and "long paragraph" in out
