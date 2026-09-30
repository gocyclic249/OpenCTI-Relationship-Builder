import pytest

from octirb.config import Config, load_config, resolve_settings


def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.delenv("OCTI_RB_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert cfg.labels.prefix == "AI-"
    assert cfg.text.fetch_enabled is True
    assert cfg.text.max_fetch_per_run == 50
    assert cfg.sectors.canonical_authors == ("Filigran",)


def test_explicit_missing_file_errors(tmp_path):
    with pytest.raises(SystemExit, match="config"):
        load_config(tmp_path / "nope.toml")


def test_unknown_key_rejected(tmp_path):
    p = write(tmp_path, "[text]\nfecth_enabled = true\n")
    with pytest.raises(SystemExit, match="fecth_enabled"):
        load_config(p)


def test_wrong_type_rejected(tmp_path):
    p = write(tmp_path, '[selection]\nsince_days = "six months"\n')
    with pytest.raises(SystemExit, match="since_days"):
        load_config(p)


def test_invalid_regex_named(tmp_path):
    p = write(tmp_path, '[selection]\nexclude_title_patterns = ["[unclosed"]\n')
    with pytest.raises(SystemExit, match=r"\[unclosed"):
        load_config(p)


def test_bad_create_missing_type_rejected(tmp_path):
    p = write(tmp_path, '[actors]\ncreate_missing_type = "Malware"\n')
    with pytest.raises(SystemExit, match="create_missing_type"):
        load_config(p)


def test_negative_values_rejected(tmp_path):
    p = write(tmp_path, "[text]\nmax_fetch_per_run = -1\n")
    with pytest.raises(SystemExit, match="max_fetch_per_run"):
        load_config(p)


def test_warn_percent_range(tmp_path):
    p = write(tmp_path, "[disk]\nwarn_percent = 120\n")
    with pytest.raises(SystemExit, match="warn_percent"):
        load_config(p)


def test_label_helper():
    assert Config().label("Sector") == "AI-Sector"


def test_token_from_env(monkeypatch):
    monkeypatch.setenv("OPENCTI_TOKEN", "tok-1")
    s = resolve_settings(Config())
    assert s.token == "tok-1"
    assert s.graphql_url == "http://localhost:8080/graphql"


def test_token_from_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    monkeypatch.delenv("OPENCTI_ADMIN_TOKEN", raising=False)
    env = tmp_path / ".env"
    env.write_text('OPENCTI_ADMIN_TOKEN="tok-2"\n', encoding="utf-8")
    cfg = load_config(write(tmp_path, f'[platform]\nenv_file = "{env}"\n'))
    assert resolve_settings(cfg).token == "tok-2"


def test_no_token_errors(monkeypatch):
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    monkeypatch.delenv("OPENCTI_ADMIN_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="OPENCTI_TOKEN"):
        resolve_settings(Config())


def test_sector_aliases_table(tmp_path):
    p = write(tmp_path, '[sectors.aliases]\n"Energy & Utilities" = "Energy"\n')
    assert load_config(p).sectors.aliases["Energy & Utilities"] == "Energy"


def test_disk_warn(tmp_path, capsys, monkeypatch):
    import octirb.config as c

    cfg = load_config(write(tmp_path, "[disk]\nwarn_percent = 1\n"))
    monkeypatch.setattr(c.shutil, "disk_usage", lambda _p: (100, 99, 1))
    lines: list[str] = []
    c.check_disk(cfg, lines.append)
    assert any("threshold 1%" in ln for ln in lines)


def test_report_labels_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("OCTI_RB_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert cfg.report_labels.enabled is True
    assert cfg.report_labels.color == "#5b6abf"


def test_report_labels_parsed(tmp_path):
    p = write(tmp_path, '[report_labels]\nenabled = false\ncolor = "#AABBCC"\n')
    cfg = load_config(p)
    assert cfg.report_labels.enabled is False
    assert cfg.report_labels.color == "#AABBCC"


def test_report_labels_bad_color_rejected(tmp_path):
    p = write(tmp_path, '[report_labels]\ncolor = "blue"\n')
    with pytest.raises(SystemExit, match=r"\[report_labels\]\.color"):
        load_config(p)


def test_report_labels_unknown_key_rejected(tmp_path):
    p = write(tmp_path, "[report_labels]\nprefix = 'x'\n")
    with pytest.raises(SystemExit, match="prefix"):
        load_config(p)
