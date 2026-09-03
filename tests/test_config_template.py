"""The commented config file an install starts from.

It is hand-written text, which makes it a second representation of the
schema -- and ``Config`` forbids unknown keys, so a key here that the
model no longer has would stop a fresh install from loading its own
config file. These tests are what keeps the two from drifting.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from lightr import configtemplate
from lightr.config import Config


def _field_names(model: type) -> set[str]:
    """Every field name anywhere in the config model tree."""
    names: set[str] = set()
    pending = [model]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen or not hasattr(current, "model_fields"):
            continue
        seen.add(current)
        for name, field in current.model_fields.items():
            names.add(name)
            annotation = field.annotation
            for candidate in (annotation, *getattr(annotation, "__args__", ())):
                if hasattr(candidate, "model_fields"):
                    pending.append(candidate)
    return names


class TestItLoads:
    def test_the_template_is_a_valid_config(self) -> None:
        raw = yaml.safe_load(configtemplate.TEMPLATE)

        assert Config.model_validate(raw).database.driver == "sqlite"

    def test_every_commented_key_is_a_real_setting(self) -> None:
        """A comment that names a setting Lightr does not have is worse
        than no comment: someone uncomments it and the config stops
        loading."""
        known = _field_names(Config)
        commented = {
            match.group(1)
            for line in configtemplate.TEMPLATE.splitlines()
            if (match := re.match(r"#\s+([a-z_]+):", line))
        }

        assert commented
        assert commented <= known, sorted(commented - known)

    def test_the_shipped_example_matches_the_template(self) -> None:
        """One representation, two places it has to appear."""
        example = Path(__file__).resolve().parents[1] / "lightr.yaml.example"

        assert example.read_text(encoding="utf-8") == configtemplate.TEMPLATE


class TestWhatItLeavesOut:
    def test_no_generated_secret_appears_as_a_blank(self) -> None:
        """A hand-typed internal key that disagrees with Dovecot's copy
        fails as "wrong password" for every user, so the template must
        not invite one."""
        for secret in (
            "internal_key", "master_password", "master_user", "admin_key",
        ):
            assert f"{secret}:" not in configtemplate.TEMPLATE

    def test_the_hostname_is_present_and_flagged(self) -> None:
        """It is the one setting every install must change."""
        raw = yaml.safe_load(configtemplate.TEMPLATE)

        assert raw["server"]["hostname"] == "localhost"
        assert "Set this" in configtemplate.TEMPLATE


class TestWriting:
    def test_it_writes_when_there_is_nothing_there(self, tmp_path: Path) -> None:
        target = tmp_path / "etc" / "config.yaml"
        configtemplate.write(target)

        assert Config.load(target).database.driver == "sqlite"

    def test_it_never_replaces_an_existing_config(self, tmp_path: Path) -> None:
        """This runs on every package upgrade, and the file it would
        replace holds the keys the running install authenticates with."""
        target = tmp_path / "config.yaml"
        target.write_text("server:\n  hostname: mail.example.com\n", encoding="utf-8")

        configtemplate.write(target)

        assert "mail.example.com" in target.read_text(encoding="utf-8")

    def test_it_is_not_world_readable(self, tmp_path: Path) -> None:
        """It gains a database password and the Dovecot internal key."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        assert target.stat().st_mode & 0o007 == 0

    def test_the_service_group_can_read_it(self, tmp_path: Path) -> None:
        """The unit runs as User=lightr. 0600 would mean the service
        cannot read its own configuration -- and preflight would not
        catch it, because it only warns about world-readable files."""
        import os

        if os.name == "nt":  # pragma: no cover - POSIX only
            pytest.skip("POSIX permissions")

        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        assert target.stat().st_mode & 0o040


class TestWritingBackGeneratedSecrets:
    """Lightr writes a handful of secrets into the config it was given.

    It used to do that by dumping the whole model over the file, which
    threw away every comment -- and, on a live server, a hand-edited
    Postgres DSN with it.
    """

    def test_the_comments_survive(self, tmp_path: Path) -> None:
        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        configtemplate.set_values(target, {("dovecot", "internal_key"): "abc123"})

        text = target.read_text(encoding="utf-8")
        assert "Everything commented out below" in text
        assert Config.load(target).dovecot.internal_key == "abc123"

    def test_hand_edited_settings_survive(self, tmp_path: Path) -> None:
        target = tmp_path / "config.yaml"
        configtemplate.write(target)
        configtemplate.set_values(
            target, {("database", "dsn"): "postgresql://u:p@127.0.0.1/lightr"}
        )

        configtemplate.set_values(target, {("dovecot", "internal_key"): "abc123"})

        assert "postgresql://u:p@127.0.0.1/lightr" in target.read_text(encoding="utf-8")

    def test_a_second_run_changes_nothing(self, tmp_path: Path) -> None:
        """The package runs this on every upgrade."""
        target = tmp_path / "config.yaml"
        configtemplate.write(target)
        values: dict[tuple[str, str], object] = {("dovecot", "internal_key"): "abc123"}
        configtemplate.set_values(target, values)
        before = target.read_text(encoding="utf-8")

        changed = configtemplate.set_values(target, values)

        assert changed == []
        assert target.read_text(encoding="utf-8") == before

    def test_it_writes_into_an_existing_block_not_a_second_one(
        self, tmp_path: Path
    ) -> None:
        """PyYAML silently keeps the last of two `dovecot:` mappings,
        so appending a fresh block would delete whatever the operator
        had put in the first one."""
        target = tmp_path / "config.yaml"
        target.write_text(
            "dovecot:\n  imap_port: 10143\n", encoding="utf-8"
        )

        configtemplate.set_values(target, {("dovecot", "internal_key"): "abc123"})

        cfg = Config.load(target)
        assert cfg.dovecot.imap_port == 10143
        assert cfg.dovecot.internal_key == "abc123"

    def test_an_existing_setting_is_rewritten_in_place(self, tmp_path: Path) -> None:
        target = tmp_path / "config.yaml"
        target.write_text("server:\n  hostname: old\n", encoding="utf-8")

        configtemplate.set_values(target, {("server", "hostname"): "new"})

        text = target.read_text(encoding="utf-8")
        assert text.count("hostname:") == 1
        assert Config.load(target).server.hostname == "new"

    def test_a_commented_line_is_not_mistaken_for_the_setting(
        self, tmp_path: Path
    ) -> None:
        """The template is mostly commented-out defaults; writing over
        one would produce a setting nested under a comment."""
        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        configtemplate.set_values(target, {("logging", "level"): "debug"})

        assert Config.load(target).logging.level == "debug"
        assert "#   level: info" in target.read_text(encoding="utf-8")

    def test_a_top_level_scalar_can_be_set(self, tmp_path: Path) -> None:
        """`data_dir` is not inside a block."""
        target = tmp_path / "config.yaml"
        configtemplate.write(target)

        configtemplate.set_values(target, {("data_dir", ""): "/srv/lightr"})

        assert Config.load(target).data_dir == Path("/srv/lightr")


class TestThereIsOnlyOneLocation:
    def test_the_default_path_ignores_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LIGHTR_CONFIG is gone. It made the answer to "which file is
        this install reading" depend on how the process was started."""
        monkeypatch.setenv("LIGHTR_CONFIG", "/tmp/somewhere-else.yaml")

        assert Config.default_path() == Path("/etc/lightr/config.yaml")
