"""Config loading, normalisation, and round-tripping."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from lightr.config import Config, DatabaseDriver


def test_defaults_match_the_go_engine() -> None:
    cfg = Config()
    assert cfg.server.hostname == "localhost"
    assert cfg.smtp.addr == ":25"
    assert cfg.smtp.submission_addr == ":587"
    assert cfg.smtp.max_message_bytes == 25 * 1024 * 1024
    assert cfg.smtp.max_recipients == 50
    assert cfg.smtp.allow_insecure is False
    assert cfg.http.addr == ":8080"
    assert cfg.dkim.selector == "default"
    assert cfg.dkim.key_bits == 2048
    assert cfg.spam.enabled is True
    assert cfg.spam.suspicious_threshold == 2.0
    assert cfg.spam.junk_threshold == 4.0
    assert cfg.security.require_tls_for_auth is True


def test_paths_derive_from_data_dir(tmp_path: Path) -> None:
    cfg = Config(data_dir=tmp_path)
    assert cfg.database.path == tmp_path / "lightr.db"
    assert cfg.tls.cert_file == tmp_path / "tls" / "server.crt"
    assert cfg.tls.key_file == tmp_path / "tls" / "server.key"


def test_explicit_paths_are_not_overridden(tmp_path: Path) -> None:
    cfg = Config.model_validate(
        {
            "data_dir": str(tmp_path),
            "database": {"driver": "sqlite", "path": "/srv/custom.db"},
            "tls": {"cert_file": "/etc/ssl/mine.crt", "key_file": "/etc/ssl/mine.key"},
        }
    )
    assert cfg.database.path == Path("/srv/custom.db")
    assert cfg.tls.cert_file == Path("/etc/ssl/mine.crt")


class TestDatabaseURL:
    def test_sqlite_uses_data_dir(self, tmp_path: Path) -> None:
        cfg = Config(data_dir=tmp_path)
        assert cfg.database_url.startswith("sqlite+aiosqlite:///")
        assert "lightr.db" in cfg.database_url

    @pytest.mark.parametrize("prefix", ["postgresql://", "postgres://"])
    def test_libpq_dsn_is_normalised_onto_asyncpg(self, prefix: str) -> None:
        cfg = Config.model_validate(
            {"database": {"driver": "postgres", "dsn": f"{prefix}u:p@host:5432/lightr"}}
        )
        assert cfg.database_url == "postgresql+asyncpg://u:p@host:5432/lightr"

    def test_postgres_without_dsn_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="dsn is required"):
            Config.model_validate({"database": {"driver": "postgres"}})


class TestValidation:
    def test_unknown_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Config.model_validate({"nonsense": True})

    @pytest.mark.parametrize(
        ("block", "field", "value"),
        [
            ("smtp", "max_recipients", 0),
            ("smtp", "max_message_bytes", 10),
        ],
    )
    def test_out_of_range_values_are_rejected(self, block: str, field: str, value: int) -> None:
        with pytest.raises(ValidationError):
            Config.model_validate({block: {field: value}})


class TestGoCompatibility:
    """An existing Go config file must load unchanged."""

    GO_CONFIG = """
data_dir: /var/lib/lightr
server:
  hostname: mail.acme.test
  bind_address: 0.0.0.0
database:
  driver: sqlite
  path: /var/lib/lightr/lightr.db
http:
  addr: ":8080"
smtp:
  addr: ":25"
  submission_addr: ":587"
  max_message_bytes: 26214400
  max_recipients: 50
  allow_insecure: false
imap:
  addr: ":143"
  tls_addr: ":993"
  allow_insecure: false
dkim:
  selector: default
  key_bits: 2048
api:
  key: sekret
  admin_key: adminsekret
logging:
  level: info
spam:
  enabled: true
  suspicious_threshold: 2.0
  junk_threshold: 4.0
security:
  require_tls_for_auth: true
"""

    def test_retired_imap_block_is_dropped_not_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(self.GO_CONFIG, encoding="utf-8")

        cfg = Config.load(path)

        assert cfg.server.hostname == "mail.acme.test"
        assert cfg.api.admin_key == "adminsekret"
        assert not hasattr(cfg, "imap")

    def test_dovecot_defaults_replace_the_imap_block(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(self.GO_CONFIG, encoding="utf-8")

        cfg = Config.load(path)

        assert cfg.dovecot.imap_port == 143
        assert cfg.dovecot.maildir_root == Path("/var/mail/lightr")
        assert cfg.dovecot.uses_lmtp_socket is True


class TestRoundTrip:
    def test_missing_file_yields_defaults(self, tmp_path: Path) -> None:
        cfg = Config.load(tmp_path / "does-not-exist.yaml")
        assert cfg.server.hostname == "localhost"

    def test_save_then_load_is_stable(self, tmp_path: Path) -> None:
        original = Config.model_validate(
            {
                "data_dir": str(tmp_path),
                "server": {"hostname": "mail.acme.test"},
                "spam": {"dnsbl_zones": ["zen.spamhaus.org"]},
            }
        )
        path = tmp_path / "config.yaml"
        original.save(path)

        assert Config.load(path) == original

    def test_saved_yaml_has_no_python_tags(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        Config(data_dir=tmp_path).save(path)

        text = path.read_text(encoding="utf-8")
        assert "!!python" not in text
        assert isinstance(yaml.safe_load(text), dict)

    def test_non_mapping_yaml_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")

        with pytest.raises(ValueError, match="mapping"):
            Config.load(path)


def test_driver_enum_accepts_yaml_strings() -> None:
    cfg = Config.model_validate({"database": {"driver": "sqlite"}})
    assert cfg.database.driver is DatabaseDriver.SQLITE


class TestPathSerialisation:
    """Lightr runs on Linux; a config must never carry Windows paths."""

    def test_paths_are_written_posix_style(self) -> None:
        text = Config().to_yaml()
        assert "\\" not in text
        assert "/var/lib/lightr" in text

    def test_a_windows_style_path_round_trips_as_posix(self, tmp_path: Path) -> None:
        cfg = Config(data_dir=tmp_path)
        path = tmp_path / "config.yaml"
        cfg.save(path)

        assert "\\" not in path.read_text(encoding="utf-8")

    def test_the_saved_config_still_loads(self, tmp_path: Path) -> None:
        original = Config(data_dir=tmp_path)
        path = tmp_path / "config.yaml"
        original.save(path)

        assert Config.load(path).data_dir == original.data_dir


class TestExplicitNulls:
    """An explicit null must survive a save/load cycle.

    `lmtp_socket: null` is how an operator says 'use TCP, not a unix
    socket'. Excluding nulls on save made that setting silently revert
    to the default the next time anything wrote the config -- which
    `lightr setup` does.
    """

    def test_a_null_survives_a_round_trip(self, tmp_path: Path) -> None:
        cfg = Config.model_validate(
            {"data_dir": str(tmp_path), "dovecot": {"lmtp_socket": None}}
        )
        path = tmp_path / "config.yaml"
        cfg.save(path)

        reloaded = Config.load(path)
        assert reloaded.dovecot.lmtp_socket is None
        assert reloaded.dovecot.uses_lmtp_socket is False

    def test_the_null_is_written_not_omitted(self, tmp_path: Path) -> None:
        cfg = Config.model_validate(
            {"data_dir": str(tmp_path), "dovecot": {"lmtp_socket": None}}
        )
        path = tmp_path / "config.yaml"
        cfg.save(path)

        assert "lmtp_socket" in path.read_text(encoding="utf-8")

    def test_two_saves_do_not_drift(self, tmp_path: Path) -> None:
        """Saving a loaded config must produce the same config."""
        first = Config.model_validate(
            {"data_dir": str(tmp_path), "dovecot": {"lmtp_socket": None}}
        )
        path = tmp_path / "config.yaml"
        first.save(path)

        second = Config.load(path)
        second.save(path)

        assert Config.load(path) == second
        assert Config.load(path).dovecot.lmtp_socket is None
