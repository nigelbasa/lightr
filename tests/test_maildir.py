"""Maildir layout and path safety."""

from __future__ import annotations

from pathlib import Path

import pytest

from lightr.dovecot.maildir import (
    DEFAULT_FOLDERS,
    MaildirError,
    MaildirLayout,
    layout_for,
)


class TestLayoutPaths:
    def test_domain_first_layout(self, tmp_path: Path) -> None:
        """Domain-first so a whole domain moves or backs up as one dir."""
        layout = layout_for(tmp_path, "ops@acme.test")
        assert layout.root == tmp_path / "acme.test" / "ops"

    def test_addresses_are_lowercased(self, tmp_path: Path) -> None:
        assert layout_for(tmp_path, "OPS@ACME.test").root == (
            tmp_path / "acme.test" / "ops"
        )

    def test_same_local_part_on_two_domains_does_not_collide(
        self, tmp_path: Path
    ) -> None:
        a = layout_for(tmp_path, "info@one.test")
        b = layout_for(tmp_path, "info@two.test")
        assert a.root != b.root

    def test_non_address_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(MaildirError, match="not an email address"):
            layout_for(tmp_path, "just-a-local-part")

    @pytest.mark.parametrize(
        "evil",
        [
            "../../etc/passwd@acme.test",
            "ops@../../../etc",
            "ops/../root@acme.test",
        ],
    )
    def test_traversal_attempts_are_rejected(self, tmp_path: Path, evil: str) -> None:
        with pytest.raises(MaildirError, match="unsafe"):
            layout_for(tmp_path, evil)


class TestFolders:
    def test_inbox_is_the_root(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path)
        assert layout.folder("INBOX") == tmp_path
        assert layout.folder("inbox") == tmp_path

    def test_named_folder_is_dot_prefixed(self, tmp_path: Path) -> None:
        assert MaildirLayout(tmp_path).folder("Sent") == tmp_path / ".Sent"

    def test_nested_folders_use_maildirpp_dots(self, tmp_path: Path) -> None:
        """Dovecot's Maildir++ maps a hierarchy onto dot separators."""
        assert MaildirLayout(tmp_path).folder("Work/Clients") == tmp_path / ".Work.Clients"

    def test_empty_folder_name_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(MaildirError, match="cannot be empty"):
            MaildirLayout(tmp_path).folder("")

    def test_traversal_in_a_folder_name_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(MaildirError, match="unsafe"):
            MaildirLayout(tmp_path).folder("../escape")


class TestProvisioning:
    def test_create_makes_the_cur_new_tmp_triplet(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()

        for sub in ("cur", "new", "tmp"):
            assert (layout.root / sub).is_dir()
        assert layout.exists()

    def test_create_makes_the_default_folders(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()

        for name in DEFAULT_FOLDERS:
            assert (layout.folder(name) / "cur").is_dir()

    def test_default_folders_are_subscribed(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()

        subscribed = (layout.root / "subscriptions").read_text(encoding="utf-8").split()
        assert set(DEFAULT_FOLDERS) == set(subscribed)

    def test_create_is_idempotent(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()
        layout.create()
        assert layout.exists()

    def test_create_does_not_clobber_subscriptions(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()
        (layout.root / "subscriptions").write_text("Custom\n", encoding="utf-8")

        layout.create()

        assert (layout.root / "subscriptions").read_text(encoding="utf-8") == "Custom\n"

    def test_exists_is_false_before_creation(self, tmp_path: Path) -> None:
        assert MaildirLayout(tmp_path / "nothing").exists() is False


class TestCounting:
    def test_counts_cur_and_new(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()
        (layout.root / "new" / "1234.msg").write_text("a", encoding="utf-8")
        (layout.root / "cur" / "5678.msg:2,S").write_text("b", encoding="utf-8")
        (layout.root / "tmp" / "half-written").write_text("c", encoding="utf-8")

        # tmp holds partial deliveries and must not be counted.
        assert layout.message_count() == 2

    def test_counts_a_named_folder(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()
        (layout.folder("Sent") / "cur" / "1.msg").write_text("x", encoding="utf-8")

        assert layout.message_count("Sent") == 1
        assert layout.message_count("INBOX") == 0

    def test_missing_folder_counts_zero(self, tmp_path: Path) -> None:
        layout = MaildirLayout(tmp_path / "box")
        layout.create()
        assert layout.message_count("Nonexistent") == 0
