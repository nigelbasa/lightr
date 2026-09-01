"""DKIM key generation and signing.

The signature is verified with dkimpy's own verifier against the key
we generated, so these tests prove real interoperability rather than
just that a header was added.
"""

from __future__ import annotations

import pytest

from lightr.mail.dkim import (
    DEFAULT_KEY_BITS,
    DKIMError,
    DKIMKey,
    _has_header,
    generate_key,
    sign,
    sign_or_warn,
)

RAW = (
    b"From: ops@acme.test\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: Test message\r\n"
    b"Date: Tue, 01 Sep 2026 10:00:00 +0000\r\n"
    b"Message-ID: <abc@acme.test>\r\n"
    b"\r\n"
    b"Body text.\r\n"
)


@pytest.fixture(scope="module")
def key() -> DKIMKey:
    # 1024 keeps the suite fast; the code path is identical.
    return generate_key("s2026", bits=1024)


class TestKeyGeneration:
    def test_produces_a_pkcs8_private_key(self, key: DKIMKey) -> None:
        assert key.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")

    def test_public_key_is_base64(self, key: DKIMKey) -> None:
        import base64

        base64.b64decode(key.public_key_b64, validate=True)

    def test_default_is_2048_bits(self) -> None:
        assert DEFAULT_KEY_BITS == 2048

    @pytest.mark.parametrize("bits", [256, 512, 768])
    def test_weak_keys_are_refused(self, bits: int) -> None:
        with pytest.raises(DKIMError, match="too weak"):
            generate_key(bits=bits)

    def test_keys_are_unique(self) -> None:
        assert generate_key(bits=1024).public_key_b64 != (
            generate_key(bits=1024).public_key_b64
        )


class TestDNSRecord:
    def test_name_follows_the_selector_convention(self, key: DKIMKey) -> None:
        assert key.dns_name("acme.test") == "s2026._domainkey.acme.test"

    def test_value_declares_dkim1_and_rsa(self, key: DKIMKey) -> None:
        value = key.dns_value()
        assert value.startswith("v=DKIM1; k=rsa; p=")
        assert key.public_key_b64 in value

    def test_full_record_is_a_txt_record(self, key: DKIMKey) -> None:
        record = key.dns_record("acme.test")
        assert " IN TXT " in record
        assert record.startswith("s2026._domainkey.acme.test.")


class TestSigning:
    def test_signature_is_prepended(self, key: DKIMKey) -> None:
        signed = sign(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        assert signed.startswith(b"DKIM-Signature:")

    def test_body_is_unchanged(self, key: DKIMKey) -> None:
        signed = sign(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        assert signed.endswith(b"Body text.\r\n")

    def test_signature_actually_verifies(self, key: DKIMKey) -> None:
        """The test that matters: a real verifier accepts it."""
        import dkim as dkimpy

        signed = sign(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        assert dkimpy.verify(signed, dnsfunc=lambda name, **kw: key.dns_value())

    def test_tampered_body_fails_verification(self, key: DKIMKey) -> None:
        import dkim as dkimpy

        signed = sign(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        tampered = signed.replace(b"Body text.", b"Evil text.")

        assert not dkimpy.verify(tampered, dnsfunc=lambda name, **kw: key.dns_value())

    def test_tampered_subject_fails_verification(self, key: DKIMKey) -> None:
        """Subject is in the signed set precisely so this fails."""
        import dkim as dkimpy

        signed = sign(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        tampered = signed.replace(b"Subject: Test message", b"Subject: Pay me now")

        assert not dkimpy.verify(tampered, dnsfunc=lambda name, **kw: key.dns_value())

    def test_missing_key_raises(self) -> None:
        with pytest.raises(DKIMError, match="no DKIM private key"):
            sign(RAW, domain="acme.test", selector="s", private_key_pem="")

    def test_malformed_key_raises(self) -> None:
        with pytest.raises(DKIMError, match="could not sign"):
            sign(RAW, domain="acme.test", selector="s", private_key_pem="not a key")


class TestHeaderSelection:
    def test_only_present_headers_are_signed(self) -> None:
        """Signing an absent header makes verifiers reject the
        signature, so the list is filtered to what exists."""
        assert _has_header(RAW, b"Subject") is True
        assert _has_header(RAW, b"Reply-To") is False

    def test_header_matching_is_case_insensitive(self) -> None:
        assert _has_header(b"subject: x\r\n\r\nbody", b"Subject") is True

    def test_body_text_is_not_mistaken_for_a_header(self) -> None:
        raw = b"From: a@b.test\r\n\r\nSubject: this is body text\r\n"
        assert _has_header(raw, b"Subject") is False

    def test_message_without_a_message_id_still_signs(self, key: DKIMKey) -> None:
        import dkim as dkimpy

        raw = b"From: ops@acme.test\r\nSubject: No ID\r\n\r\nBody\r\n"
        signed = sign(
            raw, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        assert dkimpy.verify(signed, dnsfunc=lambda name, **kw: key.dns_value())


class TestSendingPathFallback:
    """An invalid signature is worse than none -- it turns a neutral
    verdict into a failure."""

    def test_missing_key_sends_unsigned(self) -> None:
        assert sign_or_warn(RAW, domain="x.test", selector="s", private_key_pem="") == RAW

    def test_broken_key_sends_unsigned(self) -> None:
        assert sign_or_warn(
            RAW, domain="x.test", selector="s", private_key_pem="garbage"
        ) == RAW

    def test_valid_key_still_signs(self, key: DKIMKey) -> None:
        signed = sign_or_warn(
            RAW, domain="acme.test", selector="s2026",
            private_key_pem=key.private_key_pem,
        )
        assert signed.startswith(b"DKIM-Signature:")

    def test_failure_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="lightr.dkim"):
            sign_or_warn(RAW, domain="x.test", selector="s", private_key_pem="")
        assert "unsigned" in caplog.text
