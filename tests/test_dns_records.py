"""The DNS contract: what to publish, and checking what is published."""

from __future__ import annotations

import pytest

from lightr.mail.dns_records import (
    DEFAULT_DMARC,
    CheckResult,
    CheckState,
    Record,
    RecordKind,
    Verification,
    _matches,
    records_for,
)

PUBLIC_KEY = "MIIBIjANBgkqABC"


class TestGeneratedRecords:
    def test_mx_spf_and_dmarc_are_always_present(self) -> None:
        kinds = {r.kind for r in records_for("acme.test", mail_hostname="mail.acme.test")}
        assert {RecordKind.MX, RecordKind.SPF, RecordKind.DMARC} <= kinds

    def test_dkim_appears_only_with_a_key(self) -> None:
        without = records_for("acme.test", mail_hostname="mail.acme.test")
        with_key = records_for(
            "acme.test", mail_hostname="mail.acme.test", dkim_public_key=PUBLIC_KEY
        )

        assert RecordKind.DKIM not in {r.kind for r in without}
        assert RecordKind.DKIM in {r.kind for r in with_key}

    def test_mx_points_at_the_mail_host(self) -> None:
        mx = next(
            r for r in records_for("acme.test", mail_hostname="mail.acme.test")
            if r.kind is RecordKind.MX
        )
        assert mx.value == "mail.acme.test."
        assert mx.priority == 10

    def test_spf_includes_the_mail_host(self) -> None:
        spf = next(
            r for r in records_for("acme.test", mail_hostname="mail.acme.test")
            if r.kind is RecordKind.SPF
        )
        assert "a:mail.acme.test" in spf.value
        assert spf.value.startswith("v=spf1")

    def test_dmarc_is_at_the_underscore_name(self) -> None:
        dmarc = next(
            r for r in records_for("acme.test", mail_hostname="mail.acme.test")
            if r.kind is RecordKind.DMARC
        )
        assert dmarc.name == "_dmarc.acme.test"

    def test_default_dmarc_quarantines_rather_than_rejects(self) -> None:
        """A new domain with slightly wrong SPF should have mail filed
        in Junk, not destroyed."""
        assert "p=quarantine" in DEFAULT_DMARC

    def test_dkim_uses_the_selector(self) -> None:
        dkim = next(
            r
            for r in records_for(
                "acme.test",
                mail_hostname="mail.acme.test",
                dkim_selector="s2026",
                dkim_public_key=PUBLIC_KEY,
            )
            if r.kind is RecordKind.DKIM
        )
        assert dkim.name == "s2026._domainkey.acme.test"

    def test_the_domain_is_its_own_mail_host_by_default(self) -> None:
        mx = next(
            r for r in records_for("acme.test", mail_hostname="")
            if r.kind is RecordKind.MX
        )
        assert mx.value == "acme.test."


class TestZoneFormatting:
    def test_txt_values_are_quoted(self) -> None:
        record = Record(RecordKind.SPF, "acme.test", "TXT", "v=spf1 ~all")
        assert record.as_zone_line() == 'acme.test. IN TXT "v=spf1 ~all"'

    def test_mx_carries_its_priority(self) -> None:
        record = Record(RecordKind.MX, "acme.test", "MX", "mail.acme.test.", priority=10)
        assert record.as_zone_line() == "acme.test. IN MX 10 mail.acme.test."


class TestMatching:
    """Matching is lenient on purpose: an operator may have a stricter
    SPF than we suggest, or several MX hosts."""

    def test_mx_matches_among_several(self) -> None:
        record = Record(RecordKind.MX, "acme.test", "MX", "mail.acme.test.")
        assert _matches(record, ["20 backup.acme.test", "10 mail.acme.test"])

    def test_mx_missing_from_the_list_fails(self) -> None:
        record = Record(RecordKind.MX, "acme.test", "MX", "mail.acme.test.")
        assert not _matches(record, ["10 elsewhere.test"])

    def test_a_stricter_spf_is_accepted(self) -> None:
        record = Record(RecordKind.SPF, "acme.test", "TXT", "v=spf1 mx ~all")
        assert _matches(record, ["v=spf1 ip4:203.0.113.0/24 -all"])

    def test_a_non_spf_txt_record_does_not_satisfy_spf(self) -> None:
        record = Record(RecordKind.SPF, "acme.test", "TXT", "v=spf1 mx ~all")
        assert not _matches(record, ["google-site-verification=abc"])

    def test_dkim_matches_on_the_key_material(self) -> None:
        record = Record(
            RecordKind.DKIM, "d._domainkey.acme.test", "TXT",
            f"v=DKIM1; k=rsa; p={PUBLIC_KEY}",
        )
        assert _matches(record, [f"v=DKIM1; k=rsa; p={PUBLIC_KEY}"])

    def test_a_different_dkim_key_fails(self) -> None:
        record = Record(
            RecordKind.DKIM, "d._domainkey.acme.test", "TXT",
            f"v=DKIM1; k=rsa; p={PUBLIC_KEY}",
        )
        assert not _matches(record, ["v=DKIM1; k=rsa; p=SOMETHINGELSE"])

    def test_dmarc_matches_any_valid_policy(self) -> None:
        record = Record(RecordKind.DMARC, "_dmarc.acme.test", "TXT", DEFAULT_DMARC)
        assert _matches(record, ["v=DMARC1; p=reject"])


class TestVerificationOutcome:
    def _result(self, kind: RecordKind, state: CheckState) -> CheckResult:
        return CheckResult(kind, state)

    def test_all_required_records_present_is_verified(self) -> None:
        verification = Verification(
            "acme.test",
            [
                self._result(k, CheckState.OK)
                for k in (RecordKind.MX, RecordKind.SPF, RecordKind.DKIM, RecordKind.DMARC)
            ],
        )
        assert verification.verified

    @pytest.mark.parametrize(
        "kind",
        [RecordKind.MX, RecordKind.SPF, RecordKind.DKIM, RecordKind.DMARC],
    )
    def test_any_missing_required_record_fails(self, kind: RecordKind) -> None:
        checks = [
            self._result(k, CheckState.OK if k is not kind else CheckState.MISSING)
            for k in (RecordKind.MX, RecordKind.SPF, RecordKind.DKIM, RecordKind.DMARC)
        ]
        assert not Verification("acme.test", checks).verified

    def test_ptr_is_guidance_and_does_not_block(self) -> None:
        """PTR is set by whoever owns the IP -- usually the hosting
        provider -- so requiring it would block correct domains."""
        checks = [
            self._result(k, CheckState.OK)
            for k in (RecordKind.MX, RecordKind.SPF, RecordKind.DKIM, RecordKind.DMARC)
        ]
        checks.append(self._result(RecordKind.PTR, CheckState.MISSING))

        assert Verification("acme.test", checks).verified

    def test_a_lookup_error_is_not_a_pass(self) -> None:
        """Treating 'could not check' as success would mark a domain
        verified during a DNS outage."""
        checks = [
            self._result(k, CheckState.OK)
            for k in (RecordKind.MX, RecordKind.SPF, RecordKind.DKIM)
        ]
        checks.append(self._result(RecordKind.DMARC, CheckState.ERROR))

        assert not Verification("acme.test", checks).verified

    def test_failures_are_listed(self) -> None:
        verification = Verification(
            "acme.test",
            [
                self._result(RecordKind.MX, CheckState.OK),
                self._result(RecordKind.SPF, CheckState.MISSING),
                self._result(RecordKind.DKIM, CheckState.MISMATCH),
            ],
        )
        assert {f.kind for f in verification.failures} == {
            RecordKind.SPF,
            RecordKind.DKIM,
        }


class TestClientDiscoveryRecords:
    """Autoconfig, autodiscover and the SRV pair.

    They let a mail app configure itself from an address alone. Mail is
    delivered without them, which is exactly why they must not be able
    to hold a domain back from verifying -- a domain whose mail works
    is verified.
    """

    def test_they_are_absent_by_default(self) -> None:
        kinds = {r.kind for r in records_for("acme.test", mail_hostname="mail.acme.test")}

        assert RecordKind.AUTOCONFIG not in kinds
        assert RecordKind.SRV_IMAP not in kinds

    def test_include_optional_adds_all_four(self) -> None:
        kinds = {
            r.kind
            for r in records_for(
                "acme.test", mail_hostname="mail.acme.test", include_optional=True
            )
        }

        assert {
            RecordKind.AUTOCONFIG,
            RecordKind.AUTODISCOVER,
            RecordKind.SRV_IMAP,
            RecordKind.SRV_SUBMISSION,
        } <= kinds

    def test_the_required_records_are_unchanged_by_the_flag(self) -> None:
        plain = records_for("acme.test", mail_hostname="mail.acme.test")
        extended = records_for(
            "acme.test", mail_hostname="mail.acme.test", include_optional=True
        )

        assert extended[: len(plain)] == plain

    def _record(self, kind: RecordKind):
        return next(
            r
            for r in records_for(
                "acme.test", mail_hostname="mail.acme.test", include_optional=True
            )
            if r.kind is kind
        )

    def test_autoconfig_is_a_cname_at_the_name_thunderbird_fetches(self) -> None:
        record = self._record(RecordKind.AUTOCONFIG)

        assert record.name == "autoconfig.acme.test"
        assert record.type == "CNAME"
        assert record.value == "mail.acme.test."

    def test_autodiscover_is_the_name_outlook_fetches(self) -> None:
        assert self._record(RecordKind.AUTODISCOVER).name == "autodiscover.acme.test"

    def test_the_imap_srv_names_the_tls_port(self) -> None:
        record = self._record(RecordKind.SRV_IMAP)

        assert record.name == "_imaps._tcp.acme.test"
        assert record.type == "SRV"
        assert record.value.endswith("993 mail.acme.test.")

    def test_the_submission_srv_names_port_587(self) -> None:
        record = self._record(RecordKind.SRV_SUBMISSION)

        assert record.name == "_submission._tcp.acme.test"
        assert "587" in record.value


class TestOnlyDeliverabilityDecidesVerification:
    def test_the_four_mail_records_are_required(self) -> None:
        assert all(
            k.required_for_verification
            for k in (
                RecordKind.MX,
                RecordKind.SPF,
                RecordKind.DKIM,
                RecordKind.DMARC,
            )
        )

    def test_ptr_and_the_discovery_records_are_not(self) -> None:
        assert not any(
            k.required_for_verification
            for k in (
                RecordKind.PTR,
                RecordKind.AUTOCONFIG,
                RecordKind.AUTODISCOVER,
                RecordKind.SRV_IMAP,
                RecordKind.SRV_SUBMISSION,
            )
        )

    def test_an_unpublished_autoconfig_does_not_block_a_domain(self) -> None:
        """The regression this pair of mechanisms exists to prevent."""
        checks = [
            CheckResult(kind, CheckState.OK)
            for kind in (
                RecordKind.MX,
                RecordKind.SPF,
                RecordKind.DKIM,
                RecordKind.DMARC,
            )
        ]
        checks.append(CheckResult(RecordKind.AUTOCONFIG, CheckState.MISSING))

        assert Verification("acme.test", checks).verified


class TestDiscoveryRecordMatching:
    def test_a_cname_matches_its_target(self) -> None:
        record = Record(RecordKind.AUTOCONFIG, "autoconfig.acme.test", "CNAME",
                        "mail.acme.test.")

        assert _matches(record, ["mail.acme.test"])

    def test_a_cname_pointing_elsewhere_does_not(self) -> None:
        record = Record(RecordKind.AUTOCONFIG, "autoconfig.acme.test", "CNAME",
                        "mail.acme.test.")

        assert not _matches(record, ["mail.globex.test"])

    def test_an_srv_matches_on_port_and_target(self) -> None:
        record = Record(RecordKind.SRV_IMAP, "_imaps._tcp.acme.test", "SRV",
                        "0 1 993 mail.acme.test.")

        assert _matches(record, ["10 5 993 mail.acme.test."]), "weight is the operator's"

    def test_an_srv_on_the_wrong_port_does_not(self) -> None:
        record = Record(RecordKind.SRV_IMAP, "_imaps._tcp.acme.test", "SRV",
                        "0 1 993 mail.acme.test.")

        assert not _matches(record, ["0 1 143 mail.acme.test."])
