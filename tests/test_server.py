"""Server startup: address parsing and bind-failure reporting.

The address handling is tested carefully because getting it wrong is
silent: a server that binds only to loopback starts cleanly, logs
nothing unusual, and receives no mail from the internet.
"""

from __future__ import annotations

import pytest

from lightr.server import ANY_HOST, SHUTDOWN_GRACE_SECONDS, _bind_failure, parse_addr


class TestAddressParsing:
    @pytest.mark.parametrize(
        ("addr", "expected"),
        [
            (":25", (ANY_HOST, 25)),
            (":587", (ANY_HOST, 587)),
            ("", (ANY_HOST, 25)),
            ("   ", (ANY_HOST, 25)),
            ("127.0.0.1:2525", ("127.0.0.1", 2525)),
            ("localhost:8080", ("localhost", 8080)),
            ("localhost", ("localhost", 25)),
            ("0.0.0.0:25", ("0.0.0.0", 25)),
        ],
    )
    def test_parsing(self, addr: str, expected: tuple[str, int]) -> None:
        assert parse_addr(addr, 25) == expected

    def test_any_host_is_the_empty_string(self) -> None:
        """Not None, and not "0.0.0.0".

        None makes aiosmtpd bind IPv6 loopback only -- a production
        server would start cleanly and never receive external mail.
        "0.0.0.0" and "::" are rejected outright on some platforms.
        Only "" binds dual-stack.
        """
        assert ANY_HOST == ""
        assert ANY_HOST is not None

    def test_default_port_is_used_when_absent(self) -> None:
        assert parse_addr("mail.acme.test", 587)[1] == 587

    def test_explicit_port_beats_the_default(self) -> None:
        assert parse_addr(":2525", 25)[1] == 2525

    def test_ipv6_literal_with_a_port(self) -> None:
        """rpartition splits on the last colon, so a bracketed literal
        keeps its address intact."""
        host, port = parse_addr("[::1]:2525", 25)
        assert host == "[::1]"
        assert port == 2525


class TestBindFailureMessages:
    def test_privileged_port_explains_the_capability(self) -> None:
        message = _bind_failure("smtp", 25, OSError("permission denied"))
        assert "below 1024" in message
        assert "cap_net_bind_service" in message

    def test_high_port_does_not_claim_a_privilege_problem(self) -> None:
        """The first version said 'ports below 1024 need root' for every
        failure, which was actively misleading on a high port."""
        message = _bind_failure("smtp", 2525, OSError("address unavailable"))
        assert "below 1024" not in message
        assert "root" not in message

    @pytest.mark.parametrize("errno", [48, 98, 10048])
    def test_address_in_use_is_named(self, errno: int) -> None:
        exc = OSError("in use")
        exc.errno = errno
        assert "already listening" in _bind_failure("smtp", 2525, exc)

    def test_the_port_is_always_named(self) -> None:
        assert "2525" in _bind_failure("smtp", 2525, OSError("nope"))

    def test_the_underlying_error_survives(self) -> None:
        assert "nope" in _bind_failure("smtp", 2525, OSError("nope"))


class TestShutdown:
    def test_grace_period_is_generous_enough_to_finish_a_delivery(self) -> None:
        """The LMTP client's own timeout is 30s by default, so the
        grace period must not be so short that it always truncates."""
        assert SHUTDOWN_GRACE_SECONDS >= 20
