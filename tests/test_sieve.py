"""Sieve generation from Lightr filter rules."""

from __future__ import annotations

import pytest

from lightr.dovecot.sieve import (
    Action,
    Condition,
    Field,
    MatchType,
    Operator,
    Rule,
    SieveError,
    compile_condition,
    compile_rule,
    compile_script,
)


def _rule(*conditions: Condition, **kwargs: object) -> Rule:
    kwargs.setdefault("actions", [(Action.FILE_INTO, "Filed")])
    return Rule(name=kwargs.pop("name", "test rule"), conditions=conditions, **kwargs)  # type: ignore[arg-type]


class TestSieveNativeConditions:
    def test_subject_contains(self) -> None:
        test, requires = compile_condition(
            Condition(Field.SUBJECT, Operator.CONTAINS, "invoice")
        )
        assert test == 'header :contains "Subject" "invoice"'
        assert requires == set()

    def test_from_equals(self) -> None:
        test, _ = compile_condition(Condition(Field.FROM, Operator.EQUALS, "a@b.test"))
        assert test == 'header :is "From" "a@b.test"'

    def test_starts_with_becomes_a_glob(self) -> None:
        test, _ = compile_condition(
            Condition(Field.FROM, Operator.STARTS_WITH, "billing@")
        )
        assert test == 'header :matches "From" "billing@*"'

    def test_ends_with_becomes_a_glob(self) -> None:
        test, _ = compile_condition(Condition(Field.TO, Operator.ENDS_WITH, "@acme.test"))
        assert test == 'header :matches "To" "*@acme.test"'

    def test_wildcards_in_literals_are_escaped(self) -> None:
        """A literal '*' must not become a wildcard."""
        test, _ = compile_condition(
            Condition(Field.SUBJECT, Operator.STARTS_WITH, "50%*off")
        )
        assert "\\*" in test

    def test_custom_header(self) -> None:
        test, _ = compile_condition(
            Condition(Field.HEADER, Operator.CONTAINS, "bulk", header="X-Precedence")
        )
        assert test == 'header :contains "X-Precedence" "bulk"'

    def test_header_condition_without_a_name_is_rejected(self) -> None:
        with pytest.raises(SieveError, match="needs a header name"):
            compile_condition(Condition(Field.HEADER, Operator.CONTAINS, "x"))

    def test_body_requires_the_body_extension(self) -> None:
        test, requires = compile_condition(
            Condition(Field.BODY, Operator.CONTAINS, "unsubscribe")
        )
        assert test == 'body :text :contains "unsubscribe"'
        assert requires == {"body"}

    def test_size_over(self) -> None:
        test, _ = compile_condition(
            Condition(Field.SIZE, Operator.GREATER_THAN, "5000000")
        )
        assert test == "size :over 5000000"

    def test_size_needs_an_integer(self) -> None:
        with pytest.raises(SieveError, match="integer"):
            compile_condition(Condition(Field.SIZE, Operator.GREATER_THAN, "big"))

    def test_quotes_are_escaped(self) -> None:
        test, _ = compile_condition(
            Condition(Field.SUBJECT, Operator.CONTAINS, 'say "hi"')
        )
        assert test == 'header :contains "Subject" "say \\"hi\\""'


class TestLightrEvaluatedConditions:
    """Fields Sieve cannot compute, tested via headers Lightr injects."""

    def test_spam_score_uses_a_relational_header_test(self) -> None:
        test, requires = compile_condition(
            Condition(Field.SPAM_SCORE, Operator.GREATER_THAN, "4.0")
        )
        assert "X-Spam-Score" in test
        assert 'i;ascii-numeric' in test
        assert requires == {"relational", "comparator-i;ascii-numeric"}

    def test_spam_score_needs_a_number(self) -> None:
        with pytest.raises(SieveError, match="numeric"):
            compile_condition(Condition(Field.SPAM_SCORE, Operator.GREATER_THAN, "high"))

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            (Field.SPF_RESULT, "spf=fail"),
            (Field.DKIM_RESULT, "dkim=fail"),
            (Field.DMARC_RESULT, "dmarc=fail"),
        ],
    )
    def test_auth_results_are_tested_as_one_header(
        self, field: Field, expected: str
    ) -> None:
        test, _ = compile_condition(Condition(field, Operator.EQUALS, "fail"))
        assert "Authentication-Results" in test
        assert expected in test

    def test_attachment_presence(self) -> None:
        test, _ = compile_condition(Condition(Field.ATTACHMENT, Operator.EQUALS, "true"))
        assert test == 'header :is "X-Lightr-Has-Attachment" "yes"'

    def test_attachment_absence_is_negated(self) -> None:
        test, _ = compile_condition(Condition(Field.ATTACHMENT, Operator.EQUALS, "false"))
        assert test.startswith("not ")


class TestActions:
    def test_file_into_creates_the_folder(self) -> None:
        block, requires = compile_rule(
            _rule(
                Condition(Field.SUBJECT, Operator.CONTAINS, "x"),
                actions=[(Action.FILE_INTO, "Invoices")],
            )
        )
        assert 'fileinto :create "Invoices";' in block
        assert {"fileinto", "mailbox"} <= requires

    def test_redirect_validates_the_address(self) -> None:
        with pytest.raises(SieveError, match="email address"):
            compile_rule(
                _rule(
                    Condition(Field.SUBJECT, Operator.CONTAINS, "x"),
                    actions=[(Action.REDIRECT, "not-an-address")],
                )
            )

    def test_mark_read_needs_imap4flags(self) -> None:
        _, requires = compile_rule(
            _rule(
                Condition(Field.SUBJECT, Operator.CONTAINS, "x"),
                actions=[(Action.MARK_READ, "")],
            )
        )
        assert "imap4flags" in requires

    def test_stop_on_match_appends_stop(self) -> None:
        block, _ = compile_rule(
            _rule(Condition(Field.SUBJECT, Operator.CONTAINS, "x"), stop_on_match=True)
        )
        assert block.rstrip().endswith("stop;\n}")

    def test_stop_is_not_duplicated(self) -> None:
        block, _ = compile_rule(
            _rule(
                Condition(Field.SUBJECT, Operator.CONTAINS, "x"),
                actions=[(Action.DISCARD, ""), (Action.STOP, "")],
                stop_on_match=True,
            )
        )
        assert block.count("stop;") == 1


class TestRuleCompilation:
    def test_multiple_conditions_use_allof(self) -> None:
        block, _ = compile_rule(
            _rule(
                Condition(Field.FROM, Operator.CONTAINS, "billing"),
                Condition(Field.SUBJECT, Operator.CONTAINS, "invoice"),
            )
        )
        assert "allof (" in block

    def test_any_match_uses_anyof(self) -> None:
        block, _ = compile_rule(
            _rule(
                Condition(Field.FROM, Operator.CONTAINS, "a"),
                Condition(Field.FROM, Operator.CONTAINS, "b"),
                match_type=MatchType.ANY,
            )
        )
        assert "anyof (" in block

    def test_single_condition_is_not_wrapped(self) -> None:
        block, _ = compile_rule(_rule(Condition(Field.FROM, Operator.CONTAINS, "a")))
        assert "allof" not in block

    def test_rule_without_conditions_is_rejected(self) -> None:
        with pytest.raises(SieveError, match="no conditions"):
            compile_rule(Rule(name="empty", conditions=[], actions=[(Action.STOP, "")]))

    def test_rule_without_actions_is_rejected(self) -> None:
        with pytest.raises(SieveError, match="no actions"):
            compile_rule(
                Rule(
                    name="empty",
                    conditions=[Condition(Field.FROM, Operator.CONTAINS, "a")],
                    actions=[],
                )
            )


class TestScriptGeneration:
    def test_requires_are_hoisted_and_deduplicated(self) -> None:
        script = compile_script(
            [
                _rule(Condition(Field.BODY, Operator.CONTAINS, "a"), name="one"),
                _rule(Condition(Field.BODY, Operator.CONTAINS, "b"), name="two"),
            ]
        )
        rendered = script.render()
        assert rendered.count("require") == 1
        assert '"body"' in rendered
        assert '"fileinto"' in rendered

    def test_rules_run_in_priority_order(self) -> None:
        script = compile_script(
            [
                _rule(Condition(Field.FROM, Operator.CONTAINS, "z"), name="last", priority=900),
                _rule(Condition(Field.FROM, Operator.CONTAINS, "a"), name="first", priority=1),
            ]
        )
        assert script.body.index("# first") < script.body.index("# last")

    def test_inactive_rules_are_skipped(self) -> None:
        script = compile_script(
            [_rule(Condition(Field.FROM, Operator.CONTAINS, "a"), is_active=False)]
        )
        assert "No active rules" in script.body

    def test_empty_ruleset_is_a_valid_script(self) -> None:
        rendered = compile_script([]).render()
        assert "require" not in rendered
        assert rendered.strip().endswith("# No active rules.")

    def test_script_warns_against_hand_editing(self) -> None:
        assert "Do not edit" in compile_script([]).render()

    def test_realistic_junk_rule(self) -> None:
        """The rule most installs will actually have."""
        script = compile_script(
            [
                Rule(
                    name="File spam into Junk",
                    conditions=[Condition(Field.SPAM_SCORE, Operator.GREATER_THAN, "4")],
                    actions=[(Action.FILE_INTO, "Junk"), (Action.STOP, "")],
                    priority=1,
                )
            ]
        )
        rendered = script.render()
        assert '"relational"' in rendered
        assert 'fileinto :create "Junk";' in rendered
        assert "X-Spam-Score" in rendered
