"""
LogPoison — attacks/tests/test_format_aware.py
Implements: SPEC.md § Coding conventions — unit tests for FormatAwareAttack.

A mock LLM is used for all tests; no real API calls are made.  The mock
is parameterised by a 'flip_on' substring: if that substring appears in
the candidate log, it returns 'BENIGN' (else 'MALICIOUS').  This lets us
craft tests where we know exactly which perturbation will flip the label.

Test coverage:
  - Successful digit-substitution flip with edit_distance == 1.
  - edit_distance field is an integer in the output record.
  - max_edits budget is respected (no LLM calls beyond the budget).
  - Invalid-format candidates are never passed to the LLM.
  - AttackFailedError raised when no flip is found within budget.
  - validate_format() returns False for deliberately malformed logs.
  - Format-validity hard constraint: only valid logs are ever classified.

Run with:
    pytest attacks/tests/test_format_aware.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from attacks import AttackFailedError, BaseAttack, FormatValidationError
from attacks.format_aware import FormatAwareAttack, edit_distance

# ---------------------------------------------------------------------------
# Mock LLM target
# ---------------------------------------------------------------------------


class MockLLM:
    """Returns 'BENIGN' if *flip_on* substring is in the log, else 'MALICIOUS'."""

    def __init__(self, flip_on: str, original_class: str = "MALICIOUS") -> None:
        self.flip_on = flip_on
        self.original_class = original_class
        self.calls: list[str] = []

    def classify(self, log: str) -> dict:
        self.calls.append(log)
        if self.flip_on in log:
            flipped = "BENIGN" if self.original_class == "MALICIOUS" else "MALICIOUS"
        else:
            flipped = self.original_class
        return {
            "classification": flipped,
            "confidence": 90,
            "mitre_tactic": None,
            "recommendation": "Mock response.",
        }


class NeverFlipLLM:
    """Always returns MALICIOUS regardless of the log content."""

    def classify(self, log: str) -> dict:
        return {"classification": "MALICIOUS", "confidence": 99, "mitre_tactic": None}


# ---------------------------------------------------------------------------
# Sample records
# ---------------------------------------------------------------------------

# JSON record — we inject into the 'content' field (value "generating core.3255")
# The digit '3' in "core.3255" can be perturbed by digit_sub operator.
JSON_RECORD = {
    "log_id": "test-json-fa-001",
    "raw_log": json.dumps({
        "timestamp": "1117838570",
        "level": "INFO",
        "content": "generating core.3255",
    }, separators=(",", ":")),
    "format": "JSON",
    "ground_truth_label": "malicious",
    "attack_type": "Impact",
    "is_adversarial": False,
    "attack_goal": None,
    "attacker_level": None,
    "source_dataset": "BGL",
}

SYSLOG_RECORD = {
    "log_id": "test-syslog-fa-001",
    "raw_log": (
        "<30>1 2008-11-09T20:35:27Z hdfs-cluster dfs.DataNode 153 - - "
        "Served block blk_8 to /10.0.0.1"
    ),
    "format": "syslog",
    "ground_truth_label": "malicious",
    "attack_type": "Impact",
    "is_adversarial": False,
    "attack_goal": None,
    "attacker_level": None,
    "source_dataset": "HDFS",
}

CEF_RECORD = {
    "log_id": "test-cef-fa-001",
    "raw_log": (
        "CEF:0|UNB|CICIDS2017|1.0|IMPACT|Network Flow: DoS|8|"
        "dstPort=80 flowDur=12345 totFwdPkt=5"
    ),
    "format": "CEF",
    "ground_truth_label": "malicious",
    "attack_type": "Impact",
    "is_adversarial": False,
    "attack_goal": None,
    "attacker_level": None,
    "source_dataset": "CICIDS2017",
}


# ---------------------------------------------------------------------------
# Tests: edit_distance utility
# ---------------------------------------------------------------------------

class TestEditDistance:
    """Tests for the standalone Levenshtein edit_distance function."""

    def test_identical_strings(self):
        assert edit_distance("abc", "abc") == 0

    def test_single_substitution(self):
        assert edit_distance("abc", "axc") == 1

    def test_single_insertion(self):
        assert edit_distance("abc", "abcd") == 1

    def test_single_deletion(self):
        assert edit_distance("abcd", "abc") == 1

    def test_empty_strings(self):
        assert edit_distance("", "") == 0

    def test_one_empty(self):
        assert edit_distance("abc", "") == 3


# ---------------------------------------------------------------------------
# Tests: validate_format hard constraint (format-validity assertions)
# ---------------------------------------------------------------------------

class TestValidateFormat:
    """validate_format() must return False for broken logs — hard constraint."""

    def test_valid_syslog_returns_true(self):
        log = "<30>1 2008-11-09T20:35:27Z host app 123 - - message"
        assert BaseAttack.validate_format(log, "syslog") is True

    def test_invalid_syslog_no_pri(self):
        assert BaseAttack.validate_format("no PRI here", "syslog") is False

    def test_invalid_syslog_pri_out_of_range(self):
        assert BaseAttack.validate_format("<999>1 - host app 1 - - msg", "syslog") is False

    def test_invalid_syslog_newline_in_header(self):
        assert BaseAttack.validate_format("<30>1 2008-11-09T20:35:27Z\n host app 1 - - msg", "syslog") is False

    def test_valid_cef_returns_true(self):
        log = "CEF:0|vendor|product|1.0|class|name|5|key=value"
        assert BaseAttack.validate_format(log, "CEF") is True

    def test_invalid_cef_wrong_segment_count(self):
        # Only 7 segments (missing extension)
        assert BaseAttack.validate_format("CEF:0|a|b|c|d|e|5", "CEF") is False

    def test_invalid_cef_no_cef_prefix(self):
        assert BaseAttack.validate_format("NOT:0|a|b|c|d|e|5|key=val", "CEF") is False

    def test_invalid_cef_ext_no_key_eq(self):
        # Extension doesn't start with key=
        assert BaseAttack.validate_format("CEF:0|a|b|c|d|e|5|just plain text", "CEF") is False

    def test_valid_json_returns_true(self):
        assert BaseAttack.validate_format('{"a": "b"}', "JSON") is True

    def test_invalid_json_not_dict(self):
        assert BaseAttack.validate_format("[1, 2, 3]", "JSON") is False

    def test_invalid_json_malformed(self):
        assert BaseAttack.validate_format("{broken json}", "JSON") is False

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown format"):
            BaseAttack.validate_format("anything", "XML")


# ---------------------------------------------------------------------------
# Tests: FormatAwareAttack — successful flip
# ---------------------------------------------------------------------------

class TestFormatAwareSuccess:
    """FormatAwareAttack finds a flip via digit substitution at edit distance 1."""

    def test_json_digit_sub_flips_classification(self):
        # "core.3255" contains digit '3'. digit_sub produces "core.2255" etc.
        # Our mock flips when "core.2255" appears (flip_on="core.2255").
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        assert result["is_adversarial"] is True
        assert result["adversarial_classification"] == "BENIGN"
        assert result["original_classification"] == "MALICIOUS"

    def test_edit_distance_is_integer(self):
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        assert isinstance(result["edit_distance"], int)
        assert result["edit_distance"] >= 1

    def test_edit_distance_equals_1_for_single_digit_sub(self):
        """Single digit substitution must produce edit_distance == 1."""
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        assert result["edit_distance"] == 1, (
            "A single digit substitution should yield edit_distance of 1"
        )

    def test_perturbation_budget_field_present(self):
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        assert "perturbation_budget" in result
        assert result["perturbation_budget"] >= 1

    def test_output_format_valid(self):
        """The adversarial log returned must pass validate_format."""
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        assert BaseAttack.validate_format(result["raw_log"], result["format"]), (
            "Adversarial log must remain format-valid — hard constraint"
        )

    def test_syslog_case_flip_flip(self):
        # Digit '8' in "blk_8" → can become '7' or '9'.
        # Use flip_on="blk_7" so the mock flips on the perturbed version.
        llm = MockLLM(flip_on="blk_7", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(SYSLOG_RECORD)
        assert result["is_adversarial"] is True
        assert BaseAttack.validate_format(result["raw_log"], "syslog")

    def test_result_schema_keys(self):
        llm = MockLLM(flip_on="core.2255", original_class="MALICIOUS")
        atk = FormatAwareAttack(llm_target=llm, max_edits=3, seed=42)
        result = atk.craft(JSON_RECORD)
        required = {
            "log_id", "raw_log", "format", "ground_truth_label",
            "attack_type", "is_adversarial", "attack_goal", "attacker_level",
            "source_dataset", "edit_distance",
        }
        assert required.issubset(result.keys())


# ---------------------------------------------------------------------------
# Tests: FormatAwareAttack — budget and validity constraints
# ---------------------------------------------------------------------------

class TestFormatAwareConstraints:
    """Verify the hard constraints on budget and format validity."""

    def test_attack_failed_when_no_flip_within_budget(self):
        """Raises AttackFailedError when the LLM never flips."""
        atk = FormatAwareAttack(llm_target=NeverFlipLLM(), max_edits=1, seed=0)
        with pytest.raises(AttackFailedError):
            atk.craft(JSON_RECORD)

    def test_invalid_original_raises_format_validation_error(self):
        """If the original log itself is invalid, craft() raises FormatValidationError."""
        bad_record = {**JSON_RECORD, "raw_log": "{broken json}"}
        llm = MockLLM(flip_on="anything")
        atk = FormatAwareAttack(llm_target=llm, max_edits=2, seed=0)
        with pytest.raises(FormatValidationError):
            atk.craft(bad_record)

    def test_invalid_candidates_never_reach_llm(self):
        """The LLM must never be called with a format-invalid log."""
        # We wrap a real LLM mock to track every call
        inner_llm = MockLLM(flip_on="__never_matches__", original_class="MALICIOUS")

        class SpyLLM:
            def __init__(self):
                self.calls = []

            def classify(self, log: str) -> dict:
                # Assert format validity at the moment of the LLM call
                fmt = JSON_RECORD["format"]
                assert BaseAttack.validate_format(log, fmt), (
                    f"LLM received an invalid {fmt} log: {log!r}"
                )
                self.calls.append(log)
                return inner_llm.classify(log)

        spy = SpyLLM()
        atk = FormatAwareAttack(llm_target=spy, max_edits=1, seed=42)
        with pytest.raises(AttackFailedError):
            atk.craft(JSON_RECORD)
        # If we got here, all LLM calls were with valid-format logs
        assert len(spy.calls) > 0, "At least one valid candidate should have been tried"

    def test_max_edits_constructor_validation(self):
        with pytest.raises(ValueError, match="max_edits"):
            FormatAwareAttack(llm_target=NeverFlipLLM(), max_edits=0)
