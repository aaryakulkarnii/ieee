"""
LogPoison — attacks/tests/test_semantic_camouflage.py
Tests for SemanticCamouflageAttack (SPEC.md § Attack Classes #2).

All tests are offline and fast:
  - LLM rewrite is mocked with a deterministic string transformer.
  - The sentence-transformer model is replaced with MockSentenceTransformer,
    which returns pre-computed numpy vectors chosen so that embedding-shift
    assertions are predictable.

To run an integration test that loads the real all-mpnet-base-v2 model,
pass ``--integration`` to pytest (requires sentence-transformers installed).

Run:
    pytest attacks/tests/test_semantic_camouflage.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from attacks import BaseAttack, FormatValidationError
from attacks.semantic_camouflage import SemanticCamouflageAttack

# ---------------------------------------------------------------------------
# Pre-computed embedding vectors
# ---------------------------------------------------------------------------
# Chosen so that:
#   cosine_sim(MALICIOUS, BENIGN) = 0.0   (orthogonal — far apart)
#   cosine_sim(REWRITTEN, BENIGN) ≈ 1.0   (rewrite moved toward benign)
#   embedding_shift = 1.0 − 0.0 = 1.0    (positive → attack worked)

MALICIOUS_VEC = np.array([1.0, 0.0, 0.0], dtype=np.float32)
REWRITTEN_VEC = np.array([0.0, 1.0, 0.0], dtype=np.float32)
BENIGN_VEC    = np.array([0.0, 1.0, 0.0], dtype=np.float32)  # same direction as rewritten


class MockSentenceTransformer:
    """Deterministic model stub that returns pre-computed vectors."""

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name

    def encode(
        self,
        texts: list[str],
        show_progress_bar: bool = False,
        normalize_embeddings: bool = False,
        batch_size: int = 32,
    ) -> np.ndarray:
        results = []
        for text in texts:
            t = text.lower()
            if any(kw in t for kw in ("routine", "normal", "access", "scheduled")):
                results.append(REWRITTEN_VEC.copy())
            else:
                results.append(MALICIOUS_VEC.copy())
        arr = np.array(results, dtype=np.float32)
        if normalize_embeddings:
            norms = np.linalg.norm(arr, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            arr = arr / norms
        return arr


# ---------------------------------------------------------------------------
# Mock LLM client
# ---------------------------------------------------------------------------

class MockLLMRewriter:
    """Rewrites to a predictable benign-sounding string."""

    def rewrite(self, prompt: str) -> str:
        # Extract the original message from the prompt. The REWRITE_PROMPT
        # template ends with '\n\nRewritten message:' as a completion cue;
        # split on the first double-newline after 'Original message:' to avoid
        # capturing that suffix.
        if "Original message:" in prompt:
            after = prompt.split("Original message:")[-1]
            # Trim the trailing '\n\nRewritten message:' cue if present
            orig = after.split("\n\n")[0].strip()
        else:
            orig = prompt.strip()
        # Prefix with benign-sounding phrase; contains 'access' so that
        # MockSentenceTransformer returns REWRITTEN_VEC for this text.
        return f"Routine scheduled access: {orig}"

    def classify(self, log: str) -> dict:
        return {"classification": "BENIGN", "confidence": 80, "mitre_tactic": None}


# ---------------------------------------------------------------------------
# Shared test records
# ---------------------------------------------------------------------------

SYSLOG_RECORD = {
    "log_id": "sc-syslog-001",
    "raw_log": (
        "<30>1 2008-11-09T20:35:27Z hdfs-cluster dfs.DataNode 153 - - "
        "Served block blk_-160899 to /10.251.215.16"
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
    "log_id": "sc-cef-001",
    "raw_log": (
        "CEF:0|UNB|CICIDS2017|1.0|IMPACT|DoS Hulk|8|"
        "dstPort=80 flowDur=9999999 totFwdPkt=50000 cicidsLabel=DoS Hulk"
    ),
    "format": "CEF",
    "ground_truth_label": "malicious",
    "attack_type": "Impact",
    "is_adversarial": False,
    "attack_goal": None,
    "attacker_level": None,
    "source_dataset": "CICIDS2017",
}

JSON_RECORD = {
    "log_id": "sc-json-001",
    "raw_log": json.dumps({
        "timestamp": "1117838570",
        "level":     "FATAL",
        "content":   "VOLTAGE EXCEPTION at node R00-M1-N0",
    }, separators=(",", ":")),
    "format": "JSON",
    "ground_truth_label": "malicious",
    "attack_type": "Impact",
    "is_adversarial": False,
    "attack_goal": None,
    "attacker_level": None,
    "source_dataset": "BGL",
}

# Benign centroid sources (list[str] — no file I/O in tests)
BENIGN_TEXTS = [
    "Routine file access: opening config.xml",
    "Normal scheduled heartbeat from service monitor",
    "Access granted to /var/log for routine maintenance",
]


# ---------------------------------------------------------------------------
# Helper: build an attack with mock model injected
# ---------------------------------------------------------------------------

def make_attack(record: dict | None = None, centroid_source=BENIGN_TEXTS):
    """Return a SemanticCamouflageAttack with mock LLM and mock ST model."""
    atk = SemanticCamouflageAttack(
        llm_client=MockLLMRewriter(),
        centroid_source=centroid_source,
        model_name="mock-model",
        attacker_level="greybox",
    )
    # Inject mock model directly into the class cache
    SemanticCamouflageAttack._model_cache["mock-model"] = MockSentenceTransformer("mock-model")
    return atk


# ---------------------------------------------------------------------------
# Tests: craft() output
# ---------------------------------------------------------------------------

class TestSemanticCamouflageOutput:

    def setup_method(self):
        make_attack()  # prime the cache

    def test_returns_adversarial_record(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert result["is_adversarial"] is True

    def test_attack_goal_is_evasion(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert result["attack_goal"] == "evasion"

    def test_log_id_contains_attack_name(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert "semantic_camouflage" in result["log_id"]

    def test_required_schema_keys_present(self):
        required = {
            "log_id", "raw_log", "format", "ground_truth_label",
            "attack_type", "is_adversarial", "attack_goal", "attacker_level",
            "source_dataset",
        }
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert required.issubset(result.keys())

    def test_embedding_metric_keys_present(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        for key in ("cosine_sim_orig_rewrite", "embedding_shift"):
            assert key in result, f"Missing metric key: {key}"

    def test_rewritten_message_field_present(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert "rewritten_message" in result

    def test_ground_truth_label_unchanged(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert result["ground_truth_label"] == SYSLOG_RECORD["ground_truth_label"]


# ---------------------------------------------------------------------------
# Tests: format validity (hard constraint)
# ---------------------------------------------------------------------------

class TestSemanticCamouflageFormatValidity:
    """validate_format() must pass for all formats — hard constraint."""

    def test_syslog_format_valid_after_rewrite(self):
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert BaseAttack.validate_format(result["raw_log"], "syslog"), (
            "Crafted syslog log must remain RFC 5424 valid"
        )

    def test_cef_format_valid_after_rewrite(self):
        atk = make_attack()
        result = atk.craft(CEF_RECORD)
        assert BaseAttack.validate_format(result["raw_log"], "CEF"), (
            "Crafted CEF log must have 8 segments and valid extension"
        )

    def test_json_format_valid_after_rewrite(self):
        atk = make_attack()
        result = atk.craft(JSON_RECORD)
        assert BaseAttack.validate_format(result["raw_log"], "JSON"), (
            "Crafted JSON log must remain valid dict"
        )

    def test_broken_rewrite_raises_format_validation_error(self):
        """If the LLM rewrite returns text that breaks the format, we must raise."""

        class BreakingRewriter:
            """Returns a string with pipe chars that break CEF structure."""
            def rewrite(self, prompt):
                return "broken|output|with|too|many|pipes|for|CEF|structure"

        atk = SemanticCamouflageAttack(
            llm_client=BreakingRewriter(),
            centroid_source=None,
            model_name="mock-model",
        )
        SemanticCamouflageAttack._model_cache["mock-model"] = MockSentenceTransformer("mock-model")

        # CEF: extra pipes break the 8-segment structure
        with pytest.raises(FormatValidationError):
            atk.craft(CEF_RECORD)


# ---------------------------------------------------------------------------
# Tests: embedding shift metrics
# ---------------------------------------------------------------------------

class TestSemanticCamouflageMetrics:

    def test_cosine_sim_orig_rewrite_is_float(self):
        atk = make_attack()
        result = atk.craft(JSON_RECORD)
        val = result["cosine_sim_orig_rewrite"]
        assert isinstance(val, float), f"expected float, got {type(val)}"

    def test_embedding_shift_is_positive(self):
        """Rewrite should move embedding toward the benign centroid."""
        atk = make_attack(centroid_source=BENIGN_TEXTS)
        result = atk.craft(JSON_RECORD)
        shift = result.get("embedding_shift")
        assert shift is not None, "embedding_shift should not be None when centroid_source is set"
        assert shift > 0.0, (
            f"embedding_shift should be positive (got {shift}), "
            "meaning rewrite moved toward benign cluster"
        )

    def test_centroid_none_disables_shift_metric(self):
        """centroid_source=None should produce embedding_shift=None."""
        atk = SemanticCamouflageAttack(
            llm_client=MockLLMRewriter(),
            centroid_source=None,
            model_name="mock-model",
        )
        SemanticCamouflageAttack._model_cache["mock-model"] = MockSentenceTransformer("mock-model")
        result = atk.craft(JSON_RECORD)
        assert result["embedding_shift"] is None
        # cosine_sim_orig_rewrite should still be computed
        assert result["cosine_sim_orig_rewrite"] is not None

    def test_centroid_list_source_used_directly(self):
        """Centroid built from list[str] (no file I/O required)."""
        atk = make_attack(centroid_source=BENIGN_TEXTS)
        result = atk.craft(JSON_RECORD)
        # cosine_sim_rewrite_benign should be present and a float
        assert isinstance(result.get("cosine_sim_rewrite_benign"), float)

    def test_metrics_gracefully_none_when_model_unavailable(self):
        """If model cache is empty and sentence-transformers can't import, metrics → None."""
        atk = SemanticCamouflageAttack(
            llm_client=MockLLMRewriter(),
            centroid_source=BENIGN_TEXTS,
            model_name="__nonexistent_model__",
        )
        # Remove from cache to force reload attempt
        SemanticCamouflageAttack._model_cache.pop("__nonexistent_model__", None)

        # Patch SentenceTransformer to raise on load
        with patch("attacks.semantic_camouflage.SemanticCamouflageAttack._get_model",
                   return_value=None):
            result = atk.craft(JSON_RECORD)

        assert result["embedding_shift"] is None
        assert result["cosine_sim_orig_rewrite"] is None
        # Log should still be returned (format valid)
        assert BaseAttack.validate_format(result["raw_log"], "JSON")


# ---------------------------------------------------------------------------
# Tests: structured fields preserved after rewrite
# ---------------------------------------------------------------------------

class TestStructuredFieldsPreserved:

    def test_syslog_structured_header_unchanged(self):
        """Rewriting MSG must not touch PRI/VERSION/TIMESTAMP/HOSTNAME etc."""
        original_header = "<30>1 2008-11-09T20:35:27Z hdfs-cluster dfs.DataNode 153 - -"
        atk = make_attack()
        result = atk.craft(SYSLOG_RECORD)
        assert result["raw_log"].startswith(original_header), (
            "Syslog structured header must be byte-for-byte identical after rewrite"
        )

    def test_json_keys_unchanged(self):
        """JSON key names must not change; only the targeted value is rewritten."""
        atk = make_attack()
        result = atk.craft(JSON_RECORD)
        obj = json.loads(result["raw_log"])
        # All original keys must still exist
        orig_keys = set(json.loads(JSON_RECORD["raw_log"]).keys())
        assert orig_keys.issubset(obj.keys())

    def test_cef_header_segments_unchanged(self):
        """CEF vendor/product/version/classId and severity/extension must be
        unchanged after rewrite.  parts[5] (the name field) IS the rewrite target
        so it is intentionally different."""
        atk = make_attack()
        result = atk.craft(CEF_RECORD)
        orig_parts = CEF_RECORD["raw_log"].split("|", 7)
        new_parts  = result["raw_log"].split("|", 7)
        # parts[5] is the name field — rewritten by design; skip it
        unchanged_indices = [0, 1, 2, 3, 4, 6, 7]
        for i in unchanged_indices:
            assert orig_parts[i] == new_parts[i], (
                f"CEF segment[{i}] must not change (vendor/product/classId/sev/ext); "
                f"expected {orig_parts[i]!r}, got {new_parts[i]!r}"
            )
