"""
LogPoison — llm_targets/ollama_target.py
Implements: SPEC.md § Target LLMs

Ollama adapter that implements LLMClientProtocol.

Fixes applied:
  [F1] Default classification changed BENIGN → UNCLEAR (silent API failures
       were indistinguishable from successful evasion attacks)
  [F2] Classification parser now handles the "MALICIOUS in explanation,
       BENIGN in verdict" case — looks for structured verdict line first,
       falls back to full-text scan only when no structured line exists
  [F3] Confidence regex extended to handle markdown bold, numbered prefixes,
       inline phrasing, and "High/Medium/Low" verbal confidence
  [F4] MITRE regex extended to handle abbreviated "MITRE Tactic:" label and
       tactic codes like "T1110 - Brute Force"
  [F5] Timeout raised from 30s → 120s for multi-turn context poisoning calls
  [F6] API failure now returns explicit error sentinel so caller can detect
       and exclude failed calls from ASR calculations
  [F7] Retry logic added (3 attempts, 5s backoff) for transient timeouts
  [F8] Malformed JSON response handled gracefully
  [F9] chat() now validates message roles before inserting system prompt
       to avoid duplicate system messages on repeated calls
"""

from __future__ import annotations

import logging
import re
import time

import requests

from attacks import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Sentinel returned when the API call fails — callers MUST check for this
# and exclude these records from ASR calculations
API_FAILURE_SENTINEL = "__API_FAILURE__"

# Verbal confidence map for when model says "High" instead of a number
VERBAL_CONFIDENCE = {
    "very high": 95.0,
    "high": 80.0,
    "medium": 60.0,
    "moderate": 60.0,
    "low": 35.0,
    "very low": 15.0,
    "uncertain": 50.0,
}


class OllamaTarget:
    """Ollama API client implementing LLMClientProtocol."""

    def __init__(
        self,
        model_name: str = "llama3.1",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,   # [F5] raised from 30s
        max_retries: int = 3,      # [F7] retry on transient failures
        retry_delay: float = 5.0,
    ):
        self.model_name = model_name
        self.base_url = base_url
        self.api_url = f"{self.base_url}/api/chat"
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._test_connection()

    def _test_connection(self):
        """Warn if Ollama is not reachable, but don't crash."""
        try:
            requests.get(self.base_url, timeout=3.0)
            logger.info(f"Ollama reachable at {self.base_url}")
        except requests.exceptions.RequestException:
            logger.warning(
                f"Ollama server not reachable at {self.base_url}. "
                "Ensure Ollama is running before evaluating."
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def classify(self, log: str) -> dict:
        """
        Send a single log entry for classification.
        Returns dict: classification, confidence, mitre_tactic, raw_text, api_ok
        """
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": log},
        ]
        response_text = self._call_api(messages)
        return self._parse_classification(response_text)

    def rewrite(self, prompt: str) -> str:
        """Rewrite a string (used for Semantic Camouflage attack)."""
        messages = [{"role": "user", "content": prompt}]
        result = self._call_api(messages)
        return result.strip() if result != API_FAILURE_SENTINEL else ""

    def chat(self, messages: list[dict]) -> dict:
        """
        Multi-turn conversation for Context Poisoning.
        Expects a list of {"role": "user"/"assistant", "content": ...} dicts.
        System prompt is prepended automatically if not already present.
        """
        # [F9] Only insert system prompt if first message isn't already one
        if not messages or messages[0].get("role") != "system":
            messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages

        response_text = self._call_api(messages)
        return self._parse_classification(response_text)

    # ------------------------------------------------------------------
    # API call with retry logic
    # ------------------------------------------------------------------

    def _call_api(self, messages: list[dict]) -> str:
        """
        POST to Ollama /api/chat with retry on transient failures.
        Returns response content string, or API_FAILURE_SENTINEL on hard failure.
        """
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
        }

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self.api_url,
                    json=payload,
                    timeout=self.timeout,   # [F5]
                )
                resp.raise_for_status()

                # [F8] Handle malformed JSON
                try:
                    data = resp.json()
                except ValueError:
                    logger.error(f"Malformed JSON response from Ollama (attempt {attempt})")
                    if attempt < self.max_retries:
                        time.sleep(self.retry_delay)
                        continue
                    return API_FAILURE_SENTINEL

                content = data.get("message", {}).get("content", "")
                if not content:
                    logger.warning(f"Empty content in Ollama response (attempt {attempt})")
                    if attempt < self.max_retries:
                        time.sleep(self.retry_delay)
                        continue
                    return API_FAILURE_SENTINEL

                return content

            except requests.exceptions.Timeout:
                logger.warning(f"Ollama request timed out (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error("All retry attempts exhausted after timeout.")
                    return API_FAILURE_SENTINEL

            except requests.exceptions.RequestException as e:
                logger.error(f"Ollama API call failed (attempt {attempt}): {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    return API_FAILURE_SENTINEL

        return API_FAILURE_SENTINEL

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_classification(self, text: str) -> dict:
        """
        Parse unstructured LLM text into structured classification data.

        Strategy:
          1. Check for API failure sentinel → return api_ok=False
          2. Look for a structured "Classification: X" verdict line first [F2]
          3. If no structured line, fall back to full-text keyword scan [F2]
          4. Parse confidence with extended regex [F3]
          5. Parse MITRE tactic with extended regex [F4]
        """
        # [F1] Default is UNCLEAR, not BENIGN
        result = {
            "classification": "UNCLEAR",
            "confidence": 0.0,
            "mitre_tactic": None,
            "raw_text": text,
            "api_ok": True,
        }

        # [F6] Hard failure — exclude from ASR
        if text == API_FAILURE_SENTINEL:
            result["classification"] = "UNCLEAR"
            result["api_ok"] = False
            logger.error("API failure — this record must be excluded from ASR calculations.")
            return result

        upper = text.upper()

        # ------------------------------------------------------------------
        # [F2] Classification — structured verdict line takes priority
        # Handles:
        #   "1. Classification: BENIGN"
        #   "Classification: **MALICIOUS**"
        #   "Classification: BENIGN (authorized test)"
        # ------------------------------------------------------------------
        verdict_match = re.search(
            r"(?i)(?:\d+\.\s*)?classification\s*:\s*\*{0,2}(BENIGN|MALICIOUS)\*{0,2}",
            text
        )
        if verdict_match:
            result["classification"] = verdict_match.group(1).upper()
        else:
            # Fallback: full-text scan — but handle the tricky case where
            # model says "Although this looks MALICIOUS, it is BENIGN"
            # We count occurrences and take the last explicit label
            benign_positions = [m.start() for m in re.finditer(r'\bBENIGN\b', upper)]
            malicious_positions = [m.start() for m in re.finditer(r'\bMALICIOUS\b', upper)]

            if benign_positions or malicious_positions:
                last_benign = max(benign_positions) if benign_positions else -1
                last_malicious = max(malicious_positions) if malicious_positions else -1
                # Whichever label appears last is the verdict
                result["classification"] = "BENIGN" if last_benign > last_malicious else "MALICIOUS"

        # ------------------------------------------------------------------
        # [F3] Confidence — extended to handle many formats:
        #   "Confidence: 90%"
        #   "2. Confidence: 85"
        #   "**Confidence:** 85%"
        #   "Confidence Score: 75%"
        #   "Confidence Level: High (90%)"
        #   "I am 90% confident"
        #   "Confidence: High"
        # ------------------------------------------------------------------
        # Try numeric first
        conf_match = re.search(
            r"(?i)(?:\d+\.\s*)?\*{0,2}confidence[^:]*:\*{0,2}\s*(?:[A-Za-z]+\s*\()?([0-9.]+)\s*%?",
            text
        )
        if conf_match:
            try:
                val = float(conf_match.group(1))
                # normalise: if someone writes 0.9 instead of 90
                result["confidence"] = val if val > 1 else val * 100
            except ValueError:
                pass
        else:
            # Try "I am 90% confident" phrasing
            inline_match = re.search(r"(?i)(?:am|with)\s+([0-9.]+)\s*%\s*confident", text)
            if inline_match:
                try:
                    result["confidence"] = float(inline_match.group(1))
                except ValueError:
                    pass
            else:
                # Try verbal: "Confidence: High"
                verbal_match = re.search(
                    r"(?i)confidence[^:]*:\s*\*{0,2}(very high|very low|high|medium|moderate|low|uncertain)\*{0,2}",
                    text
                )
                if verbal_match:
                    word = verbal_match.group(1).lower()
                    result["confidence"] = VERBAL_CONFIDENCE.get(word, 0.0)

        # ------------------------------------------------------------------
        # [F4] MITRE Tactic — extended to handle:
        #   "MITRE ATT&CK Tactic: Credential Access"
        #   "MITRE Tactic: Lateral Movement"  (abbreviated)
        #   "MITRE ATT&CK Tactic: T1110 - Brute Force"
        #   "3. MITRE ATT&CK Tactic: None"
        # ------------------------------------------------------------------
        tactic_match = re.search(
            r"(?i)(?:\d+\.\s*)?MITRE(?:\s+ATT&CK)?\s+Tactic\s*:\s*\*{0,2}([^\n]+?)\*{0,2}$",
            text,
            re.MULTILINE,
        )
        if tactic_match:
            tactic = tactic_match.group(1).strip()
            # Normalise None/N/A variants
            if tactic.lower() not in ("none", "n/a", "null", "", "not applicable", "none (authorized activity)"):
                result["mitre_tactic"] = tactic

        return result