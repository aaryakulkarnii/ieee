"""
LogPoison — llm_targets/ollama_target.py
Implements: SPEC.md § Target LLMs

Ollama adapter that implements LLMClientProtocol.
"""

from __future__ import annotations

import json
import logging
import re
import requests
import time

from attacks import SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class OllamaTarget:
    """Ollama API client implementing LLMClientProtocol."""

    def __init__(self, model_name: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url
        self.api_url = f"{self.base_url}/api/chat"
        self._test_connection()

    def _test_connection(self):
        """Warn if Ollama is not reachable, but don't crash."""
        try:
            requests.get(self.base_url, timeout=2.0)
        except requests.exceptions.RequestException:
            logger.warning(
                f"Ollama server not reachable at {self.base_url}. "
                "Ensure Ollama is running if you intend to evaluate against it."
            )

    def classify(self, log: str) -> dict:
        """
        Send log to LLM for classification.
        Returns dict with: classification, confidence, mitre_tactic, raw_text
        """
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{log}"}
        ]
        
        response_text = self._call_api(messages)
        return self._parse_classification(response_text)

    def rewrite(self, prompt: str) -> str:
        """
        Rewrite a string based on the given prompt (Semantic Camouflage).
        """
        messages = [{"role": "user", "content": prompt}]
        return self._call_api(messages).strip()

    def chat(self, messages: list[dict]) -> dict:
        """
        Continue a multi-turn conversation (Context Poisoning).
        """
        # Make sure the system prompt is present at the start
        if not messages or messages[0].get("role") != "system":
            messages.insert(0, {"role": "system", "content": SYSTEM_PROMPT})
            
        response_text = self._call_api(messages)
        return self._parse_classification(response_text)

    def _call_api(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False
        }
        try:
            resp = requests.post(self.api_url, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"Ollama API call failed: {e}")
            return ""

    def _parse_classification(self, text: str) -> dict:
        """Parse unstructured LLM text into structured classification data."""
        # Defaults
        result = {
            "classification": "BENIGN", 
            "confidence": 0.0, 
            "mitre_tactic": None,
            "raw_text": text
        }
        
        # 1. Classification
        if "MALICIOUS" in text.upper():
            result["classification"] = "MALICIOUS"
            
        # 2. Confidence
        # Look for numbers near "Confidence:"
        m_conf = re.search(r"(?i)confidence:\s*([0-9.]+)", text)
        if m_conf:
            try:
                result["confidence"] = float(m_conf.group(1))
            except ValueError:
                pass

        # 3. MITRE Tactic
        # Very rough heuristic: grab whatever is after "MITRE ATT&CK Tactic:" up to a newline
        m_tactic = re.search(r"(?i)MITRE ATT&CK Tactic:\s*([^\n]+)", text)
        if m_tactic:
            tactic = m_tactic.group(1).strip()
            if tactic.lower() not in ("none", "n/a", "null", ""):
                result["mitre_tactic"] = tactic

        return result
