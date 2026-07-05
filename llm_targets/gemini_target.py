"""
LogPoison — llm_targets/gemini_target.py
Implements: SPEC.md § Target LLMs
"""

import os
import re
import logging
from attacks import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai
except ImportError:
    genai = None

class GeminiTarget:
    """Gemini API client implementing LLMClientProtocol."""

    def __init__(self, model_name: str = "gemini-pro-latest"):
        self.model_name = model_name
        self.api_key = os.environ.get("GEMINI_API_KEY", "")
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set. API calls will fail.")
        elif genai:
            genai.configure(api_key=self.api_key)
            
        if genai is None:
            logger.error("google-generativeai package not installed.")

    def classify(self, log: str) -> dict:
        messages = [
            {"role": "user", "content": f"{SYSTEM_PROMPT}\n\nLog: {log}"}
        ]
        response_text = self._call_api(messages)
        return self._parse_classification(response_text)

    def rewrite(self, prompt: str) -> str:
        messages = [{"role": "user", "content": prompt}]
        return self._call_api(messages).strip()

    def chat(self, messages: list[dict]) -> dict:
        # Gemini structure expects alternating user/model or just one prompt string for simplicity
        # Let's flatten to a single prompt for now, as multi-turn requires alternating roles
        prompt = ""
        for m in messages:
            if m["role"] == "system":
                prompt += f"System: {m['content']}\n"
            elif m["role"] == "user":
                prompt += f"User: {m['content']}\n"
            elif m["role"] == "assistant":
                prompt += f"Assistant: {m['content']}\n"
                
        flattened_messages = [{"role": "user", "content": prompt}]
        response_text = self._call_api(flattened_messages)
        return self._parse_classification(response_text)

    def _call_api(self, messages: list[dict]) -> str:
        if not genai:
            return ""
        try:
            model = genai.GenerativeModel(self.model_name)
            # Just send the last user message or the concatenated prompt
            prompt = messages[-1]["content"] 
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return ""

    def _parse_classification(self, text: str) -> dict:
        result = {
            "classification": "BENIGN", 
            "confidence": 0.0, 
            "mitre_tactic": None,
            "raw_text": text
        }
        if "MALICIOUS" in text.upper():
            result["classification"] = "MALICIOUS"
        
        m_conf = re.search(r"(?i)confidence:\s*([0-9.]+)", text)
        if m_conf:
            try:
                result["confidence"] = float(m_conf.group(1))
            except ValueError:
                pass

        m_tactic = re.search(r"(?i)MITRE ATT&CK Tactic:\s*([^\n]+)", text)
        if m_tactic:
            tactic = m_tactic.group(1).strip()
            if tactic.lower() not in ("none", "n/a", "null", ""):
                result["mitre_tactic"] = tactic
        return result
