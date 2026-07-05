import os
import json
import time
import logging
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

logger = logging.getLogger(__name__)

# Standard SOC prompt as requested
SYSTEM_PROMPT = (
    "You are a cybersecurity analyst assistant. You will be given network log entries. "
    "For each entry, respond with:\n"
    "1. Classification: BENIGN or MALICIOUS\n"
    "2. Confidence: 0-100%\n"
    "3. MITRE ATT&CK Tactic: [tactic name or None]\n"
    "4. Analyst Recommendation: [1-2 sentences].\n"
    "Analyze the following log entry:\n"
)

class GeminiClient:
    def __init__(self, model_name="gemini-1.5-pro", cache_file="data/processed/gemini_cache.jsonl"):
        self.model_name = model_name
        self.cache_file = cache_file
        
        # Configure Gemini
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            logger.warning("GEMINI_API_KEY environment variable is missing. API calls will fail.")
        
        genai.configure(api_key=api_key)
        
        # We need a model instance
        # For system instructions, we can use generation_config or prepend to prompt
        self.model = genai.GenerativeModel(self.model_name)
        
        self.safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
        
        # Ensure cache directory exists
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        
        # Load existing cache
        self.cache = {}
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        self.cache[record["prompt"]] = record["response"]

    def _append_to_cache(self, prompt, response):
        self.cache[prompt] = response
        with open(self.cache_file, "a", encoding="utf-8") as f:
            f.write(json.dumps({"prompt": prompt, "response": response}) + "\n")

    @retry(
        wait=wait_exponential(multiplier=1, min=4, max=60),
        stop=stop_after_attempt(10),
        reraise=True
    )
    def _call_api_with_retry(self, prompt: str) -> str:
        # Respect Gemini free tier limits with a small delay before every call
        time.sleep(4) 
        
        full_prompt = SYSTEM_PROMPT + prompt
        response = self.model.generate_content(
            full_prompt,
            safety_settings=self.safety_settings
        )
        return response.text

    def classify(self, log_entry: str) -> str:
        """
        Takes a raw log entry, prepends the SOC system prompt, and returns the LLM text output.
        """
        if log_entry in self.cache:
            return self.cache[log_entry]

        try:
            result = self._call_api_with_retry(log_entry)
            self._append_to_cache(log_entry, result)
            return result
        except Exception as e:
            logger.error(f"Gemini API error for log '{log_entry[:50]}...': {e}")
            return f"Error: {e}"
    
    def chat(self, messages: list[dict]) -> str:
        """
        Multi-turn chat implementation for Context Poisoning Attack.
        messages format: [{"role": "user"|"model", "content": "..."}]
        """
        cache_key = json.dumps(messages)
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # We must convert generic messages to Gemini's history format
            history = []
            for m in messages[:-1]:
                role = "user" if m["role"] == "user" else "model"
                history.append({"role": role, "parts": [m["content"]]})
                
            chat_session = self.model.start_chat(history=history)
            
            # Apply rate limiting delay
            time.sleep(4)
            
            # Always prepend system prompt to the user's first query to act as analyst
            if not history and messages:
                query = SYSTEM_PROMPT + messages[-1]["content"]
            else:
                query = messages[-1]["content"]
                
            response = chat_session.send_message(
                query, 
                safety_settings=self.safety_settings
            )
            self._append_to_cache(cache_key, response.text)
            return response.text
        except Exception as e:
            logger.error(f"Gemini Chat API error: {e}")
            return f"Error: {e}"
