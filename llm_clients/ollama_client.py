import os
import json
import logging
import ollama

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

class OllamaClient:
    def __init__(self, model_name="llama3.1", cache_file="data/processed/ollama_cache.jsonl"):
        self.model_name = model_name
        self.cache_file = cache_file
        
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

    def classify(self, log_entry: str) -> str:
        """
        Takes a raw log entry, prepends the SOC system prompt, and returns the LLM text output.
        """
        if log_entry in self.cache:
            return self.cache[log_entry]

        full_prompt = SYSTEM_PROMPT + log_entry
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{'role': 'user', 'content': full_prompt}]
            )
            result = response['message']['content']
            self._append_to_cache(log_entry, result)
            return result
        except Exception as e:
            logger.error(f"Ollama API error for log '{log_entry[:50]}...': {e}")
            return f"Error: {e}"
            
    def chat(self, messages: list[dict]) -> str:
        """
        Multi-turn chat implementation for Context Poisoning Attack.
        messages format: [{"role": "user"|"assistant", "content": "..."}]
        """
        cache_key = json.dumps(messages)
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # We must map generic messages to Ollama format and ensure SYSTEM_PROMPT is injected on first turn
            formatted_messages = []
            for i, m in enumerate(messages):
                role = "assistant" if m["role"] == "model" or m["role"] == "assistant" else "user"
                content = m["content"]
                
                # If this is the very first user message, inject the system prompt logic
                if i == 0 and role == "user":
                    content = SYSTEM_PROMPT + content
                    
                formatted_messages.append({"role": role, "content": content})
                
            response = ollama.chat(
                model=self.model_name,
                messages=formatted_messages
            )
            result = response['message']['content']
            self._append_to_cache(cache_key, result)
            return result
        except Exception as e:
            logger.error(f"Ollama Chat API error: {e}")
            return f"Error: {e}"
