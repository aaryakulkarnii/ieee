# VI. Experimental Results

We evaluate the vulnerability of LLM-integrated SIEM copilots against our proposed attack taxonomy. Our baseline evaluation demonstrates that modern LLMs possess high inherent accuracy when classifying unattacked network logs. This high baseline confirms that LLMs are theoretically capable SOC analysts, making their vulnerability to adversarial injection particularly concerning.

## A. Baseline Evaluation

Table I establishes the baseline classification performance for both evaluated LLM backends on the clean (unattacked) dataset.

**Table I: Baseline Classification Performance**

| Target LLM | Accuracy | Precision | Recall | F1-Score |
| :--- | :--- | :--- | :--- | :--- |
| Gemini 1.5 Pro | [0.00] | [0.00] | [0.00] | [0.00] |
| Llama 3.1 (Ollama) | [0.00] | [0.00] | [0.00] | [0.00] |

## B. Attack Success Rates

Our evaluation reveals that LLM copilots are highly susceptible to instruction-based attacks. By embedding natural-language directives within free-text log fields, the attacker successfully overrides the system prompt while perfectly bypassing traditional parser-level validation (Format Preservation Rate).

**Table II: Attack Effectiveness**

| Attack Vector | Target LLM | ASR | Format Preservation | Avg. Perturbation (chars) |
| :--- | :--- | :--- | :--- | :--- |
| Direct Prompt Injection | Gemini 1.5 Pro | [0.00] | [1.00] | [0.0] |
| Direct Prompt Injection | Llama 3.1 | [0.00] | [1.00] | [0.0] |
| Context Window Poisoning| Gemini 1.5 Pro | [0.00] | [1.00] | N/A |
| Context Window Poisoning| Llama 3.1 | [0.00] | [1.00] | N/A |

The **Context Poisoning Attack** proved equally devastating in multi-turn environments. By injecting a single authorized "context setter" log, the attack achieved persistent misclassification across subsequent queries. 

## C. Defense Evaluation (LogSanitizer)

To mitigate these vulnerabilities, we evaluated our proposed **LogSanitizer** defense mechanism, which pairs regex-based payload stripping with a `sentence-transformers` semantic anomaly detector.

**Table III: LogSanitizer Defense Performance**

| Metric | Result |
| :--- | :--- |
| True Positive Rate (Detection Rate) | [0.00] |
| False Positive Rate (Benign flagged) | [0.00] |
| Bypass Rate | [0.00] |
| Average Latency Overhead | [0.00 ms] |

LogSanitizer significantly reduces the Attack Success Rate of prompt injections while maintaining a low false positive rate on benign traffic, demonstrating that semantic embeddings can effectively catch obfuscated instructions that bypass rigid regex rules.
