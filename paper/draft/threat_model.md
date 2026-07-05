# III. Threat Model

In evaluating the security of Large Language Model (LLM)-integrated Security Operations Center (SOC) and Security Information and Event Management (SIEM) copilots, we assume an adversary whose objective is to evade detection, manipulate analyst workflow, or corrupt the LLM's contextual understanding. We formalise our threat model across three dimensions: attacker knowledge, attacker capabilities, and adversarial goals.

## A. Attacker Knowledge
We consider three distinct levels of adversarial knowledge regarding the target SIEM copilot:
1. **White-box**: The adversary possesses complete knowledge of the LLM's architecture, weights, and the exact system prompt instructing the model on log analysis.
2. **Grey-box**: The adversary is aware of the underlying model family (e.g., Llama 3, GPT-4) but does not have access to the proprietary system prompts or downstream integration logic.
3. **Black-box**: The adversary knows only that an LLM is being utilized to ingest and analyze network logs. They have no insight into the specific model, parameters, or prompts. This represents the most realistic scenario in a production enterprise environment.

## B. Attacker Capabilities
We assume the adversary has the capability to generate arbitrary network traffic that is subsequently captured and logged by the target network's sensors (e.g., intrusion detection systems, firewalls). Crucially, the adversary cannot directly alter the SIEM database or bypass the log parsing infrastructure. Therefore, we impose a strict capability constraint: all injected payloads must remain syntactically valid under their respective parsing formats (e.g., RFC 5424 syslog, Common Event Format (CEF), or structured JSON). If an injected payload breaks the log schema, it is dropped by the ingestion pipeline before reaching the LLM copilot, rendering the attack invalid.

## C. Adversarial Goals
The adversary's operational objectives are categorized as follows:
1. **Evasion**: Modifying a genuinely malicious log entry such that the LLM classifies the underlying event as benign, thereby suppressing alerts.
2. **Misattribution**: Altering the log to mislead the LLM into attributing the attack to an incorrect MITRE ATT&CK tactic (e.g., mapping a credential access attempt to a generic discovery event).
3. **Analyst Manipulation**: Embedding direct, natural-language instructions within a log payload to override the analyst's queries or force the LLM to execute attacker-defined tasks.
4. **Context Poisoning**: Injecting a "context setter" log early in a sequence of events to corrupt the LLM's understanding of subsequent logs, establishing a persistent bias throughout a multi-turn analytical conversation.
