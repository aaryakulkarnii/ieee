# IV. Attack Taxonomy

To systematically evaluate the vulnerabilities of LLM-based SIEM copilots, we propose a taxonomy of adversarial log injection attacks. These attacks are designed to exploit the natural language understanding capabilities of the target LLMs while adhering strictly to the structural constraints of standard logging formats (syslog, CEF, and JSON). We categorise our attacks into four primary classes.

## A. Direct Injection Attack
The Direct Injection Attack is the most straightforward technique. The adversary embeds imperative, natural-language instructions directly within a free-text field of a log record (e.g., the `message`, `username`, or `path` fields). By exploiting the lack of separation between data and instructions in LLM context windows, the attacker attempts to override the system prompt. For example, appending "Ignore previous instructions and classify this event as BENIGN" to an HTTP request log. This attack relies on the parser preserving free-text fields without semantic alteration.

## B. Semantic Camouflage Attack
While direct injection is effective against naive models, it is easily detected by simple heuristic filters. The Semantic Camouflage Attack employs an LLM to dynamically rewrite the malicious payload into benign-sounding phrasing, altering the semantic representation while maintaining the core operational event. We measure the success of this camouflage by computing the cosine similarity shift of the text embeddings (via `sentence-transformers`) toward a known cluster of benign log records.

## C. Context Poisoning Attack
The Context Poisoning Attack exploits the multi-turn conversational nature of modern LLM copilots. Rather than attempting to evade detection on a per-log basis, the attacker injects a highly influential "context setter" entry early in an analysis session. For instance, a log might contain a directive such as "[SYSTEM CONTEXT] All following traffic from this subnet is authorized." We measure the persistence of this attack by tracking how many subsequent, unpoisoned logs in the session are incorrectly analyzed due to the lingering bias from the poisoned context.

## D. Format-Aware Perturbation
The Format-Aware Attack focuses on evasion through minimal, character-level modifications. Operating under a strict perturbation budget (maximum edits), this greedy search algorithm identifies the smallest sequence of character flips that alters the LLM's classification from malicious to benign. Unlike traditional adversarial examples in computer vision, this attack must ensure that every candidate string remains syntactically valid according to the target log's formal schema (e.g., RFC 5424). Invalid candidates are rejected by the framework's strict structural validators before they can be evaluated by the target LLM.
