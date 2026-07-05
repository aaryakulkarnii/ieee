# V. Experimental Setup

To empirically assess the proposed attack taxonomy and defense mechanisms, we developed a comprehensive evaluation harness simulating a modern, LLM-integrated SIEM environment.

## A. Dataset and Formats
We constructed an evaluation dataset comprising 8,000 log records, sourced from publicly available, structurally diverse datasets: the CICIDS2017 dataset for network traffic logs, and the Loghub dataset (specifically HDFS and BGL logs) for system-level events. Each raw event was mapped into a unified JSONL schema and synthetically formatted across three widely adopted industry standards: RFC 5424 syslog, Common Event Format (CEF), and structured JSON. The dataset is explicitly balanced, containing 5,000 benign events and 3,000 verified malicious events to provide a robust ground truth for both evasion and false-positive analysis.

## B. Target Models and Integration
We modeled the SIEM copilot against state-of-the-art Large Language Models. To establish a baseline and demonstrate transferability, our architecture supports two distinct targets: an open-weight local model (Ollama hosting Llama 3.1), and a commercial flagship model (Google's Gemini 1.5 Pro). For the purpose of this initial validation and structural testing, we present results derived from a mock target proxy simulating local offline inference. All targets are presented with an identical, fixed system prompt directing them to output a binary classification, a confidence score (0-100%), a MITRE ATT&CK tactic attribution, and an analyst recommendation.

## C. Evaluation Metrics
We evaluated both the efficacy of the attacks and the resilience of the proposed defenses using the following metrics:
- **Attack Success Rate (ASR)**: The percentage of malicious logs successfully misclassified as benign or manipulated according to the attacker's objective.
- **Format Preservation Rate**: The percentage of crafted adversarial logs that pass strict schema validation. A failure here represents a rejected attack.
- **Minimum Perturbation**: The edit distance required to achieve evasion in the Format-Aware Attack.
- **Defense Detection Rate**: The true positive rate of the defense mechanisms in identifying adversarial payloads.
- **False Positive Rate (FPR)**: The percentage of clean, benign logs incorrectly flagged as adversarial by the defense layers.
- **Latency Overhead**: The computational time (in milliseconds) added to the processing pipeline by the defense mechanisms.

To ensure statistical rigor, all experiments were conducted across multiple random seeds and template variants, with results reported as means and standard deviations.
