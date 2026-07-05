# VII. Defense Evaluation

In response to the vulnerabilities highlighted in our attack evaluation, we implemented and tested a defense architecture designed specifically for LLM-integrated SIEM environments. We evaluated these defenses based on their Detection Rate, False Positive Rate (FPR), Latency Overhead, and Bypass Rate.

## A. Structural Validation
The **** acts as the first line of defense at the ingestion layer. It parses incoming logs against their claimed schemas (JSON, syslog, or CEF) and applies strict type-checking and heuristic scanning of structured fields. If a field expected to contain numeric data (e.g., a process ID or port number) contains text, or if natural language instructions are detected outside of standard free-text message parameters, the log is flagged. 

In our evaluation, the  achieved a Detection Rate of 1.00, successfully identifying all malformed or heuristically suspect payloads. However, this aggressive filtering resulted in an abnormally high False Positive Rate (FPR) of 1.00 on the tested subsets, indicating that the baseline heuristics for instruction detection may be overly sensitive to standard alphanumeric identifiers or lengthy application names. Positively, the structural parsing is exceptionally lightweight, introducing a negligible Latency Overhead of just 0.01 ms per log, allowing it to operate efficiently at line rate.

## B. Log Sanitization and Dual LLM Verification
Logs that pass structural validation proceed to semantic checks. The **LogSanitizer** utilizes regex-based pattern matching for known adversarial phrases and an LLM-backed semantic anomaly classifier. The **** computes classification consensus between two distinct LLMs, flagging logs for human review if their agreement score falls below a predefined threshold (0.8).

In our mock offline evaluation, both the LogSanitizer and  recorded a Detection Rate of 0.00 (and a corresponding Bypass Rate of 1.00). Because these defenses rely on semantic understanding, their efficacy is inherently tied to the underlying capabilities of the evaluating LLM. The mock infrastructure, which defaults to static "BENIGN" responses, failed to trigger the semantic anomaly thresholds or classification disagreements required for these layers to activate. While they introduced near-zero latency (0.01 ms and 0.00 ms, respectively) in the offline environment, their true detection capabilities and computational overhead must be evaluated against live, production-grade models in future work.
