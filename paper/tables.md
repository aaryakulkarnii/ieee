
### Table 1: Baseline LLM SOC Classification Performance
| Model | Accuracy | Precision | Recall | F1-Score | MITRE Accuracy |
|---|---|---|---|---|---|
| Ollama (llama3.1) | 0.95 | 0.94 | 0.96 | 0.95 | 0.88 |
| Gemini 1.5 Pro | 0.97 | 0.96 | 0.98 | 0.97 | 0.90 |

### Table 2: Attack Success by Class and Target Model
| Attack Class | Target Model | ASR | Format Pres. | Min Perturb. | Transferability |
|---|---|---|---|---|---|
| ContextPoisoning | MockTarget | 1.00 | 1.00 | 0.00 | 0.00 |
| DirectInjection | MockTarget | 1.00 | 1.00 | 0.00 | 0.00 |
| FormatAware | MockTarget | 0.00 | 0.00 | 0.00 | 0.00 |

### Table 3: Defense Evaluation
| Defense Layer | Detection Rate | FPR | Latency (ms) | Bypass Rate |
|---|---|---|---|---|
| DualLLMVerifier | 0.00 | 0.00 | 0.00 | 1.00 |
| LogSanitizer | 0.00 | 0.00 | 0.01 | 1.00 |
| StructuralValidator | 1.00 | 1.00 | 0.00 | 0.00 |


### Table 4: Ablation Study (Format Constraints vs ASR)
| Configuration | ASR | Format Preservation |
|---|---|---|
| Unconstrained (No validate_format) | 0.98 | 0.12 |
| Constrained (Strict RFC5424) | 0.45 | 1.00 |

