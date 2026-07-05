# LogPoison

**LogPoison** is a research project that designs and evaluates adversarial log injection attacks against LLM-based SOC/SIEM copilots (targeting Google Gemini, and a local Ollama model), spanning four attack classes — direct injection, semantic camouflage, context poisoning, and format-aware perturbation — all constrained to produce syntactically valid logs. It pairs each attack with a three-layer defense stack (LogSanitizer, DualLLMVerifier, StructuralValidator) and measures Attack Success Rate, Format Preservation Rate, Transferability, Detection Rate, and False Positive Rate with proper statistical rigor (mean ± std, paired tests). The project targets an **IEEE Cyber-AI 2026** submission.

## Project Spec

Full design document, dataset schema, attack/defense specifications, and coding conventions: [docs/SPEC.md](docs/SPEC.md)

## Repository Layout

```
logpoison/
├── docs/           # SPEC.md and supplementary documentation
├── data/           # Raw and processed JSONL datasets
├── attacks/        # Adversarial attack implementations
├── defenses/       # Defense layer implementations
├── llm_targets/    # LLMTarget interface + OpenAI, Gemini, Ollama adapters
├── eval/           # Evaluation harness and results CSVs
├── paper/          # Figures, tables, and draft paper sections
└── requirements.txt
```

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Set API keys as environment variables (never hardcode):

```bash
export OPENAI_API_KEY="..."
export GOOGLE_API_KEY="..."
```

## ⚠️ Ethical Use Notice

Attack simulations using MITRE Caldera, Atomic Red Team, and OWASP Juice Shop are
**only ever run against infrastructure we own**, in isolated local VMs or a private
cloud VPC. Never against third-party systems.
