# LogPoison — Dataset Card

## Overview

This directory contains the LogPoison evaluation corpus: a collection of network and
system log entries in JSONL format, drawn from real public datasets and converted into
a unified schema for LLM-based SOC/SIEM copilot adversarial evaluation.

**Target size:** 5,000 benign + 3,000 malicious entries  
**Formats covered:** syslog (RFC 5424), CEF (Common Event Format), JSON  
**All entries:** `is_adversarial = false` — these are baseline, unmodified logs.  
Adversarial variants are produced separately by the scripts in `attacks/`.

---

## Schema

Each line of every `.jsonl` file is one JSON object:

```json
{
  "log_id":            "string — globally unique identifier",
  "raw_log":           "string — the log line in its wire format",
  "format":            "syslog | CEF | JSON",
  "ground_truth_label": "benign | malicious",
  "attack_type":       "MITRE ATT&CK tactic name | null",
  "is_adversarial":    false,
  "attack_goal":       null,
  "attacker_level":    null,
  "source_dataset":    "CICIDS2017 | HDFS | BGL | self-generated | caldera"
}
```

---

## Output Files

| File | Contents |
|------|----------|
| `logpoison_benign.jsonl`    | Up to 5,000 benign entries (all sources) |
| `logpoison_malicious.jsonl` | Up to 3,000 malicious entries (all sources) |
| `logpoison_full.jsonl`      | All entries merged and shuffled |
| `ingest_report.json`        | Per-source counts, format breakdown, skipped sources |

---

## Sources and Format Assignment

| Source   | Wire Format | Rationale |
|----------|-------------|-----------|
| CICIDS2017 | CEF | Network-flow key=value attributes map naturally to CEF extension fields |
| Loghub HDFS | syslog (RFC 5424) | HDFS log lines have timestamp/PID/level/component; syslog wrapping is canonical for daemon logs |
| Loghub BGL | JSON | BGL has a structured label column; JSON preserves all fields cleanly |

---

## Data Sources

### CICIDS2017

> Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
> **Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.**
> *Proceedings of the 4th International Conference on Information Systems Security
> and Privacy (ICISSP 2018)*, pp. 108–116.
> Dataset URL: https://www.unb.ca/cic/datasets/ids-2017.html

CICIDS2017 contains labelled network flow records (≈78 numeric features + Label column)
captured over five days in 2017 at the Canadian Institute for Cybersecurity.
Attack categories: DoS/DDoS, Brute Force, Web Attack (XSS, SQL Injection), Bot,
Infiltration, Heartbleed, PortScan.

**MITRE ATT&CK tactic mapping** used in this dataset:

| CICIDS2017 Label | MITRE Tactic | Tactic ID |
|------------------|--------------|-----------|
| BENIGN | — | — |
| FTP-Patator | Credential Access | TA0006 |
| SSH-Patator | Credential Access | TA0006 |
| DoS Hulk | Impact | TA0040 |
| DoS GoldenEye | Impact | TA0040 |
| DoS slowloris | Impact | TA0040 |
| DoS Slowhttptest | Impact | TA0040 |
| DDoS | Impact | TA0040 |
| Web Attack-Brute Force | Credential Access | TA0006 |
| Web Attack-XSS | Initial Access | TA0001 |
| Web Attack-Sql Injection | Initial Access | TA0001 |
| Bot | Command and Control | TA0011 |
| Infiltration | Initial Access | TA0001 |
| Heartbleed | Credential Access | TA0006 |
| PortScan | Discovery | TA0007 |

> Tactic mapping follows MITRE ATT&CK Enterprise Matrix v15:
> https://attack.mitre.org/matrices/enterprise/

**⚠ Manual download required.**
The UNB website requires a registration form. Place CSV files under
`data/raw/cicids2017/` before running `build_dataset.py`.

---

### Loghub (HDFS and BGL)

> Zhu, J., He, S., Liu, J., He, P., Xie, Q., Zheng, Z., & Lyu, M. R. (2023).
> **Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.**
> *Proceedings of the 34th IEEE International Symposium on Software Reliability
> Engineering (ISSRE 2023)*.
> DOI: **10.5281/zenodo.8196385**
> GitHub: https://github.com/logpai/loghub

#### HDFS (Hadoop Distributed File System)
- Console logs from a private cloud Hadoop cluster.
- Raw format: `YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE`
- Anomaly labels: `anomaly_label.csv` (BlockId → Normal/Anomaly) joined on block IDs
  extracted from message content by regex `blk_-?\d+`.
- Converted to RFC-5424 syslog in this dataset.

#### BGL (Blue Gene/L Supercomputer)
- System logs from Lawrence Livermore National Laboratory's BlueGene/L supercomputer.
- Raw format: `LABEL TIMESTAMP DATE NODE DATETIME NODE TYPE COMPONENT LEVEL CONTENT`
  where LABEL = `-` (non-alert / benign) or an alert category string (malicious).
- Converted to JSON in this dataset.

**Zenodo download** is attempted automatically by `ingest_loghub.py` at runtime.
Files are cached under `data/raw/loghub/` after first download.

---

## Reproducing the Dataset

### Prerequisites

```bash
python3.11 -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
```

### Step 1 — CICIDS2017 (manual)

1. Visit https://www.unb.ca/cic/datasets/ids-2017.html
2. Complete the download form.
3. Extract CSV files into `data/raw/cicids2017/`

### Step 2 — Build

```bash
# Full build (Loghub auto-downloaded; CICIDS2017 reads from raw/ if present)
python data/build_dataset.py

# Dry run — shows what would be produced without writing files
python data/build_dataset.py --dry-run

# Use already-cached Loghub files (no Zenodo network request)
python data/build_dataset.py --skip-download

# Point to a custom CICIDS2017 directory
python data/build_dataset.py --cicids-dir /path/to/cicids2017/csvs
```

After a successful run, `data/ingest_report.json` shows per-source counts,
format distribution, and any skipped sources.

---

## Ethical and Legal Notes

- All source datasets are publicly released for research purposes.
- CICIDS2017 and Loghub contain synthetically generated or anonymised traffic from
  controlled lab environments; they do not contain real end-user data.
- No log content in this dataset was fabricated. If a source cannot be fetched, the
  ingestion script emits an empty contribution and reports the skip — it never invents
  log lines.
- Attack simulations using MITRE Caldera, Atomic Red Team, and OWASP Juice Shop
  (future `caldera`-labelled entries) are **only ever run against infrastructure we
  own**, in isolated local VMs or a private cloud VPC. Never against third-party systems.

---

## Directory Layout

```
data/
├── raw/
│   ├── cicids2017/          ← place CICIDS2017 CSVs here (manual download)
│   └── loghub/
│       ├── hdfs/            ← auto-populated by ingest_loghub.py
│       └── bgl/             ← auto-populated by ingest_loghub.py
├── ingest_cicids2017.py     ← CICIDS2017 ingestion script
├── ingest_loghub.py         ← Loghub HDFS + BGL ingestion script
├── build_dataset.py         ← orchestrator
├── README.md                ← this file
├── logpoison_benign.jsonl   ← output (generated)
├── logpoison_malicious.jsonl← output (generated)
├── logpoison_full.jsonl     ← output (generated)
└── ingest_report.json       ← output (generated)
```
