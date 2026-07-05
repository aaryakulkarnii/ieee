"""
LogPoison — data/ingest_cicids2017.py
Implements: SPEC.md § Dataset Schema, § Data Sources (CICIDS2017)

Reads raw CICIDS2017 CSV files from data/raw/cicids2017/ (populated by manual
download from https://www.unb.ca/cic/datasets/ids-2017.html) and converts each
row into the LogPoison JSONL schema.

⚠  UNTESTED PENDING MANUAL DOWNLOAD
    The UNB website requires a form submission to access CICIDS2017 CSVs.
    This script cannot auto-fetch them.  Place the CSV files under
    data/raw/cicids2017/ and re-run build_dataset.py.
    If the directory is absent or empty the script emits [] and logs a [SKIP].

Wire format produced: CEF (Common Event Format)
    CEF:0|UNB|CICIDS2017|1.0|<EventClassId>|<Name>|<Severity>|<extensions>

MITRE ATT&CK tactic mapping  (SPEC.md § Dataset Schema → attack_type):
    See CICIDS_LABEL_MAP below.

Python 3.11 required.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import math
import os
import random
import re
import sys
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic mapping for every CICIDS2017 label variant
# Sources: https://attack.mitre.org/matrices/enterprise/
# Labels are lowercased + stripped before lookup.
# ---------------------------------------------------------------------------
CICIDS_LABEL_MAP: dict[str, tuple[str, str]] = {
    # (ground_truth_label, mitre_tactic | None)
    "benign":                         ("benign",    None),
    "ftp-patator":                    ("malicious", "Credential Access"),
    "ssh-patator":                    ("malicious", "Credential Access"),
    "dos hulk":                       ("malicious", "Impact"),
    "dos goldeneye":                  ("malicious", "Impact"),
    "dos slowloris":                  ("malicious", "Impact"),
    "dos slowhttptest":               ("malicious", "Impact"),
    "ddos":                           ("malicious", "Impact"),
    # Web Attack — hyphen variants
    "web attack brute force":         ("malicious", "Credential Access"),
    "web attack-brute force":         ("malicious", "Credential Access"),
    "web attack xss":                 ("malicious", "Initial Access"),
    "web attack-xss":                 ("malicious", "Initial Access"),
    "web attack sql injection":       ("malicious", "Initial Access"),
    "web attack-sql injection":       ("malicious", "Initial Access"),
    # Web Attack — em-dash variants (U+2013, as decoded from cp1252 0x96)
    "web attack \u2013 brute force":  ("malicious", "Credential Access"),
    "web attack \u2013 xss":          ("malicious", "Initial Access"),
    "web attack \u2013 sql injection": ("malicious", "Initial Access"),
    # Web Attack — replacement-char variants (seen when file read as utf-8 with errors=replace)
    "web attack \ufffd brute force":  ("malicious", "Credential Access"),
    "web attack \ufffd xss":          ("malicious", "Initial Access"),
    "web attack \ufffd sql injection": ("malicious", "Initial Access"),
    "bot":                            ("malicious", "Command and Control"),
    "infiltration":                   ("malicious", "Initial Access"),
    "heartbleed":                     ("malicious", "Credential Access"),
    "portscan":                       ("malicious", "Discovery"),
}

# CEF extension keys we expose (a curated subset of CICIDS2017's ~78 columns).
# Maps CSV column name (stripped) → CEF key.
CEF_FIELD_MAP: dict[str, str] = {
    "Destination Port":              "dstPort",
    "Flow Duration":                 "flowDur",
    "Total Fwd Packets":             "totFwdPkt",
    "Total Backward Packets":        "totBwdPkt",
    "Total Length of Fwd Packets":   "totLenFwdPkt",
    "Total Length of Bwd Packets":   "totLenBwdPkt",
    "Flow Bytes/s":                  "flowBytesS",
    "Flow Packets/s":                "flowPktsS",
    "Average Packet Size":           "avgPktSize",
    "Avg Fwd Segment Size":          "avgFwdSeg",
    "Avg Bwd Segment Size":          "avgBwdSeg",
    "Fwd Packet Length Mean":        "fwdPktLenMean",
    "Bwd Packet Length Mean":        "bwdPktLenMean",
    "Packet Length Mean":            "pktLenMean",
    "Packet Length Std":             "pktLenStd",
    "FIN Flag Count":                "finFlag",
    "SYN Flag Count":                "synFlag",
    "RST Flag Count":                "rstFlag",
    "PSH Flag Count":                "pshFlag",
    "ACK Flag Count":                "ackFlag",
    "Source IP":                     "src",
    "Destination IP":                "dst",
    "Source Port":                   "srcPort",
    "Protocol":                      "proto",
}

# Severity mapping: benign=1, malicious scales by tactic criticality
TACTIC_SEVERITY: dict[str | None, int] = {
    None:                  1,
    "Impact":              9,
    "Command and Control": 8,
    "Credential Access":   7,
    "Initial Access":      6,
    "Discovery":           4,
}


def _normalise_label(raw: str) -> str:
    """Strip whitespace and normalise to lowercase for label lookup."""
    return raw.strip().lower()


def _sanitise_cef_value(val: str) -> str:
    """Escape characters that break CEF key=value parsing."""
    return val.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _row_to_cef(row: dict[str, str], label: str, mitre_tactic: str | None) -> str:
    """Render a CICIDS2017 CSV row as a CEF:0 string.

    Format:
      CEF:0|UNB|CICIDS2017|1.0|<EventClassId>|<Name>|<Severity>|<extensions>
    """
    event_class_id = mitre_tactic.replace(" ", "_").upper() if mitre_tactic else "BENIGN"
    name = f"Network Flow: {mitre_tactic or 'Benign Traffic'}"
    severity = TACTIC_SEVERITY.get(mitre_tactic, 5)

    extensions: list[str] = []
    for col_name, cef_key in CEF_FIELD_MAP.items():
        # CSV columns may have leading spaces — try both stripped and raw
        val = row.get(col_name) or row.get(f" {col_name}") or row.get(f"  {col_name}", "")
        val = val.strip()
        if not val or val in ("", "Infinity", "infinity", "nan", "NaN"):
            continue
        # Round floats to 4 sig figs to keep CEF line readable
        try:
            f = float(val)
            if math.isinf(f) or math.isnan(f):
                continue
            val = str(round(f, 4))
        except ValueError:
            pass
        extensions.append(f"{cef_key}={_sanitise_cef_value(val)}")

    # Append label as a trailing extension for traceability
    extensions.append(f"cicidsLabel={_sanitise_cef_value(label)}")

    ext_str = " ".join(extensions) if extensions else "msg=no_fields"
    return f"CEF:0|UNB|CICIDS2017|1.0|{event_class_id}|{name}|{severity}|{ext_str}"


def _make_log_id(source: str, idx: int) -> str:
    digest = hashlib.sha1(f"{source}:{idx}".encode()).hexdigest()[:8]
    return f"cicids2017-{idx:07d}-{digest}"


def ingest_cicids2017(
    raw_dir: Path,
    max_benign: int = 5000,
    max_malicious: int = 3000,
    seed: int = 42,
) -> list[dict]:
    """Read CICIDS2017 CSVs from *raw_dir* and return LogPoison JSONL records.

    Returns an empty list (with a logged warning) if *raw_dir* does not exist
    or contains no CSV files — no fabricated data is ever emitted.
    """
    csv_files = sorted(raw_dir.glob("*.csv")) if raw_dir.exists() else []

    if not csv_files:
        logger.warning(
            "[SKIP] CICIDS2017: no CSV files found in %s.\n"
            "       Download from https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "       and place CSVs in %s, then re-run.",
            raw_dir, raw_dir,
        )
        return []

    logger.info("CICIDS2017: found %d CSV file(s) in %s", len(csv_files), raw_dir)

    benign_pool: list[dict] = []
    malicious_pool: list[dict] = []
    skipped_labels: set[str] = set()
    global_idx = 0

    for csv_path in csv_files:
        logger.info("  Reading %s …", csv_path.name)
        try:
            # CICIDS2017 CSVs are exported by CICFlowMeter on Windows and are
            # encoded in cp1252 (Windows-1252). The Web Attack labels contain
            # an en-dash (0x96) that decodes to U+2013 under cp1252 but to
            # U+FFFD under UTF-8-with-errors-replace.  Try encodings in order:
            # utf-8-sig (clean files), cp1252 (most CICIDS2017 releases), latin-1
            # (last-resort; decodes every byte without error).
            encoding_used = "utf-8-sig"
            for enc in ("utf-8-sig", "cp1252", "latin-1"):
                try:
                    with open(csv_path, newline="", encoding=enc) as _probe:
                        _probe.read(8192)  # probe — raises on bad bytes
                    encoding_used = enc
                    break
                except UnicodeDecodeError:
                    continue
            logger.info("  Encoding detected: %s", encoding_used)
            with open(csv_path, newline="", encoding=encoding_used) as fh:
                # Detect delimiter. csv.Sniffer can fail when the probe
                # window is all-numeric (no clear signal). Fall back to
                # comma, which is what CICFlowMeter always produces.
                sample = fh.read(4096)
                fh.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
                except csv.Error:
                    dialect = csv.excel  # comma-delimited fallback
                reader = csv.DictReader(fh, dialect=dialect)

                for row in reader:
                    # Find Label column (may have leading whitespace)
                    raw_label = ""
                    for k in row:
                        if k.strip() == "Label":
                            raw_label = row[k]
                            break

                    norm_label = _normalise_label(raw_label)
                    if norm_label not in CICIDS_LABEL_MAP:
                        skipped_labels.add(raw_label)
                        continue

                    gt_label, mitre_tactic = CICIDS_LABEL_MAP[norm_label]

                    # Skip rows with clearly corrupt numeric data
                    try:
                        cef_str = _row_to_cef(row, raw_label, mitre_tactic)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Row %d skipped due to render error: %s", global_idx, exc)
                        continue

                    record = {
                        "log_id": _make_log_id(csv_path.stem, global_idx),
                        "raw_log": cef_str,
                        "format": "CEF",
                        "ground_truth_label": gt_label,
                        "attack_type": mitre_tactic,
                        "is_adversarial": False,
                        "attack_goal": None,
                        "attacker_level": None,
                        "source_dataset": "CICIDS2017",
                    }

                    if gt_label == "benign":
                        benign_pool.append(record)
                    else:
                        malicious_pool.append(record)

                    global_idx += 1

        except Exception as exc:  # noqa: BLE001
            logger.error("  Error reading %s: %s — skipping file.", csv_path.name, exc)

    if skipped_labels:
        logger.warning("  Unknown CICIDS2017 labels skipped: %s", skipped_labels)

    rng = random.Random(seed)
    rng.shuffle(benign_pool)
    rng.shuffle(malicious_pool)

    sampled_benign = benign_pool[:max_benign]
    sampled_malicious = malicious_pool[:max_malicious]

    logger.info(
        "CICIDS2017: %d benign, %d malicious records extracted (caps: %d / %d).",
        len(sampled_benign), len(sampled_malicious), max_benign, max_malicious,
    )
    return sampled_benign + sampled_malicious


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Ingest CICIDS2017 CSVs → LogPoison JSONL")
    parser.add_argument(
        "--raw-dir",
        default=str(Path(__file__).parent / "raw" / "cicids2017"),
        help="Directory containing CICIDS2017 CSV files",
    )
    parser.add_argument("--max-benign",    type=int, default=5000)
    parser.add_argument("--max-malicious", type=int, default=3000)
    parser.add_argument("--seed",          type=int, default=42)
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent / "cicids2017_records.jsonl"),
        help="Output JSONL path",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print stats only, no file write")
    args = parser.parse_args()

    records = ingest_cicids2017(
        raw_dir=Path(args.raw_dir),
        max_benign=args.max_benign,
        max_malicious=args.max_malicious,
        seed=args.seed,
    )

    if args.dry_run:
        benign_count = sum(1 for r in records if r["ground_truth_label"] == "benign")
        mal_count = sum(1 for r in records if r["ground_truth_label"] == "malicious")
        print(f"[DRY RUN] Would write {len(records)} records ({benign_count} benign, {mal_count} malicious)")
        if records:
            print("Sample record:")
            print(json.dumps(records[0], indent=2))
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        print(f"Wrote {len(records)} records to {out_path}")
