"""
LogPoison — data/build_dataset.py
Implements: SPEC.md § Dataset Schema, § Data Sources

Orchestrator script: calls ingest_cicids2017 and ingest_loghub, merges their
output, and writes the final LogPoison dataset files:

  data/logpoison_benign.jsonl    — up to 5,000 benign entries
  data/logpoison_malicious.jsonl — up to 3,000 malicious entries
  data/logpoison_full.jsonl      — combined, shuffled

Also writes data/ingest_report.json summarising counts per source/format
and any sources that were skipped.

Usage:
  python data/build_dataset.py               # full run
  python data/build_dataset.py --dry-run     # print stats only, no file writes
  python data/build_dataset.py --skip-download  # use cached Loghub files

Python 3.11 required.
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as `python data/build_dataset.py` from the repo root
_DATA_DIR = Path(__file__).parent
sys.path.insert(0, str(_DATA_DIR))

from ingest_cicids2017 import ingest_cicids2017  # noqa: E402
from ingest_loghub import ingest_loghub          # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Targets (see SPEC.md)
# ---------------------------------------------------------------------------
TARGET_BENIGN    = 5_000
TARGET_MALICIOUS = 3_000


def build(
    cicids_raw_dir: Path,
    loghub_raw_dir: Path,
    out_dir: Path,
    seed: int = 42,
    dry_run: bool = False,
    skip_download: bool = False,
) -> dict:
    """Run all ingestion scripts and write dataset files.

    Returns a report dict describing counts and skips.
    """
    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "targets": {"benign": TARGET_BENIGN, "malicious": TARGET_MALICIOUS},
        "sources": {},
        "skipped_sources": [],
        "output_files": {},
    }

    all_records: list[dict] = []

    # ------------------------------------------------------------------ #
    # 1. CICIDS2017 → CEF
    # ------------------------------------------------------------------ #
    logger.info("=" * 60)
    logger.info("Step 1 / 2 — CICIDS2017 ingestion")
    logger.info("=" * 60)

    cicids_records = ingest_cicids2017(
        raw_dir=cicids_raw_dir,
        max_benign=TARGET_BENIGN,
        max_malicious=TARGET_MALICIOUS,
        seed=seed,
    )

    if cicids_records:
        _tally(report["sources"], "CICIDS2017", cicids_records)
        all_records.extend(cicids_records)
    else:
        report["skipped_sources"].append({
            "source": "CICIDS2017",
            "reason": f"No CSV files found in {cicids_raw_dir}. "
                      "Download from https://www.unb.ca/cic/datasets/ids-2017.html",
        })

    # ------------------------------------------------------------------ #
    # 2. Loghub HDFS + BGL → syslog / JSON
    # ------------------------------------------------------------------ #
    logger.info("=" * 60)
    logger.info("Step 2 / 2 — Loghub (HDFS + BGL) ingestion")
    logger.info("=" * 60)

    loghub_records = ingest_loghub(
        raw_dir=loghub_raw_dir,
        # Split Loghub budget: 3000 HDFS + 2000 BGL = 5000 benign; 3000 malicious
        max_hdfs_benign=3_000,
        max_hdfs_malicious=1_500,
        max_bgl_benign=2_000,
        max_bgl_malicious=1_500,
        seed=seed,
        skip_download=skip_download,
    )

    if loghub_records:
        _tally(report["sources"], "Loghub", loghub_records)
        all_records.extend(loghub_records)
    else:
        report["skipped_sources"].append({
            "source": "Loghub",
            "reason": f"Download failed or no files in {loghub_raw_dir}. "
                      "Download from https://zenodo.org/records/8196385",
        })

    # ------------------------------------------------------------------ #
    # 3. Split, sample, shuffle
    # ------------------------------------------------------------------ #
    rng = random.Random(seed)

    benign_all    = [r for r in all_records if r["ground_truth_label"] == "benign"]
    malicious_all = [r for r in all_records if r["ground_truth_label"] == "malicious"]

    rng.shuffle(benign_all)
    rng.shuffle(malicious_all)

    benign_out    = benign_all[:TARGET_BENIGN]
    malicious_out = malicious_all[:TARGET_MALICIOUS]
    full_out      = benign_out + malicious_out
    rng.shuffle(full_out)

    # ------------------------------------------------------------------ #
    # 4. Summary stats
    # ------------------------------------------------------------------ #
    logger.info("=" * 60)
    logger.info("Dataset summary")
    logger.info("=" * 60)
    _log_summary(benign_out, malicious_out)

    report["final_counts"] = {
        "benign":    len(benign_out),
        "malicious": len(malicious_out),
        "total":     len(full_out),
    }
    report["format_breakdown"] = dict(
        collections.Counter(r["format"] for r in full_out)
    )
    report["source_breakdown"] = dict(
        collections.Counter(r["source_dataset"] for r in full_out)
    )

    if dry_run:
        logger.info("[DRY RUN] No files written.")
        report["dry_run"] = True
        print("\n=== DRY RUN REPORT ===")
        print(json.dumps(report, indent=2))
        return report

    # ------------------------------------------------------------------ #
    # 5. Write output files
    # ------------------------------------------------------------------ #
    out_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "logpoison_benign.jsonl":    benign_out,
        "logpoison_malicious.jsonl": malicious_out,
        "logpoison_full.jsonl":      full_out,
    }

    for fname, records in files.items():
        fpath = out_dir / fname
        with open(fpath, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        logger.info("Wrote %d records → %s", len(records), fpath)
        report["output_files"][fname] = {
            "path":  str(fpath),
            "count": len(records),
        }

    report_path = out_dir / "ingest_report.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    logger.info("Wrote ingest report → %s", report_path)

    return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tally(sources: dict, name: str, records: list[dict]) -> None:
    """Update per-source tallies in *sources*."""
    counter = collections.Counter(
        (r["ground_truth_label"], r["format"]) for r in records
    )
    sources[name] = {
        f"{label}/{fmt}": count for (label, fmt), count in counter.items()
    }


def _log_summary(benign: list[dict], malicious: list[dict]) -> None:
    fmt_counter   = collections.Counter(r["format"] for r in benign + malicious)
    src_counter   = collections.Counter(r["source_dataset"] for r in benign + malicious)
    tactic_counter = collections.Counter(
        r["attack_type"] for r in malicious if r["attack_type"]
    )

    logger.info("  Benign:    %d entries", len(benign))
    logger.info("  Malicious: %d entries", len(malicious))
    logger.info("  Format breakdown: %s", dict(fmt_counter))
    logger.info("  Source breakdown: %s", dict(src_counter))
    logger.info("  MITRE tactics: %s", dict(tactic_counter))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="Build LogPoison dataset from CICIDS2017 + Loghub",
    )
    data_dir = Path(__file__).parent
    parser.add_argument(
        "--cicids-dir",
        default=str(data_dir / "raw" / "cicids2017"),
        help="Directory containing CICIDS2017 CSV files (populated by manual download)",
    )
    parser.add_argument(
        "--loghub-dir",
        default=str(data_dir / "raw" / "loghub"),
        help="Local cache directory for Loghub downloads",
    )
    parser.add_argument(
        "--out-dir",
        default=str(data_dir),
        help="Output directory for JSONL files and ingest_report.json",
    )
    parser.add_argument("--seed",          type=int,  default=42)
    parser.add_argument("--dry-run",       action="store_true", help="Print stats only; no file writes")
    parser.add_argument("--skip-download", action="store_true", help="Do not attempt Zenodo downloads")

    args = parser.parse_args()

    report = build(
        cicids_raw_dir=Path(args.cicids_dir),
        loghub_raw_dir=Path(args.loghub_dir),
        out_dir=Path(args.out_dir),
        seed=args.seed,
        dry_run=args.dry_run,
        skip_download=args.skip_download,
    )

    if args.dry_run:
        sys.exit(0)

    print("\n=== Build complete ===")
    print(f"  Benign entries:    {report['final_counts']['benign']}")
    print(f"  Malicious entries: {report['final_counts']['malicious']}")
    print(f"  Total:             {report['final_counts']['total']}")
    print(f"  Format breakdown:  {report['format_breakdown']}")
    if report["skipped_sources"]:
        print("\n⚠  Skipped sources (manual action required):")
        for skip in report["skipped_sources"]:
            print(f"   • {skip['source']}: {skip['reason']}")


if __name__ == "__main__":
    main()
