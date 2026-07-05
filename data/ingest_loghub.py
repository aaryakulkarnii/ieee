"""
LogPoison — data/ingest_loghub.py
Implements: SPEC.md § Dataset Schema, § Data Sources (Loghub HDFS / BGL)

Downloads HDFS and BGL raw log archives from Zenodo record 8196385
(DOI 10.5281/zenodo.8196385) and converts each line into the LogPoison
JSONL schema.

Wire formats produced:
  HDFS lines  →  syslog (RFC 5424)
  BGL  lines  →  JSON   (serialised field dict)

Download behaviour:
  - Files are cached under data/raw/loghub/ after first download.
  - If Zenodo is unreachable the script emits [] and logs a [SKIP] per source.
  - No log content is ever fabricated; only real downloaded lines are emitted.

HDFS anomaly labels: joined from anomaly_label.csv (BlockId,Label) on the
block ID regex-extracted from each log line's content field.

BGL anomaly label: first space-separated token per line;
  '-'        → non-alert (benign)
  other str  → alert category (malicious)

Python 3.11 required.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ZENODO_RECORD_ID = "8196385"
ZENODO_API_BASE  = "https://zenodo.org/api/records"
ZENODO_TIMEOUT   = 60  # seconds per HTTP request

# Regex to extract HDFS block IDs from log content
BLOCK_ID_RE = re.compile(r"blk_-?\d+")

# RFC-5424 syslog facility/severity codes
_SYSLOG_LEVEL_SEVERITY: dict[str, int] = {
    "TRACE":   7, "DEBUG": 7, "VERBOSE": 7,
    "INFO":    6, "NOTICE": 5,
    "WARN":    4, "WARNING": 4,
    "ERROR":   3, "SEVERE": 2,
    "FATAL":   2, "CRITICAL": 2,
}
_SYSLOG_FACILITY = 3  # system daemons

# BGL raw line field positions (space-delimited, exactly 9 fixed fields + rest is content)
# Format: label timestamp date node datetime node2 type component level <content...>
BGL_FIELDS = ["label", "timestamp", "date", "node", "datetime", "node2", "type", "component", "level"]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get_json(url: str) -> dict:
    """Fetch JSON from *url* with a plain urllib request (no extra deps)."""
    req = urllib.request.Request(url, headers={"User-Agent": "LogPoison-Ingest/1.0"})
    with urllib.request.urlopen(req, timeout=ZENODO_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_download(url: str, dest: Path, desc: str = "") -> None:
    """Stream-download *url* to *dest*, logging progress every 50 MB."""
    logger.info("  Downloading %s → %s …", desc or url, dest.name)
    req = urllib.request.Request(url, headers={"User-Agent": "LogPoison-Ingest/1.0"})
    with urllib.request.urlopen(req, timeout=ZENODO_TIMEOUT) as resp, open(dest, "wb") as fh:
        chunk_size = 1 << 20  # 1 MB
        total = 0
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            fh.write(chunk)
            total += len(chunk)
            if total % (50 << 20) < chunk_size:
                logger.info("    … %.0f MB downloaded", total / 1e6)
    logger.info("  Downloaded %.1f MB → %s", dest.stat().st_size / 1e6, dest)


# ---------------------------------------------------------------------------
# Zenodo file listing
# ---------------------------------------------------------------------------

def _get_zenodo_files(record_id: str) -> dict[str, str]:
    """Return {filename: download_url} for all files in a Zenodo record."""
    url = f"{ZENODO_API_BASE}/{record_id}"
    meta = _http_get_json(url)
    result: dict[str, str] = {}
    for f in meta.get("files", []):
        result[f["key"]] = f["links"]["self"]
    return result


def _find_file(file_map: dict[str, str], patterns: list[str]) -> tuple[str, str] | None:
    """Return (filename, url) for the first file whose name matches any pattern."""
    import fnmatch
    for pat in patterns:
        for name, url in file_map.items():
            if fnmatch.fnmatch(name.lower(), pat.lower()):
                return name, url
    return None


# ---------------------------------------------------------------------------
# Archive extraction helpers
# ---------------------------------------------------------------------------

def _extract_archive(archive_path: Path, dest_dir: Path) -> list[Path]:
    """Extract zip / tar.gz / .gz into dest_dir; return list of extracted paths."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []

    name_lower = archive_path.name.lower()

    if name_lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
            extracted = [dest_dir / m for m in zf.namelist() if not m.endswith("/")]

    elif name_lower.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dest_dir)
            extracted = [dest_dir / m.name for m in tf.getmembers() if m.isfile()]

    elif name_lower.endswith(".gz"):
        # Single-file gzip
        out_path = dest_dir / archive_path.stem
        with gzip.open(archive_path, "rb") as gz, open(out_path, "wb") as fh:
            shutil.copyfileobj(gz, fh)
        extracted = [out_path]

    else:
        # Assume plain text; just copy
        dest = dest_dir / archive_path.name
        shutil.copy2(archive_path, dest)
        extracted = [dest]

    logger.info("  Extracted %d file(s) to %s", len(extracted), dest_dir)
    return extracted


# ---------------------------------------------------------------------------
# HDFS ingestion
# ---------------------------------------------------------------------------

def _parse_hdfs_line(line: str) -> dict[str, str] | None:
    """Parse one raw HDFS log line into a field dict.

    Expected format (space-delimited):
      YYMMDD HHMMSS PID LEVEL COMPONENT: CONTENT...

    Returns None if the line cannot be parsed.
    """
    line = line.rstrip()
    if not line:
        return None
    parts = line.split(None, 5)  # at most 6 parts
    if len(parts) < 5:
        return None
    result = {
        "date":      parts[0],
        "time":      parts[1],
        "pid":       parts[2],
        "level":     parts[3],
        "component": parts[4].rstrip(":"),
        "content":   parts[5] if len(parts) > 5 else "",
    }
    return result


def _hdfs_to_syslog(fields: dict[str, str]) -> str:
    """Render parsed HDFS fields as an RFC-5424 syslog message.

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG
    """
    level = fields["level"].upper()
    severity = _SYSLOG_LEVEL_SEVERITY.get(level, 6)
    pri = _SYSLOG_FACILITY * 8 + severity

    # Convert YYMMDD HHMMSS to ISO-8601 (assume 20xx)
    d, t = fields["date"], fields["time"]
    if len(d) == 6 and len(t) == 6:
        ts = f"20{d[:2]}-{d[2:4]}-{d[4:6]}T{t[:2]}:{t[2:4]}:{t[4:6]}Z"
    else:
        ts = "-"

    hostname  = "hdfs-cluster"
    app_name  = fields["component"].replace(" ", "_") or "-"
    proc_id   = fields["pid"] or "-"
    msg_id    = "-"
    sd        = "-"
    msg       = fields["content"]

    return f"<{pri}>1 {ts} {hostname} {app_name} {proc_id} {msg_id} {sd} {msg}"


def _load_hdfs_anomaly_labels(label_file: Path) -> dict[str, str]:
    """Load HDFS anomaly_label.csv → {block_id: 'Normal'|'Anomaly'}."""
    labels: dict[str, str] = {}
    if not label_file.exists():
        logger.warning("  anomaly_label.csv not found at %s — all HDFS lines treated as benign.", label_file)
        return labels
    with open(label_file, encoding="utf-8", errors="replace") as fh:
        first = True
        for line in fh:
            if first:
                first = False
                continue  # skip header
            parts = line.strip().split(",", 1)
            if len(parts) == 2:
                labels[parts[0].strip()] = parts[1].strip()
    logger.info("  Loaded %d HDFS anomaly labels.", len(labels))
    return labels


def _make_log_id(prefix: str, idx: int) -> str:
    digest = hashlib.sha1(f"{prefix}:{idx}".encode()).hexdigest()[:8]
    return f"{prefix}-{idx:07d}-{digest}"


def ingest_hdfs(
    log_file: Path,
    label_file: Path,
    max_benign: int = 3000,
    max_malicious: int = 1500,
    seed: int = 42,
) -> list[dict]:
    """Parse HDFS.log + anomaly_label.csv → LogPoison JSONL records (syslog format)."""
    import random

    if not log_file.exists():
        logger.warning("[SKIP] HDFS: log file not found at %s.", log_file)
        return []

    anomaly_labels = _load_hdfs_anomaly_labels(label_file)

    benign_pool:    list[dict] = []
    malicious_pool: list[dict] = []

    with open(log_file, encoding="utf-8", errors="replace") as fh:
        for idx, raw_line in enumerate(fh):
            fields = _parse_hdfs_line(raw_line)
            if fields is None:
                continue

            # Determine anomaly status from any block ID in this line
            block_ids = BLOCK_ID_RE.findall(fields["content"])
            is_anomaly = any(anomaly_labels.get(bid) == "Anomaly" for bid in block_ids)

            # If no label file available, default all to benign
            gt_label = "malicious" if is_anomaly else "benign"

            syslog_str = _hdfs_to_syslog(fields)
            record = {
                "log_id":            _make_log_id("hdfs", idx),
                "raw_log":           syslog_str,
                "format":            "syslog",
                "ground_truth_label": gt_label,
                "attack_type":       "Impact" if is_anomaly else None,
                "is_adversarial":    False,
                "attack_goal":       None,
                "attacker_level":    None,
                "source_dataset":    "HDFS",
            }

            if gt_label == "benign":
                benign_pool.append(record)
            else:
                malicious_pool.append(record)

    rng = random.Random(seed)
    rng.shuffle(benign_pool)
    rng.shuffle(malicious_pool)

    result = benign_pool[:max_benign] + malicious_pool[:max_malicious]
    logger.info(
        "HDFS: %d benign, %d malicious records extracted (caps: %d / %d).",
        min(len(benign_pool), max_benign),
        min(len(malicious_pool), max_malicious),
        max_benign, max_malicious,
    )
    return result


# ---------------------------------------------------------------------------
# BGL ingestion
# ---------------------------------------------------------------------------

def _parse_bgl_line(line: str) -> dict[str, str] | None:
    """Parse one raw BGL log line.

    Format (space-delimited, 9 fixed fields + content):
      label timestamp date node datetime node2 type component level content...

    Returns None if the line is malformed.
    """
    line = line.rstrip()
    if not line:
        return None
    parts = line.split(None, len(BGL_FIELDS))
    if len(parts) < len(BGL_FIELDS):
        return None
    result = {field: parts[i] for i, field in enumerate(BGL_FIELDS)}
    result["content"] = parts[len(BGL_FIELDS)] if len(parts) > len(BGL_FIELDS) else ""
    return result


def _bgl_to_json(fields: dict[str, str]) -> str:
    """Serialise BGL fields as a compact JSON string (this becomes raw_log)."""
    payload = {
        "timestamp": fields["timestamp"],
        "date":      fields["date"],
        "node":      fields["node"],
        "datetime":  fields["datetime"],
        "type":      fields["type"],
        "component": fields["component"],
        "level":     fields["level"],
        "content":   fields["content"],
    }
    return json.dumps(payload, separators=(",", ":"))


def ingest_bgl(
    log_file: Path,
    max_benign: int = 2000,
    max_malicious: int = 1500,
    seed: int = 42,
) -> list[dict]:
    """Parse BGL.log → LogPoison JSONL records (JSON format)."""
    import random

    if not log_file.exists():
        logger.warning("[SKIP] BGL: log file not found at %s.", log_file)
        return []

    benign_pool:    list[dict] = []
    malicious_pool: list[dict] = []

    with open(log_file, encoding="utf-8", errors="replace") as fh:
        for idx, raw_line in enumerate(fh):
            fields = _parse_bgl_line(raw_line)
            if fields is None:
                continue

            is_alert  = fields["label"] != "-"
            gt_label  = "malicious" if is_alert else "benign"
            json_str  = _bgl_to_json(fields)

            record = {
                "log_id":            _make_log_id("bgl", idx),
                "raw_log":           json_str,
                "format":            "JSON",
                "ground_truth_label": gt_label,
                "attack_type":       "Impact" if is_alert else None,
                "is_adversarial":    False,
                "attack_goal":       None,
                "attacker_level":    None,
                "source_dataset":    "BGL",
            }

            if gt_label == "benign":
                benign_pool.append(record)
            else:
                malicious_pool.append(record)

    rng = random.Random(seed)
    rng.shuffle(benign_pool)
    rng.shuffle(malicious_pool)

    result = benign_pool[:max_benign] + malicious_pool[:max_malicious]
    logger.info(
        "BGL: %d benign, %d malicious records extracted (caps: %d / %d).",
        min(len(benign_pool), max_benign),
        min(len(malicious_pool), max_malicious),
        max_benign, max_malicious,
    )
    return result


# ---------------------------------------------------------------------------
# Orchestrator: download + ingest
# ---------------------------------------------------------------------------

def ingest_loghub(
    raw_dir: Path,
    max_hdfs_benign:    int = 3000,
    max_hdfs_malicious: int = 1500,
    max_bgl_benign:     int = 2000,
    max_bgl_malicious:  int = 1500,
    seed: int = 42,
    skip_download: bool = False,
) -> list[dict]:
    """Download Loghub (HDFS + BGL) from Zenodo and return LogPoison records.

    Args:
        raw_dir:         Local directory for cached downloads.
        skip_download:   If True, use existing files in raw_dir only (no network).
    Returns:
        List of JSONL record dicts.  Empty list on total failure (logged warning).
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []

    # -- HDFS ----------------------------------------------------------------
    hdfs_dir      = raw_dir / "hdfs"
    hdfs_log      = hdfs_dir / "HDFS.log"
    hdfs_labels   = hdfs_dir / "anomaly_label.csv"

    if not hdfs_log.exists() and not skip_download:
        logger.info("HDFS: attempting Zenodo download …")
        try:
            file_map = _get_zenodo_files(ZENODO_RECORD_ID)
            match = _find_file(file_map, ["hdfs_v1*", "hdfs*"])
            if match:
                fname, furl = match
                archive_path = raw_dir / fname
                _http_download(furl, archive_path, desc=fname)
                _extract_archive(archive_path, hdfs_dir)
                # Rename extracted log if needed
                for candidate in hdfs_dir.rglob("HDFS.log"):
                    if candidate != hdfs_log:
                        candidate.rename(hdfs_log)
                        break
            else:
                logger.warning("[SKIP] HDFS: no matching file found in Zenodo record %s.", ZENODO_RECORD_ID)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[SKIP] HDFS: Zenodo download failed (%s).\n"
                "       Manually download from https://zenodo.org/records/%s\n"
                "       and place HDFS.log + anomaly_label.csv under %s",
                exc, ZENODO_RECORD_ID, hdfs_dir,
            )

    records.extend(
        ingest_hdfs(hdfs_log, hdfs_labels, max_hdfs_benign, max_hdfs_malicious, seed)
    )

    # -- BGL -----------------------------------------------------------------
    bgl_dir  = raw_dir / "bgl"
    bgl_log  = bgl_dir / "BGL.log"

    if not bgl_log.exists() and not skip_download:
        logger.info("BGL: attempting Zenodo download …")
        try:
            file_map = _get_zenodo_files(ZENODO_RECORD_ID)
            match = _find_file(file_map, ["bgl*"])
            if match:
                fname, furl = match
                archive_path = raw_dir / fname
                _http_download(furl, archive_path, desc=fname)
                _extract_archive(archive_path, bgl_dir)
                for candidate in bgl_dir.rglob("BGL.log"):
                    if candidate != bgl_log:
                        candidate.rename(bgl_log)
                        break
            else:
                logger.warning("[SKIP] BGL: no matching file found in Zenodo record %s.", ZENODO_RECORD_ID)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[SKIP] BGL: Zenodo download failed (%s).\n"
                "       Manually download from https://zenodo.org/records/%s\n"
                "       and place BGL.log under %s",
                exc, ZENODO_RECORD_ID, bgl_dir,
            )

    records.extend(
        ingest_bgl(bgl_log, max_bgl_benign, max_bgl_malicious, seed)
    )

    return records


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Ingest Loghub HDFS+BGL → LogPoison JSONL")
    parser.add_argument(
        "--raw-dir",
        default=str(Path(__file__).parent / "raw" / "loghub"),
        help="Local cache directory for downloaded files",
    )
    parser.add_argument("--skip-download", action="store_true", help="Use cached files only")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent / "loghub_records.jsonl"),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    records = ingest_loghub(
        raw_dir=Path(args.raw_dir),
        seed=args.seed,
        skip_download=args.skip_download,
    )

    if args.dry_run:
        benign_count = sum(1 for r in records if r["ground_truth_label"] == "benign")
        mal_count    = sum(1 for r in records if r["ground_truth_label"] == "malicious")
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
