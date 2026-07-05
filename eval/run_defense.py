import argparse
import json
import logging
import os
import sys
import time

# Ensure we can import from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from defenses.log_sanitizer import LogSanitizer
from attacks.direct_injection import apply_direct_injection
from attacks.context_poisoning import apply_context_poisoning

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Evaluate LogSanitizer defense")
    args = parser.parse_args()
    
    logger.info("Initializing LogSanitizer...")
    sanitizer = LogSanitizer()
    
    dataset_path = "data/processed/dataset.jsonl"
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}")
        return

    benign_records = []
    adversarial_records = []
    
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                if record.get("is_adversarial", False):
                    adversarial_records.append(record)
                elif record.get("ground_truth_label") == "benign":
                    benign_records.append(record)
                    
    # Generate the crafted versions for the adversarial records
    crafted_adversarial_logs = []
    for r in adversarial_records:
        if r["attack_goal"] == "evasion":
            crafted_r = apply_direct_injection(r)
            if "crafted_log" in crafted_r:
                crafted_adversarial_logs.append(crafted_r["crafted_log"])
        elif r["attack_goal"] == "poisoning":
            # Context poisoning returns a list of messages. We want to see if the defense
            # detects the poison message (the first one)
            messages = apply_context_poisoning(r)
            crafted_adversarial_logs.append(messages[0]["content"])
            
    # Subsample benign records to match adversarial count for balanced FPR testing
    test_benign = benign_records[:len(crafted_adversarial_logs)]
    benign_logs = [r["raw_log"] for r in test_benign]

    logger.info(f"Evaluating Defense on {len(crafted_adversarial_logs)} attacked logs and {len(benign_logs)} benign logs.")

    # Measure True Positives (Attacks detected) and Latency
    tp = 0
    start_time = time.time()
    for log in crafted_adversarial_logs:
        is_detected, _ = sanitizer.sanitize(log)
        if is_detected:
            tp += 1
    adv_latency = (time.time() - start_time) / len(crafted_adversarial_logs) if crafted_adversarial_logs else 0

    # Measure False Positives (Benign logs flagged as attacks)
    fp = 0
    start_time = time.time()
    for log in benign_logs:
        is_detected, _ = sanitizer.sanitize(log)
        if is_detected:
            fp += 1
    benign_latency = (time.time() - start_time) / len(benign_logs) if benign_logs else 0

    detection_rate = tp / len(crafted_adversarial_logs) if crafted_adversarial_logs else 0
    fpr = fp / len(benign_logs) if benign_logs else 0
    avg_latency = (adv_latency + benign_latency) / 2
    bypass_rate = 1.0 - detection_rate

    logger.info("=== Defense Evaluation Results ===")
    logger.info(f"Detection Rate (TPR): {detection_rate:.4f}")
    logger.info(f"False Positive Rate:  {fpr:.4f}")
    logger.info(f"Bypass Rate:          {bypass_rate:.4f}")
    logger.info(f"Avg Latency per log:  {avg_latency * 1000:.2f} ms")

if __name__ == "__main__":
    main()
