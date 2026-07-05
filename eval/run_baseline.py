import argparse
import json
import logging
import os
import sys

# Ensure we can import from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_clients.gemini_client import GeminiClient
from llm_clients.ollama_client import OllamaClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def parse_llm_response(text: str) -> str:
    """Extracts BENIGN or MALICIOUS from the LLM text output."""
    text_upper = text.upper()
    if "BENIGN" in text_upper and "MALICIOUS" not in text_upper:
        return "benign"
    elif "MALICIOUS" in text_upper and "BENIGN" not in text_upper:
        return "malicious"
    # Fallback heuristic if both or neither are present
    if text_upper.find("BENIGN") < text_upper.find("MALICIOUS"):
        if text_upper.find("BENIGN") != -1: return "benign"
        else: return "malicious"
    else:
        if text_upper.find("MALICIOUS") != -1: return "malicious"
        else: return "benign"

def main():
    parser = argparse.ArgumentParser(description="Run baseline evaluation on clean dataset")
    parser.add_argument("--target", choices=["gemini", "ollama"], required=True)
    parser.add_argument("--limit", type=int, default=100, help="Number of records to test")
    args = parser.parse_args()
    
    logger.info(f"Running baseline evaluation for {args.target}")
    
    if args.target == "gemini":
        llm = GeminiClient()
    else:
        llm = OllamaClient()
        
    dataset_path = "data/processed/dataset.jsonl"
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}")
        return

    records = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                # For baseline, we only want un-attacked data
                if not record.get("is_adversarial", False):
                    records.append(record)
                    
    # Balance test set limit if requested
    benign_records = [r for r in records if r["ground_truth_label"] == "benign"]
    malicious_records = [r for r in records if r["ground_truth_label"] == "malicious"]
    
    limit_per_class = args.limit // 2
    test_set = benign_records[:limit_per_class] + malicious_records[:limit_per_class]
    
    tp = 0 # True Positive (Malicious correctly identified)
    fp = 0 # False Positive (Benign identified as malicious)
    tn = 0 # True Negative (Benign correctly identified)
    fn = 0 # False Negative (Malicious identified as benign)
    
    for i, record in enumerate(test_set):
        logger.info(f"Processing {i+1}/{len(test_set)}")
        response_text = llm.classify(record["raw_log"])
        predicted = parse_llm_response(response_text)
        
        actual = record["ground_truth_label"]
        
        if predicted == "malicious" and actual == "malicious":
            tp += 1
        elif predicted == "malicious" and actual == "benign":
            fp += 1
        elif predicted == "benign" and actual == "benign":
            tn += 1
        elif predicted == "benign" and actual == "malicious":
            fn += 1

    accuracy = (tp + tn) / len(test_set) if len(test_set) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    logger.info("=== Baseline Results ===")
    logger.info(f"Target: {args.target}")
    logger.info(f"Total Evaluated: {len(test_set)}")
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")
    logger.info(f"F1 Score:  {f1:.4f}")

if __name__ == "__main__":
    main()
