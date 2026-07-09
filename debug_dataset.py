import json, random
from collections import Counter

data = [json.loads(l) for l in open('data/processed/logpoison_final.jsonl')]
malicious = [r for r in data if r['ground_truth_label'] == 'malicious' and not r['is_adversarial']]
random.seed(42)
random.shuffle(malicious)
sample = malicious[:20]

print(f"Total malicious clean: {len(malicious)}")
print(f"\nSource breakdown of first 20:")
print(Counter(r['source_dataset'] for r in sample))
print(Counter(r['format'] for r in sample))

print("\nAll 20 logs:")
for i, r in enumerate(sample):
    print(f"\n[{i+1}] source={r['source_dataset']} format={r['format']}")
    print(f"     {r['raw_log'][:200]}")