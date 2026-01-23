import json
import os
from collections import defaultdict

TRAIN_DIR = "train"
TEST_DIR = "test"

def count_items_by_cwe(directory):
    counts = defaultdict(int)
    unique_cves = defaultdict(set)
    global_unique_cves = set()

    for filename in os.listdir(directory):
        if not filename.endswith(".json"):
            continue

        # Extract CWE from filename: Linux_kernel_CWE-XXX_*.json
        parts = filename.split("_")
        cwe = next((p for p in parts if p.startswith("CWE-")), None)
        if cwe is None:
            continue

        filepath = os.path.join(directory, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        counts[cwe] += len(data)
        for entry in data:
            cve_id = entry.get("cve_id")
            if cve_id:
                unique_cves[cwe].add(cve_id)
                global_unique_cves.add(cve_id)

    return counts, unique_cves, global_unique_cves


if __name__ == "__main__":
    train_counts, train_unique_cves, train_global_cves = count_items_by_cwe(TRAIN_DIR)
    test_counts, test_unique_cves, test_global_cves = count_items_by_cwe(TEST_DIR)

    print("=== TRAIN SET COUNTS ===")
    for cwe in sorted(train_counts):
        print(f"{cwe}: {train_counts[cwe]} items, {len(train_unique_cves[cwe])} unique CVEs")
    print(f"Total unique CVEs in TRAIN set: {len(train_global_cves)}")

    print("\n=== TEST SET COUNTS ===")
    for cwe in sorted(test_counts):
        print(f"{cwe}: {test_counts[cwe]} items, {len(test_unique_cves[cwe])} unique CVEs")
    print(f"Total unique CVEs in TEST set: {len(test_global_cves)}")