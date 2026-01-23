import json
import random
import os
from collections import defaultdict
from pathlib import Path

TOP_10_CWES = [
    "CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787",
    "CWE-20", "CWE-200", "CWE-125", "CWE-264", "CWE-401"
]

random.seed(42)  # reproducibility

for cwe in TOP_10_CWES:
    input_file = f"Linux_kernel_{cwe}.json"
    if not Path(input_file).exists():
        print(f"[WARN] Missing file: {input_file}")
        continue

    with open(input_file, "r", encoding="utf-8") as infile:
        data = json.load(infile)

    # Group by CVE ID
    cve_groups = defaultdict(list)
    for entry in data:
        cve_id = entry.get("cve_id")
        if cve_id:
            cve_groups[cve_id].append(entry)

    train_set = []
    test_set = []

    # Split per CVE (guarantees test ⊆ train CVEs)
    for entries in cve_groups.values():
        random.shuffle(entries)

        # Always seed training with one entry
        train_set.append(entries.pop())

        # Optional test entry
        if entries:
            test_set.append(entries.pop())

        # Remaining entries → 80/20
        for entry in entries:
            if random.random() < 0.8:
                train_set.append(entry)
            else:
                test_set.append(entry)

    # Write outputs
    os.makedirs("train", exist_ok=True)
    os.makedirs("test", exist_ok=True)

    train_filename = os.path.join("train", f"Linux_kernel_{cwe}_clean_data.json")
    test_filename = os.path.join("test", f"Linux_kernel_{cwe}_clean-data_testset_new.json")

    with open(train_filename, "w", encoding="utf-8") as f:
        json.dump(train_set, f, indent=4)

    with open(test_filename, "w", encoding="utf-8") as f:
        json.dump(test_set, f, indent=4)

    # Reporting
    train_cves = {e["cve_id"] for e in train_set}
    test_cves = {e["cve_id"] for e in test_set}

    print(f"\n[{cwe}]")
    print(f"  Train entries: {len(train_set)}")
    print(f"  Train CVEs:    {len(train_cves)}")
    print(f"  Test entries:  {len(test_set)}")
    print(f"  Test CVEs:     {len(test_cves)}")
    print(f"  Test CVEs ⊆ Train CVEs: {test_cves.issubset(train_cves)}")