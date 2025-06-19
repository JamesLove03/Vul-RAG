import json
import random
from collections import defaultdict

# Constants
INPUT_FILE = "Linux_kernel_clean_data_top5_CWEs.json"
TOP_5_CWES = {"CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787"}

# Load data
with open(INPUT_FILE, "r") as infile:
    data = json.load(infile)

# Filter to only entries with at least one valid CWE
filtered_data = [
    entry for entry in data
    if any(cwe in TOP_5_CWES for cwe in entry.get("cwe", []))
]

# Group entries by CVE ID
cve_groups = defaultdict(list)
for entry in filtered_data:
    cve_id = entry.get("cve_id")
    if cve_id:
        cve_groups[cve_id].append(entry)

# Storage for per-CWE output
train_sets = defaultdict(list)
test_sets = defaultdict(list)

# Distribute entries into train/test sets
for entries in cve_groups.values():
    random.shuffle(entries)
    if not entries:
        continue
    train_entry = entries.pop()
    for cwe in train_entry.get("cwe", []):
        if cwe in TOP_5_CWES:
            train_sets[cwe].append(train_entry)

    if entries:
        test_entry = entries.pop()
        for cwe in test_entry.get("cwe", []):
            if cwe in TOP_5_CWES:
                test_sets[cwe].append(test_entry)

    for entry in entries:
        target = train_sets if random.random() < 0.7 else test_sets
        for cwe in entry.get("cwe", []):
            if cwe in TOP_5_CWES:
                target[cwe].append(entry)

# Write files per CWE
for cwe in TOP_5_CWES:
    train_filename = f"Linux_kernel_{cwe}_clean_data.json"
    test_filename = f"Linux_kernel_{cwe}_clean-data_testset_new.json"

    with open(train_filename, "w") as f:
        json.dump(train_sets[cwe], f, indent=4)

    with open(test_filename, "w") as f:
        json.dump(test_sets[cwe], f, indent=4)

# Reporting
print("Training set metrics:")
total_train = sum(len(entries) for entries in train_sets.values())
train_cves = {e['cve_id'] for entries in train_sets.values() for e in entries}
print(f"  Total entries: {total_train}")
print(f"  Unique CVEs: {len(train_cves)}")
for cwe in sorted(TOP_5_CWES):
    print(f"  {cwe}: {len(train_sets[cwe])} entries")

print("\nTesting set metrics:")
total_test = sum(len(entries) for entries in test_sets.values())
test_cves = {e['cve_id'] for entries in test_sets.values() for e in entries}
print(f"  Total entries: {total_test}")
print(f"  Unique CVEs: {len(test_cves)}")
for cwe in sorted(TOP_5_CWES):
    print(f"  {cwe}: {len(test_sets[cwe])} entries")