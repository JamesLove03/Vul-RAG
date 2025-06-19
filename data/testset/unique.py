import json
import os

# List of CWE IDs
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
filename_template = "Linux_kernel_{cwe_id}_clean_data_testset_new.json"

# Dictionary to store counts
cwe_cve_counts = {}
total_unique_cves = set()

for cwe_id in cwe_ids:
    filename = filename_template.format(cwe_id=cwe_id)
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        continue

    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
        cve_ids = set(entry['cve_id'] for entry in data)
        cwe_cve_counts[cwe_id] = len(cve_ids)
        total_unique_cves.update(cve_ids)

# Print results
print("\nUnique CVE counts by CWE:")
for cwe, count in cwe_cve_counts.items():
    print(f"{cwe}: {count} unique CVEs")

print(f"\nTotal unique CVEs across all CWEs: {len(total_unique_cves)}")