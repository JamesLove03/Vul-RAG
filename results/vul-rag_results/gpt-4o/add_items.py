import json
import os

# List of CWE IDs
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787", "CWE-20", "CWE-125", "CWE-200", "CWE-264", "CWE-401"]

for cwe_id in cwe_ids:
    file_name = f"{cwe_id}_gpt-4o.json"
    rank_sum = 0
    id_results = {}
    if not os.path.exists(file_name):
        print(f"File {file_name} not found. Skipping.")
        continue

    with open(file_name, 'r') as f:
        data = json.load(f)

    