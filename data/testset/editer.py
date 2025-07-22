import json

# Load the original JSON
CWE = ["CWE-20", "CWE-119", "CWE-125", "CWE-200", "CWE-264", "CWE-362", "CWE-401", "CWE-416", "CWE-476", "CWE-787"]

for cwe in CWE:

    with open(f"Linux_kernel_{cwe}_testset.json", "r", encoding="utf-8") as f:
        original_data = json.load(f)

# Flatten the structure
    flattened_data = []
    for cve_entries in original_data.values():
        flattened_data.extend(cve_entries["item"])

# Save the cleaned JSON
    with open(f"Linux_kernel_{cwe}_clean_data_testset_new.json", "w", encoding="utf-8") as f:
        json.dump(flattened_data, f, indent=2)