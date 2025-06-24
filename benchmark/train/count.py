import json
import glob

# List of CWE IDs you're interested in
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]

# Loop through each CWE file
for cwe_id in cwe_ids:
    filename = f"Linux_kernel_{cwe_id}_clean_data.json"
    try:
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)
            entry_count = len(data)
            print(f"{filename}: {entry_count} entries")
    except FileNotFoundError:
        print(f"{filename}: File not found")
    except json.JSONDecodeError:
        print(f"{filename}: Failed to decode JSON")