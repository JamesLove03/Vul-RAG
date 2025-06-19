import json
import tiktoken
from collections import defaultdict

# Constants
INPUT_FILE = "Linux_kernel_clean_data_top10_CWEs.json"
OUTPUT_FILE = "Linux_kernel_clean_data_top5_CWEs.json"
VALID_CWES = {"CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787"}
TOKEN_LIMIT = 16384

# Setup tokenizer
encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-16k")

# Stats
entries_kept = []
cwe_entry_count = defaultdict(int)
cwe_cve_set = defaultdict(set)

with open(INPUT_FILE, "r") as infile:
    data = json.load(infile)

for entry in data:
    cwes = entry.get("cwe", [])
    matching_cwes = VALID_CWES.intersection(cwes)
    
    if not matching_cwes:
        continue

    # Token check
    text_to_tokenize = entry.get("code_before_change", "") + entry.get("code_after_change", "") + entry.get("patch", "")
    num_tokens = len(encoding.encode(text_to_tokenize))
    
    if num_tokens >= TOKEN_LIMIT:
        continue

    entries_kept.append(entry)
    cve_id = entry.get("cve_id")

    for cwe in matching_cwes:
        cwe_entry_count[cwe] += 1
        if cve_id:
            cwe_cve_set[cwe].add(cve_id)

# Write output
with open(OUTPUT_FILE, "w") as outfile:
    json.dump(entries_kept, outfile, indent=4)

# Summary
print(f"Total entries kept: {len(entries_kept)}")
unique_cves = {entry['cve_id'] for entry in entries_kept if 'cve_id' in entry}
print(f"Total unique CVEs kept: {len(unique_cves)}\n")

print("Breakdown by CWE:")
for cwe in sorted(cwe_entry_count.keys()):
    print(f"{cwe}: {cwe_entry_count[cwe]} entries, {len(cwe_cve_set[cwe])} unique CVEs")