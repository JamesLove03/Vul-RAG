import json
import os

CWES = [
    "CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787",
    "CWE-20", "CWE-200", "CWE-125", "CWE-264", "CWE-401"
]

INPUT_TEMPLATE = "Linux_kernel_{cwe}_testset.json"
OUTPUT_TEMPLATE = "Linux_kernel_{cwe}_testset_flat.json"

def flatten_testset(cwe):
    input_file = INPUT_TEMPLATE.format(cwe=cwe)
    output_file = OUTPUT_TEMPLATE.format(cwe=cwe)

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    flattened = []

    # data is a dict keyed by CVE ID
    for cve_id, cve_block in data.items():
        items = cve_block.get("item", [])
        for entry in items:
            # Ensure CVE ID is present and consistent
            entry["cve_id"] = cve_id
            flattened.append(entry)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(flattened, f, indent=4)

    print(f"{cwe}: {len(flattened)} entries written")

def main():
    for cwe in CWES:
        flatten_testset(cwe)

if __name__ == "__main__":
    main()