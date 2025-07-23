import json
import random
from collections import defaultdict

TOP_10_CWES = {
    "CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787",
    "CWE-20", "CWE-200", "CWE-125", "CWE-264", "CWE-401"
}

for cwe in TOP_10_CWES:
    input_filename = f"Linux_kernel_{cwe}_clean_data.json"
    output_training_filename = f"Linux_kernel_{cwe}_clean_data.json"
    output_testing_filename = f"Linux_kernel_{cwe}_clean_data_testset_new.json"

    # Load data
    with open(input_filename, "r", encoding='utf-8') as f:
        data = json.load(f)

    # Group entries by CVE
    cve_groups = defaultdict(list)
    for entry in data:
        cve_id = entry.get("cve_id")
        if cve_id:
            cve_groups[cve_id].append(entry)

    # Divide into training and testing sets
    train_data = []
    test_data = []
    for cve_id, entries in cve_groups.items():
        random.shuffle(entries)
        if len(entries) == 1:
            test_data.append(entries[0])
        else:
            train_data.append(entries[0])
            test_data.extend(entries[1:])

    # Write output
    with open(output_testing_filename, "w", encoding='utf-8') as f:
        json.dump(test_data, f, indent=4)   
   
    with open(output_training_filename, "w", encoding='utf-8') as f:
        json.dump(train_data, f, indent=4)



    # Print stats
    print(f"{cwe}:")
    print(f"  Training set: {len(train_data)} entries, {len(set(e['cve_id'] for e in train_data))} unique CVEs")
    print(f"  Testing set:  {len(test_data)} entries, {len(set(e['cve_id'] for e in test_data))} unique CVEs\n")