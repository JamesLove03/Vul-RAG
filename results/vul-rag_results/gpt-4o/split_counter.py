import json
import os

cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
output = {}
total_counts = {"final_result_1": 0, "final_result_0": 0}

for cwe_id in cwe_ids:
    file_name = f"{cwe_id}_gpt-4o.json"
    if not os.path.exists(file_name):
        print(f"{file_name} not found, skipping.")
        continue

    with open(file_name, "r") as f:
        data = json.load(f)

    result = {"final_result_1": 0, "final_result_0": 0}

    for category in ["vul_data", "non_vul_data"]:
        for entry in data.get(category, []):
            final = entry.get("final_result")
            if final == 1:
                result["final_result_1"] += 1
                total_counts["final_result_1"] += 1
            elif final == 0:
                result["final_result_0"] += 1
                total_counts["final_result_0"] += 1

    output[cwe_id] = result

output["Total"] = total_counts

with open("pos_neg_split.json", "w") as f_out:
    json.dump(output, f_out, indent=4)

