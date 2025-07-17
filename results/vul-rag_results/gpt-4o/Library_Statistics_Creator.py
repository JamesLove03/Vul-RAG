import json
import os

# List of CWE IDs
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]

# Output dictionary to collect results
final_output = {}
total_counts = {
    "Library_Presence": 0,
    "Library_Correct": 0,
    "Library_Wrong": 0,
    "Non_Lib_Correct": 0,
    "Non_Lib_Incorrect": 0,
    "Total_Entries": 0,
    "Average_Rank": 0
}

total_rank_sum = 0

for cwe_id in cwe_ids:
    file_name = f"{cwe_id}_gpt-4o.json"
    rank_sum = 0

    if not os.path.exists(file_name):
        print(f"File {file_name} not found. Skipping.")
        continue

    with open(file_name, 'r') as f:
        data = json.load(f)

    results = {
        "Library_Presence": 0,
        "Library_Correct": 0,
        "Library_Wrong": 0,
        "Non_Lib_Correct": 0,
        "Non_Lib_Incorrect": 0,
        "Total_Entries": 0,
        "Average_Rank": 0
    }

    total_entry_count = 0  # per file
    for category in ["vul_data", "non_vul_data"]:
        entries = data.get(category, [])
        total_entry_count += len(entries)

        for item in entries:
            cve_id = item.get("cve_id")
            final_result = item.get("final_result", None)
            detect_results = item.get("detect_result", [])
            #this part counts the average appearance of the first matching cve entry
            rank_of_first_match = 0
            for idx, dr in enumerate(detect_results):
                vk = dr.get("vul_knowledge")
                if vk and vk.get("cve_id") == cve_id:
                    rank_of_first_match = idx + 1  # 1-based index
                    break
            rank_sum += rank_of_first_match

            vul_knowledges = [dr.get("vul_knowledge") for dr in detect_results if "vul_knowledge" in dr]
            cve_ids_in_knowledge = {vk.get("cve_id") for vk in vul_knowledges if vk}
            has_match = cve_id in cve_ids_in_knowledge
            last_match = (
                vul_knowledges[-1].get("cve_id") == cve_id
                if vul_knowledges and vul_knowledges[-1].get("cve_id")
                else False
            )
            if has_match:
                results["Library_Presence"] += 1

            if final_result is None:
                print(f"Missing final_result for entry {cve_id}, skipping.")
                continue
            
            if category == 'vul_data':
                if final_result == 1:
                    if last_match:
                        results["Library_Correct"] += 1
                    else:
                        results["Non_Lib_Correct"] += 1
                elif final_result == 0:
                    if has_match:
                        results["Library_Wrong"] += 1
                    else:
                        results["Non_Lib_Incorrect"] += 1

            if category == 'non_vul_data':
                if final_result == 1:
                    if last_match:
                        results["Library_Wrong"] += 1
                    else:
                        results["Non_Lib_Incorrect"] += 1
                elif final_result == 0:
                    if has_match:
                        results["Library_Correct"] += 1
                    else:
                        results["Non_Lib_Correct"] += 1

    results["Average_Rank"] = rank_sum / results["Library_Presence"]
    total_rank_sum += rank_sum
    results["Total_Entries"] = total_entry_count
    # Accumulate into total counts
    for key in results:
        if key in total_counts:
            total_counts[key] += results[key]
    final_output[cwe_id] = results

# Add total summary
total_counts["Average_Rank"] = total_rank_sum / total_counts["Library_Presence"]
final_output["Total"] = total_counts

# Write results to lib_results.json
with open("lib_results.json", "w") as f_out:
    json.dump(final_output, f_out, indent=4)

print("All counts and totals (including total entries) written to lib_results.json.")