import json
import os

# CWE IDs to process
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]

# Store data from each file
all_data = {}

for cwe_id in cwe_ids: #iterate each file
    file_name = f"{cwe_id}_gpt-4o-gpt-4o_VulRAG-detection_default-settings.json"

    if not os.path.exists(file_name):
        print(f"File {file_name} not found. Skipping.")
        continue

    with open(file_name, 'r') as f:
        data = json.load(f)
    
    for category in ["vul_data", "non_vul_data"]: #iterate through vul and nonvul
        
        for item in data.get(category, []): #iterate through each entry
            detect_results = item.get("detect_result", [])
            item["final_result"] = 0
            
            for i, result in enumerate(detect_results): #iterate through all vulnerability knowledge
                vul = "### YES ###" in result.get("vul_output", "")
                sol = "### YES ###" in result.get("sol_output", "")
                
                if vul and not sol:
                    item["final_result"] = 1
                    break
                elif sol:
                    detect_results[:] = detect_results[: i + 1]
                    print("just trimmed cve number: ", item['id'])
                    break
    
    with open(file_name, 'w') as f:
        json.dump(data, f, indent=4)