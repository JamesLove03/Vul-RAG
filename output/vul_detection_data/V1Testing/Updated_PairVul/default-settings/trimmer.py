import json
import os

# List of CWE IDs
cwe_ids = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787", "CWE-20", "CWE-125", "CWE-200", "CWE-264", "CWE-401"]

#This file will trim my results down to top 3 and fix the final_result variable in the json 

for cwe_id in cwe_ids:
    file_name = f"{cwe_id}_gpt-4o-gpt-4o-mini_VulRAG-detection_default-settings.json"
    rank_sum = 0
    id_results = {}
    if not os.path.exists(file_name):
        print(f"File {file_name} not found. Skipping.")
        continue

    with open(file_name, 'r') as f:
        data = json.load(f)

    for category in ["vul_data", "non_vul_data"]:
        entries = data.get(category, [])

        for item in entries:
            detect_results = item.get("detect_result", [])

            vul_knowledge_items = [dr for dr in detect_results if "vul_knowledge" in dr]

            trimmed = []
            for dr in detect_results:
                
                trimmed.append(dr)

                vul_output = dr.get("vul_output", "").upper()
                sol_output = dr.get("sol_output", "").upper()

                vul_decision = "### YES ###" in vul_output
                sol_decision = "### YES ###" in sol_output
                    
                if sol_decision:
                    item["final_result"] = 0  
                    break
                    
                elif vul_decision:
                    item["final_result"] = 1
                    break
                    
            item["detect_result"] = trimmed

    with open(file_name, 'w') as f:
        json.dump(data, f, indent=4)