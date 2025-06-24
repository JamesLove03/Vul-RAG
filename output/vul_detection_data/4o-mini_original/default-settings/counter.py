import json
import os

CWES = ["CWE-119", "CWE-362", "CWE-476", "CWE-787", "CWE-416"]  # Replace with your JSON file path

output_file = "CWE-119.txt"

totalcount = { #calculates total numbers across all CWEs
    "True_Positive": 0,
    "True_Negative": 0,
    "False_Positive": 0,
    "False_Negative": 0,
    "Accurate Pair Count": 0,
    "Valid Pair Count": 0,
    "Pair Accuracy": 0,
    "Num top 5": 0,
    "Sum of Lib Ranks": 0,
    "Average correct Rank": 0,
    "Library hit rate": 0,
    "Num Correct Lib": 0,
    "Num wrong Lib": 0,
    "Num total Lib": 0,
    "Lib Decision Rate": 0,
    "Lib Correct Decision Rate": 0,
    "Lib Wrong Decision Rate": 0,
    "Non-Lib Decision Rate": 0,
    "Non-lib correct rate": 0,
    "Non-lib wrong rate": 0,
    "Non-lib wrong sum": 0,
    "non-lib correct sum": 0,
    "No decision correct rate": 0,
    "No decision wrong rate": 0, 
    "No decision pick rate": 0,
    "No decision correct sum": 0,
    "No decision wrong sum": 0,
    "Balanced Recall": 0,
    "Balanced Precision": 0,
}


categories = { #calculates numebers for each individual CWE
        "True Positive": 0,
        "True Negative": 0,
        "False Positive": 0,
        "False Negative": 0,
        "Other": 0,
        "Accurate Pair Count": 0,
        "Valid Pair Count": 0,
        "Accurate Library Count": 0,
        "Accurate Library Rate":  0,
        "Pair Accuracy": 0,
        "Average Library Match": 0
    }

entrysumNV = 0

def process_non_vul(entry):
    
    entry_cve = entry.get("cve_id", "") #searches for the cve of the overall entry
    match_found = False 
    entry_count = 0 #will count the number of library entries processed
    found = 0 #flag to show if the output was found or if we ran out of entries
    global entrysumNV   
    library(entry, entry_cve)


    for result in entry.get("detect_result", []): #for each vulknowledge entry
        entry_count += 1
        vul_output = result.get("vul_output", "")
        sol_output = result.get("sol_output", "")


        knowledge = result.get("vul_knowledge", {})
        if knowledge.get("cve_id", "") == entry_cve:
            match_found = True            

        if ("NO" in vul_output): #code in non-vul continue to next entry
            entrysumNV += entry_count
            continue #repeats if no vul is found
        elif "YES" in sol_output: #code is vulnerable but patched add to True negative
            entrysumNV += entry_count
            if knowledge.get("cve_id", "") == entry_cve:
                totalcount["Num Correct Lib"] += 1
            else:
                totalcount["non-lib correct sum"] += 1
            categories["True Negative"] += 1
            found = 1
            break
        elif "NO" in sol_output: #Code is vulnerable add to false pos
            entrysumNV += entry_count
            if knowledge.get("cve_id", "") == entry_cve:
                totalcount["Num wrong Lib"] += 1
            else:
                totalcount["Non-lib wrong sum"] += 1
            categories["False Positive"] += 1
            found = -1
            break


    if found == 0: #run out of entries means add to True Negative in this case
        categories["True Negative"] += 1
        found = 1
        totalcount["No decision correct sum"] += 1

    if match_found == True:
        categories["Accurate Library Count"] += 1

    return found


def count(filename):
    
    global categories
    categories = {
        "True Positive": 0,
        "True Negative": 0,
        "False Positive": 0,
        "False Negative": 0,
        "Other": 0,
        "Accurate Pair Count": 0,
        "Valid Pair Count": 0,
        "Accurate Library Count": 0,
        "Accurate Library Rate":  0,
        "Pair Accuracy": 0,
        "Average Library Match": 0
    }

    base_name = os.path.splitext(filename)[0]  # create output filename
    output_filename = f"{base_name}_stats.json"
    
    try:
        with open(filename, "r", encoding="utf-8") as f: #open the filename passed
            data = json.load(f)

            vul_data = data["vul_data"] #load the data into a variable
            non_vul_data = data["non_vul_data"]

            global entrysumNV 
            entrysumNV = 0 #counter for calculating the average position the code ends on (average library entry)
            total_entries = 0 #will be used to calculate total number of entries for %
            
            non_vul_lookup = {entry["id"]: entry for entry in non_vul_data} #will lookup and return matching non_vul entry for the current vul_entry

            for entry in vul_data: #iterates through all entries in vul_data
                vul_id = entry["id"]
                non_vul_entry = non_vul_lookup.get(vul_id) #gets the matching entry

                nonvuloutput = process_non_vul(non_vul_entry) #handles the non_vul pair

                total_entries += 1 #counts both entries being added
                entry_count = 0 #will count the number of library entries processed
                found = 0 #flag to show if the output was found or if we ran out of entries
                
                entry_cve = entry.get("cve_id", "") #searches for the cve of the overall entry
                match_found = False 
                library(entry, entry_cve)


                for result in entry.get("detect_result", []): #for each vulknowledge entry
                    
                    entry_count += 1
                    vul_output = result.get("vul_output", "")
                    sol_output = result.get("sol_output", "")
                    
                    knowledge = result.get("vul_knowledge", {})
                    if knowledge.get("cve_id", "") == entry_cve:
                        match_found = True
                        totalcount["Sum of Lib Ranks"] += entry_count        

                    if ("NO" in vul_output): #code in non-vul continue to next entry
                        entrysumNV += entry_count
                        continue #repeats if no vul is found
                    elif "YES" in sol_output: #code is vulnerable but patched add to false negative
                        entrysumNV += entry_count
                        categories["False Negative"] += 1
                        if knowledge.get("cve_id", "") == entry_cve:
                            totalcount["Num wrong Lib"] += 1
                        else:
                            totalcount["Non-lib wrong sum"] +=1
                        found = -1
                        break
                    elif "NO" in sol_output: #Code is vulnerable add to true pos
                        entrysumNV += entry_count
                        categories["True Positive"] += 1
                        if knowledge.get("cve_id", "") == entry_cve:
                            totalcount["Num Correct Lib"] += 1
                        else:
                            totalcount["non-lib correct sum"] += 1
                        found = 1
                        break

                if found == 0: #run out of entries means add to False Negative in this case
                    categories["False Negative"] += 1
                    totalcount["No decision wrong sum"] += 1

                if match_found == True:
                    categories["Accurate Library Count"] += 1

                if (nonvuloutput == 1 and found == 1):
                    categories["Accurate Pair Count"] += 1

        categories["Valid Pair Count"] = total_entries

        categories["Accurate Library Rate"] = categories["Accurate Library Count"] / categories["Valid Pair Count"]

        categories["Pair Accuracy"] = categories["Accurate Pair Count"] / categories["Valid Pair Count"]

        categories["Average Library Match"] = entrysumNV / categories["Valid Pair Count"]

        with open(output_filename, "w", encoding="utf-8") as out:
            json.dump(categories, out, indent=4)


                
        totalcount["True_Negative"] += categories["True Negative"]
        totalcount["False_Negative"] += categories["False Negative"]
        totalcount["True_Positive"] += categories["True Positive"]
        totalcount["False_Positive"] += categories["False Positive"]
        totalcount["Valid Pair Count"] += categories["Valid Pair Count"]
        totalcount["Accurate Pair Count"] += categories["Accurate Pair Count"]

    except FileNotFoundError:
        print(f"File {filename} not found.")
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")




def library(data, cve):
    entry_count = 0
    for result in data.get("detect_result", []):
        entry_count += 1
        knowledge = result.get("vul_knowledge", {})
        if knowledge.get("cve_id", "") == cve:
            totalcount["Num top 5"] += 1
            totalcount["Sum of Lib Ranks"] += (entry_count)  # iterates if the cves match
           
            

if __name__ == '__main__':
    for item in CWES: #calls for all files within the folder
        name =  f"{item}_gpt-4o-mini-gpt-4o-mini_VulRAG-detection_default-settings.json"
        count(name)
    
    totalcount["Pair Accuracy"] = totalcount["Accurate Pair Count"] / totalcount["Valid Pair Count"]
    totalcount["Average correct Rank"] = totalcount["Sum of Lib Ranks"] / totalcount["Num top 5"]
    totalcount["Library hit rate"] = totalcount["Num top 5"] / (totalcount["Valid Pair Count"] * 2) 
    totalcount["Num total Lib"] = totalcount["Num wrong Lib"] + totalcount["Num Correct Lib"]
    totalcount["Lib Decision Rate"] = totalcount["Num total Lib"] / ( 2 * totalcount["Valid Pair Count"])
    totalcount["Lib Correct Decision Rate"] = totalcount["Num Correct Lib"] / (totalcount["Num Correct Lib"] + totalcount["Num wrong Lib"])
    totalcount["Lib Wrong Decision Rate"] = totalcount["Num wrong Lib"] / (totalcount["Num Correct Lib"] + totalcount["Num wrong Lib"])
    totalcount["Non-Lib Decision Rate"] = (( 2 * totalcount["Valid Pair Count"]) - totalcount["Num total Lib"]) / ( 2 * totalcount["Valid Pair Count"])
    totalcount["Non-lib correct rate"] = totalcount["non-lib correct sum"] / (( 2 * totalcount["Valid Pair Count"]) - totalcount["Num total Lib"])
    totalcount["Non-lib wrong rate"] = totalcount["Non-lib wrong sum"] / (( 2 * totalcount["Valid Pair Count"]) - totalcount["Num total Lib"])
    totalcount["No decision correct rate"] = totalcount["No decision correct sum"] / (totalcount["No decision wrong sum"] + totalcount["No decision correct sum"])
    totalcount["No decision wrong rate"] = totalcount["No decision wrong sum"] / (totalcount["No decision wrong sum"] + totalcount["No decision correct sum"])
    totalcount["No decision pick rate"] = (totalcount["No decision wrong sum"] + totalcount["No decision correct sum"]) / ( 2 * totalcount["Valid Pair Count"])
    totalcount["Balanced Recall"] = (totalcount["True_Positive"] / totalcount["Valid Pair Count"] + totalcount["True_Negative"] / totalcount["Valid Pair Count"]) / 2
    totalcount["Balanced Precision"] = ( totalcount["True_Positive"] / (totalcount["True_Positive"] + totalcount["False_Positive"]) + totalcount["True_Negative"] / (totalcount["True_Negative"] + totalcount["False_Negative"])) / 2


    with open("final_metrics", "w", encoding="utf-8") as out:
        json.dump(totalcount, out, indent=4)
        