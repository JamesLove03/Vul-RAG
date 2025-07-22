import json

def extract_true_ids(input_filename, output_filename):
    with open(input_filename, 'r') as infile:
        data = json.load(infile)

    true_ids = []
    for cve_entries in data.values():
        for entry in cve_entries:
            if 'true_id' in entry:
                true_ids.append(entry['true_id'])

    with open(output_filename, 'w') as outfile:
        json.dump(true_ids, outfile, indent=2)

# Example usage:
extract_true_ids('gpt-3.5-turbo_CWE-401_316_pattern_all.json', 'true_ids.json')