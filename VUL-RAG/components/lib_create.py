import json
import os


JSON_FILE = 'library_length.json'

def initialize_file():
    if not os.path.isfile(JSON_FILE):
        data = {
            "CWE_ID": "",
            "CVE_ID": "",
            "LibEntry": 0
        }
        try:
            with open(JSON_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"{JSON_FILE} created successfully.")
        except Exception as e:
            print(f"Failed to create {JSON_FILE}: {e}")


if __name__ == '__main__':
    initialize_file()