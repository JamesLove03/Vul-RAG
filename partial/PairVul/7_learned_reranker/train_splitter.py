import json
import os
import random
from pathlib import Path

# ---------------- CONFIG ----------------
ROOT_DIR = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT_DIR / ("2_elasticsearch_ready")      # folder with original CWE jsons
OUTPUT_TRAIN_DIR = ROOT_DIR / ("7_learned_reranker/train")
OUTPUT_TEST_DIR = ROOT_DIR / ("7_learned_reranker/test")

# Folder where true items live (used later by you)
TRUE_ITEM_DIR = ROOT_DIR / ("1_raw_data/train")

CWES = [
    "CWE-20", "CWE-119", "CWE-125", "CWE-200", "CWE-264",
    "CWE-362", "CWE-401", "CWE-416", "CWE-476", "CWE-787"
]

TRAIN_RATIO = 0.8
RANDOM_SEED = 47
# ----------------------------------------

random.seed(RANDOM_SEED)
OUTPUT_TRAIN_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_TEST_DIR.mkdir(parents=True, exist_ok=True)

def flatten_items(cve_dict):
    """
    Takes:
        { "CVE-XXXX": [item1, item2, ...], ... }
    Returns:
        list of items, ignoring top-level CVE keys
    """
    items = []
    for _, item_list in cve_dict.items():
        items.extend(item_list)
    return items

for cwe in CWES:
    input_path = INPUT_DIR / f"gpt-3.5-turbo_{cwe}_316_pattern_all.json"

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = flatten_items(data)
    random.shuffle(items)

    split_idx = int(len(items) * TRAIN_RATIO)
    train_items = items[:split_idx]
    test_items = items[split_idx:]

    # ---------------- TRAIN OUTPUT ----------------
    train_output = {}
    for cve_key, item_list in data.items():
        # only keep items that are in train split
        train_items_filtered = [item for item in item_list if item in train_items]
        if train_items_filtered:
            train_output[cve_key] = train_items_filtered

    with open(OUTPUT_TRAIN_DIR / f"gpt-3.5-turbo_{cwe}_316_pattern_all.json", "w", encoding="utf-8") as f:
        json.dump(train_output, f, indent=4)

    # ---------------- TEST OUTPUT ----------------
    # Only store references using true_id
    true_item_index = {}

    path = TRUE_ITEM_DIR / f"Linux_kernel_{cwe}_clean_data.json"
    with open(path, "r", encoding="utf-8") as f:
        items = json.load(f)
        for item in items:
            true_item_index[item["id"]] = item
    
    test_output = [
        true_item_index[item["true_id"]]
        for item in test_items
        if item["true_id"] in true_item_index
    ]

    with open(OUTPUT_TEST_DIR / f"Linux_kernel_{cwe}_clean_data_testset_new.json", "w", encoding="utf-8") as f:
        json.dump(test_output, f, indent=4)

    print(f"{cwe}: {len(train_items)} train / {len(test_items)} test")