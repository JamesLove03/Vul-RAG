import json
import os

def check_train_test_cve_coverage(
    cwes,
    train_dir="train",
    test_dir="test"
):
    total_test_items = 0
    covered_test_items = 0

    for cwe in cwes:
        train_path = os.path.join(
            train_dir, f"Linux_kernel_{cwe}_clean_data.json"
        )
        test_path = os.path.join(
            test_dir, f"Linux_kernel_{cwe}_clean-data_testset_new.json"
        )

        if not os.path.exists(train_path) or not os.path.exists(test_path):
            print(f"[WARN] Missing files for {cwe}, skipping.")
            continue

        with open(train_path, "r", encoding="utf-8") as f:
            train_data = json.load(f)

        with open(test_path, "r", encoding="utf-8") as f:
            test_data = json.load(f)

        # Collect all CVEs present in train
        train_cves = set(item["cve_id"] for item in train_data)

        for item in test_data:
            total_test_items += 1
            if item["cve_id"] in train_cves:
                covered_test_items += 1

    if total_test_items == 0:
        coverage_pct = 0.0
    else:
        coverage_pct = (covered_test_items / total_test_items) * 100

    print("=== Train/Test CVE Coverage ===")
    print(f"Covered test items : {covered_test_items}")
    print(f"Total test items   : {total_test_items}")
    print(f"Coverage           : {coverage_pct:.2f}%")


if __name__ == "__main__":
    cwes = [
    "CWE-416", "CWE-476", "CWE-362", "CWE-119", "CWE-787",
    "CWE-20", "CWE-200", "CWE-125", "CWE-264", "CWE-401"
]
    check_train_test_cve_coverage(cwes)