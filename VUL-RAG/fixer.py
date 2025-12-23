import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from pathlib import Path
from common import constant
import copy
from common.util.common_util import merge_batch_logs



cwes = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]

for cwe in cwes:

    batch_log_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark="PairVul")) / "metrics" / f"{cwe}log.json"
    batch_output_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark="PairVul")) /constant.BATCH_OUTPUT_NAME.format(cwe=cwe)
    
    total_input = 0
    total_output = 0

    with open(batch_output_path, "r", encoding="utf-8") as file_response:
        for line in file_response:
            if not line:
                continue

            data = json.loads(line)
            usage = data.get("response", {}).get("body", {}).get("usage", {})
            total_input += usage.get("prompt_tokens", 0)
            total_output += usage.get("completion_tokens", 0)

    with open (batch_log_path, "r", encoding="utf-8")as f:
        old_entry = json.load(f)
    
    entry = copy.deepcopy(constant.BATCH_LOG_FORMAT)
    entry["input_tokens"] = total_input
    entry["output_tokens"] = total_output

    with open (batch_log_path, "w", encoding="utf-8")as f:
        json.dump(entry, f)
    
merge_batch_logs(Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark="PairVul")) / "metrics", None, "gpt-3.5-turbo")


