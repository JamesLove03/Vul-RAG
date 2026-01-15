from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))
from common.util.common_util import calculate_additional_metrics, calculate_VD_metrics




current_path = Path.cwd() / 'data'
print(current_path)
cwe_list = ["CWE-20", "CWE-119", "CWE-125", "CWE-200", "CWE-264", "CWE-362", "CWE-401", "CWE-416", "CWE-476", "CWE-787"]

calculate_VD_metrics(str(current_path))

calculate_additional_metrics(current_path, cwe_list)