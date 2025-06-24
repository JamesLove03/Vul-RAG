import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from common.util import common_util


if __name__ == '__main__':

    common_util.calculate_VD_metrics("gpt-4o")
    common_util.calculate_VD_metrics("gpt-4o\\CWE-119_gpt-4o.json")
    common_util.calculate_VD_metrics("gpt-4o\\CWE-362_gpt-4o.json")
    common_util.calculate_VD_metrics("gpt-4o\\CWE-787_gpt-4o.json")
    common_util.calculate_VD_metrics("gpt-4o\\CWE-476_gpt-4o.json")
    common_util.calculate_VD_metrics("gpt-4o\\CWE-416_gpt-4o.json")
