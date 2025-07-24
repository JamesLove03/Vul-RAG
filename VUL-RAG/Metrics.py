import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tqdm import tqdm
import os
from common import config as cfg
from common.util import common_util
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from common import constant





if __name__ == '__main__':
    
    cwes = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
    
    result_dir_list = []

    for cwe in cwes:
        
        result_file_name = constant.VULRAG_DETECTION_RESULT_FILE_NAME.format(
            cwe_id = cwe, 
            model_name = "gpt-4o",
            summary_model_name = "gpt-4o",
            model_settings = "default-settings"
        )
        
        output_path = PathUtil.vul_detection_output(
            result_file_name,
            "json",
            "gpt-4o",
            "gpt-4o",
            "default-settings"
        )
        # result_dir_list.append(os.path.dirname(output_path))    
    
    directory = "C:/Coding/Work/Vul-RAG/Vul-RAG/output/vul_detection_data/gpt-4o_gpt-4o-mini/default-settings"
    common_util.calculate_VD_metrics(directory)

    # result_dir_list = list(set(result_dir_list))
    # assert len(result_dir_list) == 1
    # for result_dir in result_dir_list:
    #     common_util.calculate_VD_metrics(result_dir)
    #     print(result_dir)