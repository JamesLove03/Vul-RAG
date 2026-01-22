import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pdb
import logging
from util.path_util import PathUtil
from util.data_utils import DataUtils
import constant
from constant import MetricsKeywords as mk
import config as cfg
import copy
import json
from pathlib import Path


def merge_batch_logs(batch_dir, prev_batch, model_name):
    entry = copy.deepcopy(constant.BATCH_LOG_FORMAT)
    input_tok = 0
    output_tok = 0
    total_items = 0
    run_time = 0

    for file in Path(batch_dir).iterdir():
        if file.name == "final_log.json":
            continue
        with file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        input_tok += data["input_tokens"] 
        output_tok += data["output_tokens"]
        total_items += data["total_batch_items"]
        run_time += data["batch_runtime"]

    entry["custom_id"] = "Summarized Log Files"
    entry["input_tokens"] = input_tok
    entry["output_tokens"] = output_tok
    entry["total_batch_items"] = total_items
    entry["batch_runtime"] = run_time
    entry["model_name"] = model_name
    entry["prev_log"] = prev_batch

    output_path = Path(batch_dir) / "final_log.json" 
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(entry, f)
        f.write("\n")


def fill_batch_log(id, inp, out, num_items, modelname, prev_path, output_path, runtime):
    entry = copy.deepcopy(constant.BATCH_LOG_FORMAT)
    entry["custom_id"] = id
    entry["input_tokens"] = inp
    entry["output_tokens"] = out
    entry["total_batch_items"] = num_items
    entry["model_name"] = modelname
    entry["prev_log"] = prev_path
    entry["batch_runtime"] = runtime
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("a", encoding="utf-8") as f:
        json.dump(entry, f)
        f.write("\n")

def merge_search_log(search_log_dir, prev_path, embeddings, k_val, output_path):
    searched = 0
    returned = 0
    runtime = 0

    for file in Path(search_log_dir).iterdir():
        if file.name == "final_log.json":
            continue
        with file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        searched += data["searched_items"]
        returned += data["returned_items"]
        runtime += data["runtime"]

    entry = copy.deepcopy(constant.SEARCH_LOG_FORMAT)
    entry["custom_id"] = "Final merged log for searching BEFORE reranking. Performed using full fill blanks."
    entry["runtime"] = runtime
    entry["searched_items"] = searched
    entry["returned_items"] = returned
    entry["runtime"] = runtime
    entry["embeddings_included"] = embeddings
    entry["prev_log"] = str(prev_path)
    entry["K-value"] = k_val

    with output_path.open("a", encoding="utf-8") as f:
        json.dump(entry, f)
        f.write("\n")


def fill_search_log(id, num_items, returned_items, embeddings, prev_path, output_path, runtime, k_val):
    entry = copy.deepcopy(constant.SEARCH_LOG_FORMAT)
    entry["custom_id"] = id
    entry["runtime"] = runtime
    entry["searched_items"] = num_items
    entry["returned_items"] = returned_items
    entry["embeddings_included"] = embeddings
    entry["prev_log"] = prev_path
    entry["K-value"] = k_val

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("a", encoding="utf-8") as f:
        json.dump(entry, f)
        f.write("\n")


def fill_template(model:str, message:list, id:int):
    final_list = []
    
    if "gpt" in model:
        entry = copy.deepcopy(constant.GPT_BATCH_TEMPLATE)
        entry["custom_id"] = str(id)
        entry["body"]["model"] = model
        entry["body"]["messages"] = message
        entry["body"]["max_tokens"] = cfg.DEFAULT_MAX_TOKENS

    elif "claude" in model:
        user_messages = [m for m in message if m.get("role") == "user"]
        system_prompt = next( (m["content"] for m in message if m["role"] == "system"), "")

        entry = copy.deepcopy(constant.ANTHROPIC_BATCH_TEMPLATE)
        entry["custom_id"] = str(id)
        entry["params"]["model"] = model
        entry["params"]["messages"] = user_messages
        entry["params"]["max_tokens"] = cfg.DEFAULT_MAX_TOKENS
        entry["params"]["system"] = system_prompt
        
    elif "gemini" in model:
        entry = copy.deepcopy(constant.GEMINI_BATCH_TEMPLATE)
        entry["key"] = str(id)
        entry["request"]["generationConfig"]["maxOutputTokens"] = cfg.DEFAULT_MAX_TOKENS
        user_content = next( (m["content"] for m in message if m["role"] == "user"), None)
        entry["request"]["contents"][0]["parts"][0]["text"] = user_content
        entry["request"]["model"] = "models/" + model
        entry["request"]["system_instruction"]["parts"][0]["text"] = constant.DEFAULT_SYS_PROMPT
        
    else:
        raise Exception("There is no batch template for that model!")
    
    return entry


def update_log(log_dir: str, item_key: str, **kwargs):
    path = Path(log_dir) / "log.json"

    if not path.exists():
        with path.open("w") as f:
            json.dump({}, f, indent=2)

    with path.open("r") as f:
        data = json.load(f)

    if item_key not in data:
        data[item_key] = constant.LOG_FORMAT.copy()

    for key, value in kwargs.items():
        if key in data[item_key]:
            data[item_key][key] = value
    
    with path.open("w") as f:
        json.dump(data, f, indent=2)

    # EXAMPLE USAGE
    # update_log(
    # "logs/runtime.json",
    # "Item1",
    # start_time="2025-12-12T10:00:00",
    # input_tokens=1500,
    # explanation="First run of the day"
    # )


def add_item_id_for_detection_result(detection_result_file: str, cwe_id: str):
    clean_data = DataUtils.load_json(
        PathUtil.clean_data(constant.CLEAN_DATA_FILE_NAME.format(cwe_id = cwe_id), "json")
    )
    code_id_map = {}
    for data_item in clean_data:
        code_id_map[data_item['code_before_change'] + data_item['cve_id']] = data_item['id']
        code_id_map[data_item['code_after_change'] + data_item['cve_id']] = data_item['id']
    detection_result_data = DataUtils.load_json(detection_result_file)
    vul_data = detection_result_data.get('vul_data', []) + detection_result_data.get('vul_detect_data', [])
    for item in vul_data:
        if item['code_snippet'] + item['cve_id'] in code_id_map:
            item['id'] = code_id_map[item['code_snippet'] + item['cve_id']]
        else:
            print(item['code_snippet'])

    non_vul_data = detection_result_data.get('non_vul_data', []) + detection_result_data.get('non_vul_detect_data', [])
    for item in non_vul_data:
        if item['code_snippet'] + item['cve_id'] in code_id_map:
            item['id'] = code_id_map[item['code_snippet'] + item['cve_id']]
        else:
            print(item['code_snippet'])

    DataUtils.save_json(detection_result_file, detection_result_data)

def parse_kv_string_to_dict(
        key_value_string: str, 
        arg_sep: str = ";",
        kv_sep: str = "="
    ) -> dict:
    """
    This function parses a key-value string argument into a dictionary.
    The input string should have key-value pairs separated by 'arg_sep' (default is ';')
    and keys and values separated by 'kv_sep' (default is '=').
    For example, the string "key1=value1;key2=value2" will be parsed into the dictionary
    {"key1": "value1", "key2": "value2"}.
    The function also attempts to convert the values to int, float, or boolean types if possible.
    """
    key_value_list = key_value_string.split(arg_sep)
    key_value_dict = {}
    for key_value in key_value_list:
        try:
            key, value_str = key_value.split(kv_sep, 1)
        except ValueError:
            logging.warning(f"Skipping invalid key-value pair: {key_value}")
            continue
        key = key.strip()
        value_str = value_str.strip()
        try:
            value = int(value_str)
        except ValueError:
            try:
                value = float(value_str)
            except ValueError:
                if value_str.lower() == "true":
                    value = True
                elif value_str.lower() == "false":
                    value = False
                else:
                    value = value_str
        key_value_dict[key] = value
    return key_value_dict

def extract_LLM_response_by_prefix(response: str, prefix: str) -> str:
    """
    This function extracts the response from the LLM output that is prefixed by a given string.
    """
    if prefix in response:
        return response.split(prefix)[1].strip()
    else:
        return response.strip()
    
def match_LLM_response_by_keyword(response: str, keyword: str, separator: str) -> str:
    """
    This function matches the response from the LLM output by a given keyword and separator.
    """
    response_list = response.split(separator)
    for item in response_list:
        if keyword in item:
            return item.split(keyword)[1].strip()
    return ""


def calculate_metrics(**confusion_matrix) -> dict:
    print("calc_metrics was called")
    """
    Calculate various performance metrics based on the provided confusion matrix.
    Args:
        **confusion_matrix: A dictionary containing the confusion matrix values.
            Expected keys are:
            - 'True Negative': True Negative count
            - 'True Positive': True Positive count
            - 'False Negative': False Negative count
            - 'False Positive': False Positive count
            - 'id_result_map' (optional): A list of tuples, where each tuple contains two dictionaries.
                Each dictionary should have the following keys:
                - 'id': Identifier for the item
                - 'Prediction': Predicted value
                - 'Ground Truth': Ground truth value
    Returns:
        dict: A dictionary containing the calculated metrics:
            - 'Precision': Average Precision
            - 'Recall': Average Recall
            - 'F1 Score': F1 Score
            - 'Accuracy': Accuracy
            - 'False Negative Rate': False Negative Rate
            - 'False Positive Rate': False Positive Rate
            - 'True Negative Rate': True Negative Rate
            - 'True Positive Rate': True Positive Rate
            - 'Valid Pair Count' (if 'id_result_map' is provided): Valid Pair Count
            - 'Accurate Pair Count' (if 'id_result_map' is provided): Accurate Pair Count
            - 'Pair Accuracy' (if 'id_result_map' is provided): Pair Accuracy
            - 'Pair_1 Rate' (if 'id_result_map' is provided): Pair_1 Rate
            - 'Pair_0 Rate' (if 'id_result_map' is provided): Pair_0 Rate
    Raises:
        ValueError: If the confusion matrix does not contain TN, TP, FN, and FP.
    """
    TN = confusion_matrix.get(mk.TN.value)
    TP = confusion_matrix.get(mk.TP.value)
    FN = confusion_matrix.get(mk.FN.value)
    FP = confusion_matrix.get(mk.FP.value)
    CLE = confusion_matrix.get(mk.CLE.value)
    WLE = confusion_matrix.get(mk.WLE.value)
    NDC = confusion_matrix.get(mk.NDC.value)
    ND = confusion_matrix.get(mk.ND.value)
    PLE = confusion_matrix.get(mk.PLE.value)
    VBS = confusion_matrix.get(mk.VBS.value)
    SBS = confusion_matrix.get(mk.SBS.value)
    
    if TN is None or TP is None or FN is None or FP is None:
        logging.error("The confusion matrix must contain TN, TP, FN, and FP.")
        raise ValueError("The confusion matrix must contain TN, TP, FN, and FP.")

    pos_precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    pos_recall = TP / (TP + FN) if (TP + FN) > 0 else 0

    neg_precision = TN / (TN + FN) if (TN + FN) > 0 else 0
    neg_recall = TN / (TN + FP) if (TN + FP) > 0 else 0

    correct_no_lib_entries = (TP+TN) - CLE - NDC
    num_entries = FN + FP+ TN+ TP
    if (num_entries - WLE - CLE - ND) == 0:
        misinformed_acc = 0
    else:
        misinformed_acc = correct_no_lib_entries /  (num_entries - WLE - CLE - ND)
    
    informed_acc = CLE / (CLE + WLE)

    informed_rate = (CLE + WLE) / (num_entries - ND)
    misinformed_rate = 1 - informed_rate
    no_dec_rate = ND / num_entries
    presence_rate = PLE / num_entries

    precision = (pos_precision + neg_precision) / 2
    recall = (pos_recall + neg_recall) / 2

    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
    FN_rate = FN / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    FP_rate = FP / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    TN_rate = TN / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    TP_rate = TP / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1

    #add brier scores and average items
    avg_vul_brier = VBS / (num_entries - ND)
    avg_sol_brier = SBS / (num_entries - ND)

    result_map = {
        mk.PC.value: round(precision, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.RC.value: round(recall, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.F1.value: round(f1, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.AC.value: round(accuracy, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.FNR.value: round(FN_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.FPR.value: round(FP_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.TNR.value: round(TN_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.TPR.value: round(TP_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.MA.value: round(misinformed_acc, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.IA.value: round(informed_acc, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.MDR.value: round(misinformed_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.IDR.value: round(informed_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.NDR.value: round(no_dec_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.PR.value: round(presence_rate, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.VB.value: round(avg_vul_brier, cfg.METRICS_DECIMAL_PLACES_RESERVED),
        mk.SB.value: round(avg_sol_brier, cfg.METRICS_DECIMAL_PLACES_RESERVED)
    }

    if mk.TSC.value in confusion_matrix:
        TSC = confusion_matrix.get(mk.TSC.value)
        TVC = confusion_matrix.get(mk.TVC.value)

        result_map[mk.ATSC.value] = round((TSC / num_entries), cfg.METRICS_DECIMAL_PLACES_RESERVED)
        result_map[mk.ATVC.value] = round((TVC / num_entries), cfg.METRICS_DECIMAL_PLACES_RESERVED)

        for i in range(1, 11):
            skey = mk.SCS.value.format(num = i)
            vkey = mk.VCS.value.format(num = i)
            if skey in confusion_matrix:
                if confusion_matrix.get(mk.EN.value.format(num=i)) == 0:
                    result_map[mk.ASCS.value.format(num=i)] = 0
                    result_map[mk.AVCS.value.format(num=i)] = 0
                else:

                    result_map[mk.ASCS.value.format(num=i)] = round((confusion_matrix.get(skey) / confusion_matrix.get(mk.EN.value.format(num=i))), cfg.METRICS_DECIMAL_PLACES_RESERVED)
                    result_map[mk.AVCS.value.format(num=i)] = round((confusion_matrix.get(vkey) / confusion_matrix.get(mk.EN.value.format(num=i))), cfg.METRICS_DECIMAL_PLACES_RESERVED)
            else:
                break

    id_result_map = confusion_matrix.get('id_result_map')
    if id_result_map:
        print("id_result_map accessed")
        valid_pair_cnt = 0
        accurate_pair_cnt = 0
        pair_1_cnt = 0
        pair_0_cnt = 0
        for item_id, item_pair in id_result_map.items():
            assert len(item_pair) == 2, f"Invalid item pair for ID {item_id}."
            assert item_pair[0]['id'] == item_pair[1]['id'], f"ID mismatch for ID {item_id}."
            assert mk.PD.value in item_pair[0] and mk.PD.value in item_pair[1], f"PD value not found for ID {item_id}."
            assert mk.GT.value in item_pair[0] and mk.GT.value in item_pair[1], f"GT value not found for ID {item_id}."
            if item_pair[0][mk.PD.value] == item_pair[0][mk.GT.value] and \
                item_pair[1][mk.PD.value] == item_pair[1][mk.GT.value]:
                accurate_pair_cnt += 1
            if item_pair[0][mk.PD.value] == 1 and item_pair[1][mk.PD.value] == 1:
                pair_1_cnt += 1
            if item_pair[0][mk.PD.value] == 0 and item_pair[1][mk.PD.value] == 0:
                pair_0_cnt += 1
            valid_pair_cnt += 1

        result_map[mk.VPC.value] = valid_pair_cnt
        result_map[mk.APC.value] = accurate_pair_cnt
        result_map[mk.P1C.value] = pair_1_cnt
        result_map[mk.P0C.value] = pair_0_cnt
        result_map[mk.PAC.value] = accurate_pair_cnt / valid_pair_cnt if valid_pair_cnt > 0 else -1
        result_map[mk.P1R.value] = pair_1_cnt / valid_pair_cnt if valid_pair_cnt > 0 else -1
        result_map[mk.P0R.value] = pair_0_cnt / valid_pair_cnt if valid_pair_cnt > 0 else -1
        result_map[mk.PAC.value] = round(result_map[mk.PAC.value], cfg.METRICS_DECIMAL_PLACES_RESERVED)
        result_map[mk.P1R.value] = round(result_map[mk.P1R.value], cfg.METRICS_DECIMAL_PLACES_RESERVED)
        result_map[mk.P0R.value] = round(result_map[mk.P0R.value], cfg.METRICS_DECIMAL_PLACES_RESERVED)
        
    return result_map

def calculate_VD_metrics(result_file_or_dir: str, save_to_file: bool = True, max_items: int=10, V2=False):
    target_result_file_list = []
    calculate_total_metrics_flag = False
    if os.path.exists(result_file_or_dir) and os.path.isdir(result_file_or_dir):
        target_result_file_list = [
            os.path.join(result_file_or_dir, file_name) for 
            file_name in os.listdir(result_file_or_dir) 
            if file_name.endswith(".json") and not file_name.endswith("_metrics.json")
        ]
        calculate_total_metrics_flag = True
    elif os.path.exists(result_file_or_dir) and os.path.isfile(result_file_or_dir):
        target_result_file_list.append(result_file_or_dir)
    else:
        print(result_file_or_dir)
        raise ValueError("The result file or directory does not exist.")
    
    
    total_cfs_mat = {
        mk.TN.value: 0,
        mk.TP.value: 0,
        mk.FN.value: 0,
        mk.FP.value: 0,
        mk.PLE.value: 0,
        mk.CLE.value: 0,
        mk.WLE.value: 0,
        mk.NTP.value: 0, 
        mk.NLE.value: 0, 
        mk.ND.value: 0,
        mk.NDC.value: 0,
        mk.VBS.value: 0,
        mk.SBS.value: 0,
    }  

    for i in range(1, max_items + 1):
        total_cfs_mat[mk.EN.value.format(num=i)] = 0
        if V2:
            total_cfs_mat[mk.SCS.value.format(num=i)] = 0
            total_cfs_mat[mk.VCS.value.format(num=i)] = 0
    if V2:
        total_cfs_mat[mk.RT.value] = 0
        total_cfs_mat[mk.IT.value] = 0
        total_cfs_mat[mk.OT.value] = 0
        total_cfs_mat[mk.TSC.value] = 0
        total_cfs_mat[mk.TVC.value] = 0

    total_valid_pair_cnt = 0
    total_accurate_pair_cnt = 0
    total_pair_1_cnt = 0
    total_pair_0_cnt = 0

    for result_file in target_result_file_list:
        print("loading from: ", result_file)
        results = DataUtils.load_json(result_file)
        cfs_mat = {
            mk.TN.value: 0,  #true negative
            mk.TP.value: 0,  #true positive
            mk.FN.value: 0,  #false negative
            mk.FP.value: 0,  #false Positive
            mk.PLE.value: 0, #Counts the number of items that saw the correct library entry
            mk.CLE.value: 0, #acted on the correct library entry and got the correct answer
            mk.WLE.value: 0, #acted on the correct library entry, but got the wrong answer
            mk.NTP.value: 0, #holds the total number of entries the process handled
            mk.NLE.value: 0, #holds the number of times the correct library entry had no decision made on it
            mk.ND.value: 0,  #total number of no decision items
            mk.NDC.value: 0,  #number of items that had no decision and were marked correct
        }
        vul_brier_sum = 0
        sol_brier_sum = 0

        for i in range(1, max_items + 1):
            cfs_mat[mk.EN.value.format(num=i)] = 0
            if V2:
                cfs_mat[mk.VCS.value.format(num=i)] = 0
                cfs_mat[mk.SCS.value.format(num=i)] = 0
        if V2:
            cfs_mat[mk.RT.value] = 0
            cfs_mat[mk.IT.value] = 0
            cfs_mat[mk.OT.value] = 0
            cfs_mat[mk.TVC.value] = 0
            cfs_mat[mk.TSC.value] = 0

        # the key in the result file is ether xx_data or xx_detect_data
        vul_data = results.get('vul_detect_data', []) + results.get('vul_data', [])
        non_vul_data = results.get('non_vul_detect_data', []) + results.get('non_vul_data', [])
        id_result_map = {}

        for vul in vul_data:
            try:
                code_len = len(vul['detect_result'])
                cfs_mat[mk.NTP.value] += code_len
                cfs_mat[mk.EN.value.format(num=code_len)] += 1

                if V2:
                    vul_brier_sum += vul["vul_brier"]
                    sol_brier_sum += vul["sol_brier"]

                    if vul['final_result'] != -1:
                        final_item = vul['detect_result'][-1]
                        cfs_mat[mk.TVC.value] += final_item["vul_confidence"]
                        cfs_mat[mk.TSC.value] += final_item["sol_confidence"]
                        cfs_mat[mk.VCS.value.format(num=code_len)] += final_item["vul_confidence"]
                        cfs_mat[mk.SCS.value.format(num=code_len)] += final_item["sol_confidence"]

                    for i, item in enumerate(vul["detect_result"]):
                        cfs_mat[mk.RT.value] += round(item["runtime"], cfg.METRICS_DECIMAL_PLACES_RESERVED)
                        cfs_mat[mk.IT.value] += item["input_tokens"]
                        cfs_mat[mk.OT.value] += item["output_tokens"]
                        
                        
                if vul['final_result'] == -1:
                    cfs_mat[mk.ND.value] += 1

                if vul["lib_present"] == 1 and vul["lib_decision"] == 0:
                    cfs_mat[mk.NLE.value] += 1

                if cfg.RESULT_UNIFORM_MAP[vul['final_result']] == 0:
                    cfs_mat[mk.FN.value] += 1
                    if vul['lib_present'] == 1 and vul["lib_decision"] == 1:
                        cfs_mat[mk.WLE.value] += 1
                else:
                    cfs_mat[mk.TP.value] += 1
                    if vul['lib_present'] == 1 and vul['lib_decision'] == 1:
                        cfs_mat[mk.CLE.value] += 1
                        
                if vul["lib_present"] == 1:
                    cfs_mat[mk.PLE.value] += 1

            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Cannot find the final_result for the ID {vul['id']} in the file {result_file_or_dir}.")

            id_result_map[vul['id']] = [{
                **vul,
                mk.PD.value: cfg.RESULT_UNIFORM_MAP[vul['final_result']],
                mk.GT.value: 1
            }]

        for non_vul in non_vul_data:
            try:
                if non_vul['final_result'] == -1:
                    cfs_mat[mk.ND.value] += 1
                    cfs_mat[mk.NDC.value] += 1
                
                code_len = len(non_vul['detect_result'])
                cfs_mat[mk.NTP.value] += code_len
                cfs_mat[mk.EN.value.format(num=code_len)] += 1


                if V2:
                    vul_brier_sum += non_vul["vul_brier"]
                    sol_brier_sum += non_vul["sol_brier"]

                    if non_vul['final_result'] != -1:
                        final_item = non_vul['detect_result'][-1]
                        cfs_mat[mk.TVC.value] += final_item["vul_confidence"]
                        cfs_mat[mk.TSC.value] += final_item["sol_confidence"]
                        cfs_mat[mk.VCS.value.format(num=code_len)] += final_item["vul_confidence"]
                        cfs_mat[mk.SCS.value.format(num=code_len)] += final_item["sol_confidence"]

                    for i, item in enumerate(non_vul["detect_result"]):
                        cfs_mat[mk.RT.value] += round(item["runtime"], cfg.METRICS_DECIMAL_PLACES_RESERVED)
                        cfs_mat[mk.IT.value] += item["input_tokens"]
                        cfs_mat[mk.OT.value] += item["output_tokens"]
                                             
                        
                if non_vul["lib_present"] == 1 and non_vul["lib_decision"] == 0:
                    cfs_mat[mk.NLE.value] += 1

                if cfg.RESULT_UNIFORM_MAP[non_vul['final_result']] == 0:
                    cfs_mat[mk.TN.value] += 1
                    if non_vul['lib_present'] == 1 and non_vul["lib_decision"] == 1:
                        cfs_mat[mk.CLE.value] += 1
                else:
                    cfs_mat[mk.FP.value] += 1
                    if non_vul['lib_present'] == 1 and non_vul['lib_decision'] == 1:
                        cfs_mat[mk.WLE.value] += 1
                
                if non_vul["lib_present"] == 1:
                    cfs_mat[mk.PLE.value] += 1
                        
            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Cannot find the final_result for the ID {non_vul['id']} in the file {result_file_or_dir}.")

            id_result_map[non_vul['id']].append({
                **non_vul,
                mk.PD.value: cfg.RESULT_UNIFORM_MAP[non_vul['final_result']],
                mk.GT.value: 0
            })
            cfs_mat[mk.VBS.value] = vul_brier_sum
            cfs_mat[mk.SBS.value] = sol_brier_sum

        metrics_data = calculate_metrics(**cfs_mat, id_result_map = id_result_map)
        # logging.info(f"Result File: {result_file}")
        # logging.info(f"{mk.TP.value}: {cfs_mat.get(mk.TP.value)}")
        # logging.info(f"{mk.TN.value}: {cfs_mat.get(mk.TN.value)}")
        # logging.info(f"{mk.FP.value}: {cfs_mat.get(mk.FP.value)}")
        # logging.info(f"{mk.FN.value}: {cfs_mat.get(mk.FN.value)}")
        # logging.info(f"{mk.FNR.value}: {metrics_data.get(mk.FNR.value)}")
        # logging.info(f"{mk.FPR.value}: {metrics_data.get(mk.FPR.value)}")
        # logging.info(f"{mk.PC.value}: {metrics_data.get(mk.PC.value)}")
        # logging.info(f"{mk.RC.value}: {metrics_data.get(mk.RC.value)}")
        # logging.info(f"{mk.F1.value}: {metrics_data.get(mk.F1.value)}")
        # logging.info(f"{mk.AC.value}: {metrics_data.get(mk.AC.value)}")
        # logging.info(f"{mk.VPC.value}: {metrics_data.get(mk.VPC.value)}")
        # logging.info(f"{mk.APC.value}: {metrics_data.get(mk.APC.value)}")
        # logging.info(f"{mk.PAC.value}: {metrics_data.get(mk.PAC.value)}")
        # logging.info(f"{mk.P1R.value}: {metrics_data.get(mk.P1R.value)}")
        # logging.info(f"{mk.P0R.value}: {metrics_data.get(mk.P0R.value)}")
        # logging.info(f"{mk.P1C.value}: {metrics_data.get(mk.P1C.value)}")
        # logging.info(f"{mk.P0C.value}: {metrics_data.get(mk.P0C.value)}")
        # logging.info(f"--------------------------------------------------")
        total_cfs_mat[mk.TN.value] += cfs_mat.get(mk.TN.value)
        total_cfs_mat[mk.TP.value] += cfs_mat.get(mk.TP.value)
        total_cfs_mat[mk.FN.value] += cfs_mat.get(mk.FN.value)
        total_cfs_mat[mk.FP.value] += cfs_mat.get(mk.FP.value)
        
        if V2:
            total_cfs_mat[mk.RT.value] += cfs_mat.get(mk.RT.value)
            total_cfs_mat[mk.IT.value] += cfs_mat.get(mk.IT.value)
            total_cfs_mat[mk.OT.value] += cfs_mat.get(mk.OT.value)
            total_cfs_mat[mk.TVC.value] += cfs_mat.get(mk.TVC.value)
            total_cfs_mat[mk.TSC.value] += cfs_mat.get(mk.TSC.value)
            total_cfs_mat[mk.VBS.value] += cfs_mat.get(mk.VBS.value)
            total_cfs_mat[mk.SBS.value] += cfs_mat.get(mk.SBS.value)

        total_cfs_mat[mk.PLE.value] += cfs_mat.get(mk.PLE.value)
        total_cfs_mat[mk.CLE.value] += cfs_mat.get(mk.CLE.value)
        total_cfs_mat[mk.WLE.value] += cfs_mat.get(mk.WLE.value)
        total_cfs_mat[mk.NTP.value] += cfs_mat.get(mk.NTP.value)
        total_cfs_mat[mk.NLE.value] += cfs_mat.get(mk.NLE.value)
        total_cfs_mat[mk.ND.value] += cfs_mat.get(mk.ND.value)
        total_cfs_mat[mk.NDC.value] += cfs_mat.get(mk.ND.value)
        
        for i in range(1, max_items + 1):
            total_cfs_mat[mk.EN.value.format(num=i)] += cfs_mat[mk.EN.value.format(num=i)]
            if V2:
                total_cfs_mat[mk.VCS.value.format(num=i)] += cfs_mat[mk.VCS.value.format(num=i)]
                total_cfs_mat[mk.SCS.value.format(num=i)] += cfs_mat[mk.SCS.value.format(num=i)]

        total_valid_pair_cnt += metrics_data.get(mk.VPC.value)
        total_accurate_pair_cnt += metrics_data.get(mk.APC.value)
        total_pair_1_cnt += metrics_data.get(mk.P1C.value)
        total_pair_0_cnt += metrics_data.get(mk.P0C.value) 

        
        if save_to_file:
            try:
                check_result_file_legality(result_file)
            except Exception as e:
                logging.warning(f"The result file {result_file} is incomplete. Error: {e}")

            metrics_data = {
                **cfs_mat,
                **metrics_data
            }
            result_file_name = os.path.basename(result_file)
            result_file_name = result_file_name.replace(".json", "_metrics.json")
            result_file_name = os.path.join(os.path.dirname(result_file), result_file_name)
            DataUtils.save_json(result_file_name, metrics_data)

    print("made it through all the individual files")
    if calculate_total_metrics_flag:
        total_metrics_data = calculate_metrics(**total_cfs_mat)
        total_pair_accuracy = total_accurate_pair_cnt / total_valid_pair_cnt if total_valid_pair_cnt > 0 else -1
        total_pair_accuracy = round(total_pair_accuracy, cfg.METRICS_DECIMAL_PLACES_RESERVED)
        total_metrics_data[mk.VPC.value] = total_valid_pair_cnt
        total_metrics_data[mk.APC.value] = total_accurate_pair_cnt
        total_metrics_data[mk.PAC.value] = total_pair_accuracy
        total_metrics_data[mk.P1R.value] = round((total_pair_1_cnt / total_valid_pair_cnt), cfg.METRICS_DECIMAL_PLACES_RESERVED) if total_valid_pair_cnt > 0 else -1
        total_metrics_data[mk.P0R.value] = round((total_pair_0_cnt / total_valid_pair_cnt), cfg.METRICS_DECIMAL_PLACES_RESERVED) if total_valid_pair_cnt > 0 else -1
        logging.info(f"Total Metrics:")
        logging.info(f"{mk.TP.value}: {total_cfs_mat.get(mk.TP.value)}")
        logging.info(f"{mk.TN.value}: {total_cfs_mat.get(mk.TN.value)}")
        logging.info(f"{mk.FP.value}: {total_cfs_mat.get(mk.FP.value)}")
        logging.info(f"{mk.FN.value}: {total_cfs_mat.get(mk.FN.value)}")
        logging.info(f"{mk.FNR.value}: {total_metrics_data.get(mk.FNR.value)}")
        logging.info(f"{mk.FPR.value}: {total_metrics_data.get(mk.FPR.value)}")
        logging.info(f"{mk.PC.value}: {total_metrics_data.get(mk.PC.value)}")
        logging.info(f"{mk.RC.value}: {total_metrics_data.get(mk.RC.value)}")
        logging.info(f"{mk.F1.value}: {total_metrics_data.get(mk.F1.value)}")
        logging.info(f"{mk.AC.value}: {total_metrics_data.get(mk.AC.value)}")
        logging.info(f"{mk.VPC.value}: {total_valid_pair_cnt}")
        logging.info(f"{mk.APC.value}: {total_accurate_pair_cnt}")
        logging.info(f"{mk.PAC.value}: {total_pair_accuracy}")
        logging.info(f"{mk.P1R.value}: {total_metrics_data.get(mk.P1R.value)}")
        logging.info(f"{mk.P0R.value}: {total_metrics_data.get(mk.P0R.value)}")
        logging.info(f"--------------------------------------------------")

        if save_to_file:
            total_metrics_data = {
                **total_cfs_mat,
                **total_metrics_data
            }
            first_level_dir_name = os.path.basename(result_file_or_dir)
            second_level_dir_name = os.path.basename(os.path.dirname(result_file_or_dir))
            total_result_file_name = os.path.join(
                result_file_or_dir,
                f"All_CWE_metrics.json"
            )
            DataUtils.save_json(total_result_file_name, total_metrics_data)


def check_result_file_legality(path):
    CWE_CASE_NUMBER = {
        'CWE-119': 53,
        'CWE-362': 121,
        'CWE-416': 267,
        'CWE-476': 89,
        'CWE-787': 62
    }
    file_name = os.path.basename(path)
    cwe_id = file_name.split('_')[0]
    data = DataUtils.load_json(path)
    vul_list = data.get('vul_data', []) + data.get('vul_detect_data', [])
    non_vul_list = data.get('non_vul_data', []) + data.get('non_vul_detect_data', [])
    vul_id_set = set()
    non_vul_id_set = set()
    for item in vul_list:
        vul_id_set.add(item['id'])
    for item in non_vul_list:
        non_vul_id_set.add(item['id'])
    assert len(vul_id_set) == CWE_CASE_NUMBER[cwe_id]
    assert len(non_vul_id_set) == CWE_CASE_NUMBER[cwe_id]
    assert len(vul_id_set.intersection(non_vul_id_set)) == len(vul_id_set) == len(non_vul_id_set)


if __name__ == "__main__":
    pass