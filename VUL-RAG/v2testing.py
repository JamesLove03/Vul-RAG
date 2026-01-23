import os
import json
import sys
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import common.config as cfg
import logging
import pdb
from datetime import datetime

from tqdm import tqdm
import re
from common import constant
import copy
from pathlib import Path
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from components.knowledge_extractor import KnowledgeExtractor
from common.util.track_util import Tracker
from components.VulRAG import VulRAGDetector
from common import common_prompt
from common.constant import KnowledgeDocumentName as kdn
from common.model_manager import ModelManager
from common.util.common_util import fill_batch_log, merge_batch_logs, fill_search_log, merge_search_log, calculate_VD_metrics
from components.knowledge_extractor import KnowledgeExtractor
from components.VulRAG import VulRAGDetector


def get_cwes(benchmark): #returns a list of CWE values

    if benchmark == "PairVul":
        cwes = ["CWE-20", "CWE-119", "CWE-125", "CWE-200", "CWE-264", "CWE-362", "CWE-401", "CWE-416", "CWE-476", "CWE-787"] #use these for testing
        #cwes = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
    elif benchmark == "TruePairVul":
        cwes = ["CWE-20", "CWE-119", "CWE-125", "CWE-200", "CWE-264", "CWE-362", "CWE-401", "CWE-416", "CWE-476", "CWE-787"]
    return cwes

def parse_command_line_arguments():
    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        '--benchmark', 
        type = str, 
        default = "PairVul",
        help = 'which benchmark to test on',
    )
    parser.add_argument(
        '--desc',
        type=str,
        default = "None",
        help = 'file descriptor of the specific test being run'
    )
    parser.add_argument(
        '--learned',
        action= 'store_true',
        default=False,
        help='triggers using the learned reranker and embeddings'
    )
    parser.add_argument(
        '--new_directory',
        default = None,
        type=str,
        help='specifies if a new directory needs to be added'
    )
    parser.add_argument(
        '--input_dir',
        default = None,
        type=str,
        help='specifies if input comes from a subdirectory'
    )
    parser.add_argument(
        '--top_K',
        type=int,
        default=10,
        help='amount of items to store'
    )
    parser.add_argument(
        '--top_N',
        type=int,
        default=3,
        help='amount of items returned from reranking'
    )
    parser.add_argument(
        '--action',
        type = str,
        default = None,
        help = "Should be one of the following actions: enrich_test, search, rerank, decision"
    )
    parser.add_argument(
        '--model',
        type = str,
        default = "gpt-3.5-turbo",
        help = "Select the model to run on"
    )
    parser.add_argument(
        '--resume',
        action = 'store_true',
        help = 'Whether to resume from a checkpoint.'
    )
    parser.add_argument(
        '--prompt',
        type=int,
        default = 1,
        help = "determines the exact prompt to use for decision making"
    )
    args = parser.parse_args()
    return args

def create_final(rerank_result, VulD, purpose_dict, function_dict, code_dict):
    knowledge_list = []
    seen_true_ids = set()  # track added true_ids
    for item in rerank_result:
        try:
            cve_knowledge = VulD.vul_knowledge[item["cve_id"]]
            for knowledege_item in cve_knowledge:
                if str(knowledege_item["true_id"]) in purpose_dict \
                or str(knowledege_item["true_id"]) in function_dict \
                or str(knowledege_item["true_id"]) in code_dict:

                    if str(knowledege_item["true_id"]) not in seen_true_ids:  # prevent duplicates

                        knowledge_list.append({
                            "cve_id": knowledege_item.get(kdn.CVE_ID.value), 
                            "vulnerability_behavior": 
                            {
                                kdn.PRECONDITIONS.value: knowledege_item.get(kdn.PRECONDITIONS.value),
                                kdn.TRIGGER.value: knowledege_item.get(kdn.TRIGGER.value), 
                                kdn.CODE_BEHAVIOR.value: knowledege_item.get(kdn.CODE_BEHAVIOR.value)
                            }, 
                            "solution_behavior": knowledege_item.get(kdn.SOLUTION.value),
                        })
                        seen_true_ids.add(str(knowledege_item["true_id"]))  # mark as added

                        break

        except Exception as e:
            logging.error(f"Error: {e}")
            logging.error(f"Error cve_id: {item['cve_id']}")

    return knowledge_list


def enrich_test(benchmark, model, resume):

    #load from partial/{benchmark}/3_enhanced_data/test_set
    cwe_list = get_cwes(benchmark)
    testset_dir = Path(constant.V2_TESTSET_DIR.format(benchmark=benchmark))
    enhanced_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))
    enhanced_dir.mkdir(parents=True, exist_ok=True)

    for cwe in cwe_list:
        print(f"Begin working on {cwe}")
        start_time = datetime.now()

        input_filename = constant.TEST_DATA_FILE_NAME.format(
                model_name = cfg.DEFAULT_BEHAVIOR_SUMMARY_MODEL,
                cwe_id = cwe
            ) + ".json"
        input_path = testset_dir / input_filename

        batch_output_filename = constant.BATCH_OUTPUT_NAME.format(cwe=cwe)
        batch_output_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark)) / 'batch_output'
        batch_output_dir.mkdir(parents=True, exist_ok=True)

        batch_output_path =  batch_output_dir / batch_output_filename

        checkpoint_path = PathUtil.checkpoint_data(batch_output_filename, "pkl")

        cve_list = []
        test_clean_data = DataUtils.load_json(input_path)
        cve_list = test_clean_data

        logging.info(f"Start detecting {len(cve_list)} samples for {cwe}...")

        vul_list = []
        non_vul_list = []
        ckpt_cve_list = []

        model_instance = ModelManager.get_model_instance(model)

        if resume:
            if os.path.exists(checkpoint_path):
                ckpt_cve_list = list(DataUtils.load_data_from_pickle_file(checkpoint_path))
                if os.path.exists(batch_output_path):
                    data = DataUtils.load_json(batch_output_path)
                    vul_list = data['vul_data']
                    non_vul_list = data['non_vul_data']
            else:
                # to avoid overwriting the existing output file
                raise FileNotFoundError(f"Checkpoint file {checkpoint_path} not found.")
        try:
            custom_non_vul_ids = []
            custom_vul_ids = []
            batch_input_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark)) / "batch_input_file" / constant.BATCH_INPUT_NAME.format(cwe=cwe)
            batch_input_path.parent.mkdir(parents=True, exist_ok=True)  # create subfolders if needed

            for cve_item in tqdm(cve_list):
                if str(cve_item['id']) + 'P' in ckpt_cve_list or str(cve_item['id']) + 'F' in ckpt_cve_list:
                    print("Checkpoint issue")
                    continue
                
                #Generate messages for purpose and function as well as storing customids
                purpose_prompt, function_prompt = common_prompt.ExtractionPrompt.generate_extraction_prompt_for_vulrag(cve_item['code_before_change'])
                purpose_messages = model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
                function_messages = model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
                vul_list.append(purpose_messages)
                custom_vul_ids.append(str(cve_item['id']) + 'P' + 'V')
                vul_list.append(function_messages)
                custom_vul_ids.append(str(cve_item['id']) + 'F' + 'V')

                purpose_prompt, function_prompt = common_prompt.ExtractionPrompt.generate_extraction_prompt_for_vulrag(cve_item['code_after_change'])
                purpose_messages = model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
                function_messages = model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
                non_vul_list.append(purpose_messages)
                custom_non_vul_ids.append(str(cve_item['id']) + 'P' + 'N')
                non_vul_list.append(function_messages)
                custom_non_vul_ids.append(str(cve_item['id']) + 'F' + 'N')

                ckpt_cve_list.append(str(cve_item['id']))
                DataUtils.save_json(batch_input_path, {"vul_data": vul_list, "non_vul_data": non_vul_list})
            
        except Exception as e:
            DataUtils.write_data_to_pickle_file(ckpt_cve_list, checkpoint_path)
            logging.error(f"CVE ID: {cve_item['cve_id']}")
            logging.error(f"Error: {e}")
            logging.error(f"Detection for {cwe} failed. Checkpoint saved.")

        combined_list = vul_list + non_vul_list
        combined_ids = custom_vul_ids + custom_non_vul_ids

        if len(combined_list) != len(combined_ids):
            raise Exception(f"Error in the amount of ids: Items {len(combined_list)}, Custom IDs {len(combined_ids)}")
        
        model_instance.create_batch_file(combined_list, batch_input_path, combined_ids)

        batch_file = model_instance.upload_file(batch_input_path)

        input_tok, output_tok = model_instance.run_batch(batch_file, batch_output_path)
        
        end_time = datetime.now()
        runtime = ((end_time - start_time).total_seconds()) / 60 # gets runtime in minutes

        batch_log_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark)) / "metrics" / f"{cwe}log.json"
        batch_log_path.parent.mkdir(parents=True, exist_ok=True)

        fill_batch_log(f"Enhancing testset data for {cwe}", input_tok, output_tok, len(custom_vul_ids), model_instance.get_model_name(), None, batch_log_path, runtime)

        processed_item = model_instance.read(batch_output_path)
        final_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))

        output_file = final_path / f"processed_output_{cwe}.json"
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(processed_item, f, indent=2)


    print("All cwes completed")
    merge_batch_logs(Path(enhanced_dir) / "metrics", None, model_instance.get_model_name())


def load_elastic(benchmark):
    cwes = get_cwes(benchmark)

    KnowledgeE = KnowledgeExtractor(model_name = 'gpt-3.5-turbo', V2=True, benchmark=benchmark)

    KnowledgeE.document_store(cwe_name_list=cwes)


def search(benchmark, desc, k, learned, dir):
    cwes = get_cwes(benchmark)
    input_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))
    if dir is None:
        output_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark))
    else:
        output_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark)) / f'{dir}'

    orig_data_dir = Path(constant.V2_TESTSET_DIR.format(benchmark=benchmark))
    indexes = ["CWE-119", "CWE-416"]
    #define input path, and output path
    for cwe, index in zip(cwes, indexes):
        print(f"Now searching {cwe}")
        start_time = datetime.now()

        input_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        output_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        input_path = input_dir / input_file
        output_path = output_dir / output_file
        orig_data_file = constant.TEST_DATA_FILE_NAME.format(cwe_id=cwe)
        orig_data_path = (orig_data_dir / orig_data_file).with_suffix(".json")

        with open(orig_data_path, "r", encoding="utf-8") as f:
            test_data = json.load(f)

        VulD = VulRAGDetector("gpt-3.5-turbo", "gpt-3.5-turbo", input_path)
        

        #CHANGE THIS BACK FOR IT TO WORK CORRECTLY
        VulD.update_retrievers(index)
        #DO NOT FORGET TO CHANGE THIS


        start_time = datetime.now()
        total_results = []
        total_length = 0

        for value in tqdm(test_data):
            
            id = value["id"]
            vul_code_snippet = value["code_before_change"]
            non_vul_code_snippet = value["code_after_change"]

            vul_purpose = VulD.vul_knowledge.get(f"{id}PV")
            non_vul_purpose = VulD.vul_knowledge.get(f"{id}PN")

            vul_function = VulD.vul_knowledge.get(f"{id}FV")
            non_vul_function = VulD.vul_knowledge.get(f"{id}FN")

            if learned:
                vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True)
                non_vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True)
                length = len(vul_knowledge_list) + len(non_vul_knowledge_list)
            else:
                vul_knowledge_list = VulD.retrieve_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True)
                non_vul_knowledge_list = VulD.retrieve_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True)
                length = k*6

            total_length += length
            total_results.append({
                "id": id,
                "vul_knowledge": vul_knowledge_list,
                "non_vul_knowledge": non_vul_knowledge_list,
                "total_length": length,
            })

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(total_results, f, indent=2)
        
        end_time = datetime.now()
        runtime = ((end_time - start_time).total_seconds()) / 60 # gets runtime in minutes

        output_log_path = output_dir / "metrics" / f"{cwe}log.json"
        input_log_path = input_dir / 'metrics' / f"{cwe}log.json"

        fill_search_log(f"Searching elasticsearch for {cwe} using full fill_blanks methodology", 
                        len(test_data), 
                        total_length, 
                        learned, 
                        str(input_log_path), 
                        str(output_log_path), 
                        runtime, 
                        k)

            
    print("Done searching all files")
    merge_search_log((output_dir / "metrics"), 
                     (input_dir / 'metrics' / "final_log.json"),
                     learned,
                     k,
                     (output_dir / 'metrics' / 'final_log.json')
                     )


def rerank(benchmark, learned, k, desc, top_N, subdir, new_dir):

    if subdir is None:
        input_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark))
    else:
        input_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark)) / subdir

    if new_dir is None:
        output_dir = Path(constant.V2_RERANKED_DATA_DIR.format(benchmark=benchmark))
    else:
        output_dir = Path(constant.V2_RERANKED_DATA_DIR.format(benchmark=benchmark)) / f'{new_dir}'

    input_log_dir = input_dir / 'metrics'
    output_log_dir = output_dir / 'metrics'
    knowledge_dir = Path(constant.V2_ELASTIC_READY_DIR.format(benchmark=benchmark))

    cwes = get_cwes(benchmark)



    indexes = ["CWE-119", "CWE-416"] #FOR TESTING ONLY REMOVE THIS BEFORE REAL RUNS


    #define input path, and output path
    for cwe, index in zip(cwes, indexes):
        input_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        output_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        input_path = input_dir / input_file
        output_path = output_dir / output_file  
        knowledge_path = knowledge_dir / f'gpt-3.5-turbo_{index}_316_pattern_all.json'

        VulD = VulRAGDetector(model_name=desc, summary_model_name=desc,knowledge_path=knowledge_path)
        VulD.update_retrievers(cwe)
        
        VulD.add_test_knowledge(input_path)
        total_result = []
        output_len = 0
        start_time = datetime.now()

        for item in VulD.test_knowledge:
            id = item["id"]
            if learned:
                vul_final = VulD.final_format(item["vul_knowledge"])
                non_vul_final = VulD.final_format(item["non_vul_knowledge"])
            else:
                raw_v_purpose, raw_v_function, raw_v_code = item["vul_knowledge"]
                raw_nv_purpose, raw_nv_function, raw_nv_code = item["non_vul_knowledge"]
                
                v_purpose = [v['cve_id'] for v in sorted(raw_v_purpose.values(), key=lambda x: x['score'], reverse=True)]
                v_function = [v['cve_id'] for v in sorted(raw_v_function.values(), key=lambda x: x['score'], reverse=True)]
                v_code = [v['cve_id'] for v in sorted(raw_v_code.values(), key=lambda x: x['score'], reverse=True)]
                nv_purpose = [v['cve_id'] for v in sorted(raw_nv_purpose.values(), key=lambda x: x['score'], reverse=True)]
                nv_function = [v['cve_id'] for v in sorted(raw_nv_function.values(), key=lambda x: x['score'], reverse=True)]
                nv_code = [v['cve_id'] for v in sorted(raw_nv_code.values(), key=lambda x: x['score'], reverse=True)]

                vul_output = VulD.rerank_by_rank(v_purpose, v_function, v_code)
                non_vul_output = VulD.rerank_by_rank(nv_purpose, nv_function, nv_code)
                #NEED TO ADD SOME CODE HERE THAT WILL GET THE LIST INTO FINALIZED FORMAT WITH ALL THE INFORMATION
                vul_final = create_final(vul_output, VulD, raw_v_purpose, raw_v_function, raw_v_code)
                non_vul_final = create_final(non_vul_output, VulD, raw_nv_purpose, raw_nv_function, raw_nv_code)
            
            output_len = len(vul_final) + len(non_vul_final)
            total_result.append({
                "id": id,
                "vul_knowledge": vul_final,
                "non_vul_knowledge": non_vul_final,
                "vul_code": VulD.vul_knowledge[item["CVE_id"]],
                "non_vul_code": VulD.vul_knowledge[item["CWE_id"]],
            })
        end_time = datetime.now()    
        runtime = ((end_time - start_time).total_seconds()) / 60 # gets runtime in minutes

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(total_result, f, indent=2)

        fill_search_log(f"Reranking results for {cwe} using full N=10", 
                len(VulD.test_knowledge), 
                output_len, 
                learned, 
                str(input_log_dir / f"{cwe}log.json"), 
                str(output_log_dir / f"{cwe}log.json"), 
                runtime, 
                k)
        
    print("Done reranking all files")
    merge_search_log((output_dir / "metrics"), 
                     (input_dir / 'metrics' / "final_log.json"),
                     learned,
                     k,
                     (output_dir / 'metrics' / 'final_log.json')
                     )
    return 0


def decision(benchmark, subdir, model, resume, prompt, description):

    if subdir is None:
        input_dir = constant.V2_RERANKED_DATA_DIR.format(benchmark=benchmark)
    else:
        input_dir = Path(constant.V2_RERANKED_DATA_DIR.format(benchmark=benchmark)) / subdir
   
    cwes = get_cwes(benchmark)

    model_instance = ModelManager.get_model_instance(model)

    for cwe in cwes:
        print(f"Begin working on {cwe}")

        filename = constant.PROCESSED_OUTPUT.format(cwe=cwe) #open the list of reranked data
        filepath = input_dir / filename
        with open(filepath, "r", encoding='utf-8') as f:
            knowledge_list = json.load(f)

        checkpoint_path = PathUtil.checkpoint_data(filename, "pkl")

        snippet_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark)) #open the original code snippets
        snippet_path = snippet_dir / filename
        with open(snippet_path, "r", encoding='utf-8') as f:
            code_snippets = json.load(f)

        testset_path = snippet_dir / 'test_set' / constant.TEST_DATA_FILE_NAME.format(cwe_id=cwe)
        with open(testset_path.with_suffix(".json"), "r", encoding='utf-8') as f:
            test_set = json.load(f)

        output_dir = Path(constant.V2_DECISION_RESULTS_DIR.format(benchmark=benchmark)) / constant.DETECTION_RESULTS_SUBDIR.format(model_name = model_instance.get_model_name(), prompt=prompt, info=description) / constant.DETECTION_RESULTS_DIR.format(k=10)
        output_path = output_dir / constant.DETECTION_OUTPUT_FILENAME.format(cwe=cwe)
        output_dir.mkdir(parents=True, exist_ok=True)


        ckpt_cve_list = []
        vul_output_list = []
        non_vul_output_list = []
        if resume:
             if os.path.exists(checkpoint_path):
                ckpt_cve_list = list(DataUtils.load_data_from_pickle_file(checkpoint_path))
                if os.path.exists(output_path):
                    data = DataUtils.load_json(output_path)
                    vul_output_list = data['vul_data']
                    non_vul_output_list = data['non_vul_data'] #check this
                else:
                    # to avoid overwriting the existing output file
                    raise FileNotFoundError(f"Checkpoint file {checkpoint_path} not found.")
        
        for item in tqdm(knowledge_list):
            id = item["id"]
            vul_knowledge = item["vul_knowledge"]
            non_vul_knowledge = item["non_vul_knowledge"]

            testset_item = next((item for item in test_set if item["id"] == id), None)
            vul_code_snippet = testset_item["code_before_change"]
            non_vul_code_snippet = testset_item["code_after_change"]
            cve_id = testset_item["cve_id"]
            matches = {
                x: v
                for x, v in code_snippets.items()
                if "".join(filter(str.isdigit, x)) == str(id)
            }
            vul_purpose = next((v for k, v in matches.items() if "PV" in k), None)
            non_vul_purpose = next((v for k, v in matches.items() if "PN" in k), None)
            vul_function = next((v for k, v in matches.items() if "FV" in k), None)
            non_vul_function = next((v for k, v in matches.items() if "FN" in k), None)

            #runs and writes the decision for the vul_snippet
            vul_output = run_decision(vul_knowledge, vul_code_snippet, cve_id, model_instance, vul_purpose, vul_function, id, prompt)
            vul_output = set_brier(vul_output, 1)
            vul_output_list.append(vul_output)

            #runs and writes the decision for the non_vul_snippet
            non_vul_output = run_decision(non_vul_knowledge, non_vul_code_snippet, cve_id, model_instance, non_vul_purpose, non_vul_function, id, prompt)
            non_vul_output = set_brier(non_vul_output, 0)
            non_vul_output_list.append(non_vul_output)

            ckpt_cve_list.append(id)
            DataUtils.save_json(output_path, {"vul_data": vul_output_list, "non_vul_data": non_vul_output_list})

    #calculate metrics and trim down item
    cut_down(output_dir)


            

    return 0

def get_final(vul, sol): #returns the final output 1, 0, -1

    if constant.LLMResponseKeywords.POS_ANS.value in sol:
        final = 0
    elif (constant.LLMResponseKeywords.POS_ANS.value in vul and 
            constant.LLMResponseKeywords.NEG_ANS.value in sol):
        final = 1
    else:
        final = -1

    return final

def cut_down(output_dir):
    num_list = [10, 5, 3, 1]

    for item in os.listdir(output_dir):
        filepath = os.path.join(output_dir, item)
        with open(filepath, "r", encoding='utf-8') as f:
            data = json.load(f)

        parent_dir = Path(output_dir).parent
        categories = ["vul_data", "non_vul_data"]
        new_data = copy.deepcopy(data)

        for num in num_list:

            for entry in new_data.get("vul_data") + new_data.get("non_vul_data"):

                entry["detect_result"] = entry["detect_result"][:num]

                cve_list = [
                    itera["vul_knowledge"]["cve_id"]
                    for itera in entry.get("detect_result")
                ]
                
                entry["lib_present"] = 1 if entry["cve_id"] in cve_list else 0 #set lib present

                #set final_result
                last_vul_output = entry["detect_result"][-1]["vul_output"]
                last_sol_output = entry["detect_result"][-1]["sol_output"]
                final_result = get_final(last_vul_output, last_sol_output)
                entry["final_result"] = final_result

                #set lib_decision
                last_cve_id = entry["detect_result"][-1]["vul_knowledge"]["cve_id"]
                if final_result != -1 and last_cve_id == entry["cve_id"]:
                    entry["lib_decision"] = 1
                else:
                    entry["lib_decision"] = 0
                
                entry["total_entries"] = len(entry["detect_result"])

            new_output_dir = parent_dir / constant.DETECTION_RESULTS_DIR.format(k=num)
            new_output_dir.mkdir(parents=True, exist_ok=True)
            new_path = new_output_dir / item

            with open(new_path, "w", encoding='utf-8') as fw:
                json.dump(new_data, fw, indent=4, ensure_ascii=False)

    for num in num_list:
        calculate_VD_metrics(str(parent_dir / constant.DETECTION_RESULTS_DIR.format(k=num)), max_items=num, V2=True)

def extract_confidence(text: str):
    """
    Extracts confidence value from a model's plaintext response.
    Returns a float between 0 and 1. Defaults to None if not found.
    """
    # Look for 'confidence 85%' or 'confidence: 0.85' patterns
    match = re.search(r'\*{0,2}CONFIDENCE\*{0,2}\s*[:\-]?\s*([\d.]+%?)', text, re.IGNORECASE)

    if match:
        val_str = match.group(1).rstrip('%')
        val = float(val_str)        # Convert percent to 0-1 if needed
        if val > 1:
            val = val / 100.0
        return val
    return 0

def set_brier(items, truth): #this function adds 4 brier scores (Vul Acc brier, Sol Acc Brier, Vul Dec brier, Sol Dec Brier)

    if items["final_result"] == -1:
        items["vul_brier"] = 0
        items["sol_brier"] = 0
        return items

    final_result = items["detect_result"][-1]
    vul_conf = final_result["vul_confidence"]
    sol_conf = final_result["sol_confidence"]

    if truth == 1:
        if (constant.LLMResponseKeywords.POS_ANS.value in final_result["vul_output"]):
            vul_brier = (vul_conf - 1) ** 2
        else:
                vul_brier = (vul_conf - 0) ** 2
        
        if (constant.LLMResponseKeywords.POS_ANS.value in final_result["sol_output"]):
            sol_brier = (sol_conf - 0) ** 2
        else:
            sol_brier = (sol_conf - 1) ** 2

    elif truth == 0:
        if (constant.LLMResponseKeywords.NEG_ANS.value in final_result["vul_output"]):
            vul_brier = (vul_conf - 1) ** 2
        else:
                vul_brier = (vul_conf - 0) ** 2
        
        if (constant.LLMResponseKeywords.NEG_ANS.value in final_result["sol_output"]):
            sol_brier = (sol_conf - 0) ** 2
        else:
            sol_brier = (sol_conf - 1) ** 2
    
    items["vul_brier"] = round(vul_brier, cfg.METRICS_DECIMAL_PLACES_RESERVED)
    items["sol_brier"] = round(sol_brier, cfg.METRICS_DECIMAL_PLACES_RESERVED)

    return items

def run_decision(vul_knowledge, code_snippet, query_cve, model_instance, purpose, function, id, prompt):

    model_settings_dict = {}

    detect_result = []
    total_entries = 0
    lib = 0
    dec = 0
    start_time = datetime.now()

    for knowledge in vul_knowledge[:10]:
        total_entries += 1
        vul_detect_prompt = common_prompt.VulRAGPrompt.get_vul_prompt_by_key(prompt, code_snippet, knowledge)
        sol_detect_prompt = common_prompt.VulRAGPrompt.get_sol_prompt_by_key(prompt, code_snippet, knowledge)

        vul_messages = model_instance.get_messages(vul_detect_prompt, constant.DEFAULT_SYS_PROMPT)
        sol_messages = model_instance.get_messages(sol_detect_prompt, constant.DEFAULT_SYS_PROMPT)
        vul_output, v_inp_tokens, v_out_tokens = model_instance.get_response_with_messages(
                vul_messages,
                **model_settings_dict
            )
        sol_output, s_inp_tokens, s_out_tokens = model_instance.get_response_with_messages(
                sol_messages,
                **model_settings_dict
            )

        inp_tokens = v_inp_tokens + s_inp_tokens
        out_tokens = v_out_tokens + s_out_tokens

        sol_confidence = extract_confidence(sol_output)
        vul_confidence = extract_confidence(vul_output)
        if sol_confidence == 0 or vul_confidence == 0:
            pdb.set_trace()

        result = {
            "vul_knowledge": knowledge,
            "vul_detect_prompt": vul_detect_prompt,
            "vul_output": vul_output,
            "sol_detect_prompt": sol_detect_prompt,
            "sol_output": sol_output,
            "input_tokens": inp_tokens,
            "output_tokens": out_tokens,
            "runtime": ((datetime.now() - start_time).total_seconds()) / 60,
            "vul_confidence": vul_confidence,
            "sol_confidence": sol_confidence,
        }
        detect_result.append(result)

        if(query_cve == knowledge["cve_id"]):
            lib = 1          
        if (constant.LLMResponseKeywords.POS_ANS.value in vul_output and 
            constant.LLMResponseKeywords.NEG_ANS.value in sol_output):
            if(query_cve == knowledge["cve_id"]):
                dec = 1            
            return {
                "id": id,
                "cve_id": query_cve,
                "purpose": purpose, 
                "function": function, 
                "code_snippet": code_snippet, 
                "detect_result": detect_result, 
                "detection_model": model_instance.get_model_name(),
                "summary_model": model_instance.get_model_name(),
                "model_settings": model_settings_dict,
                "final_result": 1,
                "lib_present": lib,
                "lib_decision": dec,
                "total_entries": total_entries,
            }
        
        elif constant.LLMResponseKeywords.POS_ANS.value in sol_output:
            if(query_cve == knowledge["cve_id"]):
                dec = 1
            return {
                "id": id,
                "cve_id": query_cve,
                "purpose": purpose, 
                "function": function, 
                "code_snippet": code_snippet, 
                "detect_result": detect_result, 
                "detection_model": model_instance.get_model_name(),
                "summary_model": model_instance.get_model_name(),
                "model_settings": model_settings_dict,
                "final_result": 0,
                "lib_present": lib,
                "lib_decision": dec,
                "total_entries": total_entries,
            }
        else:
            continue
    
    return {
            "id": id,
            "cve_id": query_cve,
            "purpose": purpose, 
            "function": function, 
            "code_snippet": code_snippet, 
            "detect_result": detect_result, 
            "detection_model": model_instance.get_model_name(),
            "summary_model": model_instance.get_model_name(),
            "model_settings": model_settings_dict,
            "final_result": -1,
            "lib_present": lib,
            "lib_decision": dec,
            "total_entries": total_entries,
            }
            

if __name__ == '__main__':

    args = parse_command_line_arguments()

    if args.action == None:
        raise Exception("Forgot to put an action into this")
    
    if args.action == 'enrich_test':
        enrich_test(args.benchmark, args.model, args.resume)

    elif args.action == 'load':
        load_elastic(args.benchmark)

    elif args.action == 'search':
        search(args.benchmark, args.model, args.top_K, args.learned, args.new_directory)

    elif args.action == 'rerank':
        rerank(args.benchmark, args.learned, args.top_K, args.model, args.top_N, args.input_dir, args.new_directory)

    elif args.action == 'decision':
        decision(args.benchmark, args.input_dir, args.model, args.resume, args.prompt, args.desc)
    elif args.action == 'test':
        output_dir = 'C:/Coding/Work/Vul-RAG/Vul-RAG/partial/PairVul/6_decision_results/gpt-3.5-turbo_prompt=0_test_run/10_maxentries_results'
        cut_down(output_dir)
    else:
        raise Exception("There is an incorrect action verb here")