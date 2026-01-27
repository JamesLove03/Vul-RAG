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
import numpy as np
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
from collections import defaultdict


def get_cwes(benchmark): #returns a list of CWE values

    if benchmark == "PairVul":
        cwes = ["CWE-476", "CWE-787"]
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
        '--all',
        action= 'store_true',
        help = 'runs a preset routine to test all items'
    )
    parser.add_argument(
        '--desc',
        type=str,
        default = "None",
        help = 'file descriptor of the specific test being run'
    )
    parser.add_argument(
        '--action_type',
        type=int,
        default=0,
        help='signifies the search type. See search for details'
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

def rrf_fuse(item, fields, k_rrf=60):
    """
    Perform Reciprocal Rank Fusion over selected fields.
    Returns a dict: {item_id: fused_score}
    """
    rrf_scores = {}

    for field in fields:
        entries = item.get(field, {})

        # sort by score descending → rank order
        ranked = sorted(entries.values(), key=lambda x: x["score"], reverse=True)
        for rank, entry in enumerate(ranked, start=1):
            item_id = entry["id"]
            if item_id not in rrf_scores:
                rrf_scores[item_id] = {"score": 0.0, "cve_id": entry["cve_id"]}

            rrf_scores[item_id]["score"] += 1.0 / (k_rrf + rank)

    return rrf_scores

def count_cve_matches(item, target_cve, embed_mode):
    return {
        k: recall_at_k_rrf(item, target_cve, k, embed_mode)
        for k in [1, 3, 5, 10]
    }
    
def recall_at_k_rrf(item, target_cve, k, embed_mode):    
    if embed_mode == 0:
        fields = ["purpose", "function", "code"]
    elif embed_mode == 1:
        fields = ["purpose", "function", "code",
                  "purpose_emb", "function_emb", "code_emb"]
    elif embed_mode == 2:
        fields = ["purpose_emb", "function_emb", "code_emb"]
    else:
        raise ValueError("Invalid embed_mode")

    # Step 1: RRF fuse
    fused_scores = rrf_fuse(item, fields)

    # Step 2: global top-K
    top_k_ids = sorted(
        fused_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:k]

    # Step 3: dedupe + recall
    retrieved_ids = {item_id for item_id, _ in top_k_ids}

    relevant_ids = set()
    for field in fields:
        for entry in item.get(field, {}).values():
            if entry["cve_id"] == target_cve:
                relevant_ids.add(entry["id"])

    if not relevant_ids:
        return 0.0  # or skip this query entirely

    hits = len(retrieved_ids & relevant_ids)
    return hits / len(relevant_ids)

id_cve_cache = {}

def format_learned_response(benchmark, cwe, response):
    ordered_keys = list(response.keys())  # these are strings like '2143'
    scores_array = [response[key]["scores"] for key in ordered_keys]

    cache_key = (benchmark, cwe)
    if cache_key not in id_cve_cache:
        path = (
            Path(constant.V2_RAWDATA_DIR.format(benchmark=benchmark))
            / constant.RAW_DATA_FILE_NAME.format(cwe_id=cwe)
        ).with_suffix(".json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Use string keys so they match your response
        id_cve_cache[cache_key] = {str(x["id"]): x["cve_id"] for x in data}

    id_to_cve = id_cve_cache[cache_key]

    total_dict = {}
    for i, key in enumerate(ordered_keys):
        cve_id = id_to_cve.get(key)
        if cve_id is None:
            continue

        total_dict[key] = {
            "cve_id": cve_id,
            "id": key,
            "scores": scores_array[i],
        }

    return total_dict

def count_found_items(item, cve, embed):
    seen_ids = set()
    total_matches = 0

    if embed == 1:
        fields = ["purpose", "function", "code", "purpose_emb", "function_emb", "code_emb"]
    elif embed == 0:
        fields = ["purpose", "function", "code"]
    elif embed == 2:
        fields = ["purpose_emb", "function_emb", "code_emb"]

    for field in fields:
        entries = item.get(field, {})
        for entry in entries.values():
            if entry["id"] not in seen_ids:
                seen_ids.add(entry["id"])
                if entry["cve_id"] == cve:
                    total_matches += 1
    
    return total_matches

def search(benchmark, desc, k, search_type, dir):
    cwes = get_cwes(benchmark)
    input_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))
    if dir is None:
        output_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark))
    else:
        output_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark)) / f'{dir}'

    orig_data_dir = Path(constant.V2_TESTSET_DIR.format(benchmark=benchmark))
    valid_dir = Path(constant.V2_ELASTIC_READY_DIR.format(benchmark=benchmark))
    all_items = []
    num_possible_items = 0

    #define input path, and output path
    for cwe in cwes:
        print(f"Now searching {cwe}")
        start_time = datetime.now()

        input_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        output_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        input_path = input_dir / input_file
        output_path = output_dir / output_file
        orig_data_file = constant.TEST_DATA_FILE_NAME.format(cwe_id=cwe)
        orig_data_path = (orig_data_dir / orig_data_file).with_suffix(".json")
        valid_file_name = constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(model_name='gpt-3.5-turbo', cwe_id=cwe) + '.json'
        valid_path = str(valid_dir / valid_file_name)

        with open(valid_path, "r", encoding="utf-8") as f:
            valid_data = json.load(f)

        max_items_per_cve = { #gets the maximum number of CVE items in a cve_id. This is used for recall normalized
            cve_id: len(items)
            for cve_id, items in valid_data.items()
        }

        with open(orig_data_path, "r", encoding="utf-8") as f:
            test_data = json.load(f)

        VulD = VulRAGDetector("gpt-3.5-turbo", "gpt-3.5-turbo", input_path)
        
        VulD.update_retrievers(cwe)

        start_time = datetime.now()
        total_results = []
        total_vul_length = 0
        total_non_vul_length = 0
        total_vul_items_found = 0
        total_non_vul_items_found = 0
        total_max_items = 0

        for value in tqdm(test_data):
            
            id = value["id"]
            cve_id = value["cve_id"]
            vul_code_snippet = value["code_before_change"]
            non_vul_code_snippet = value["code_after_change"]

            vul_purpose = VulD.vul_knowledge.get(f"{id}PV")
            non_vul_purpose = VulD.vul_knowledge.get(f"{id}PN")

            vul_function = VulD.vul_knowledge.get(f"{id}FV")
            non_vul_function = VulD.vul_knowledge.get(f"{id}FN")

            if not vul_purpose:
                continue

            max_items = max_items_per_cve.get(cve_id, 0)

            if search_type == 0: #searches only off of BM25
                vul_knowledge_list = VulD.retrieve_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True, search_type)
                non_vul_knowledge_list = VulD.retrieve_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True, search_type)
                vul_items_found = count_found_items(vul_knowledge_list, cve_id, search_type)
                non_vul_items_found = count_found_items(non_vul_knowledge_list, cve_id, search_type)
                all_items.append({
                    "vul_knowledge": vul_knowledge_list,
                    "non_vul_knowledge": non_vul_knowledge_list,
                    "target_cve": cve_id,
                    "max_items": max_items
                })

            elif search_type == 1: # searches BM25 and embeddings
                vul_knowledge_list = VulD.retrieve_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True, search_type)
                non_vul_knowledge_list = VulD.retrieve_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True, search_type)
                vul_items_found = count_found_items(vul_knowledge_list, cve_id, search_type)
                non_vul_items_found = count_found_items(non_vul_knowledge_list, cve_id, search_type)
                all_items.append({
                    "vul_knowledge": vul_knowledge_list,
                    "non_vul_knowledge": non_vul_knowledge_list,
                    "target_cve": cve_id,
                    "max_items": max_items
                })

            elif search_type == 2: #searches embeddings only
                vul_knowledge_list = VulD.retrieve_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True, search_type)
                non_vul_knowledge_list = VulD.retrieve_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True, search_type)
                vul_items_found = count_found_items(vul_knowledge_list, cve_id, search_type)
                non_vul_items_found = count_found_items(non_vul_knowledge_list, cve_id, search_type)
                all_items.append({
                    "vul_knowledge": vul_knowledge_list,
                    "non_vul_knowledge": non_vul_knowledge_list,
                    "target_cve": cve_id,
                    "max_items": max_items
                })

            elif search_type == 3: #searches learned with backfill 0
                vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, False, True)
                non_vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, False, True)
                vul_knowledge_list = format_learned_response(benchmark, cwe, vul_knowledge_list)
                non_vul_knowledge_list = format_learned_response(benchmark, cwe, non_vul_knowledge_list)

                vul_items_found = sum(1 for item in vul_knowledge_list.values()
                                      if cve_id == item["cve_id"])
                non_vul_items_found = sum(1 for item in non_vul_knowledge_list.values()
                                      if cve_id == item["cve_id"])

            elif search_type == 4: #searches learned with backfill values
                vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True, True)
                non_vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True, True)
                vul_knowledge_list = format_learned_response(benchmark, cwe, vul_knowledge_list)
                non_vul_knowledge_list = format_learned_response(benchmark, cwe, non_vul_knowledge_list)
                
                vul_items_found = sum(1 for item in vul_knowledge_list.values()
                                      if cve_id == item["cve_id"])
                non_vul_items_found = sum(1 for item in non_vul_knowledge_list.values()
                                      if cve_id == item["cve_id"])
            else:
                raise Exception("invalid search_type value. Should be 0-4")


            vul_length = len(vul_knowledge_list) 
            non_vul_length = len(non_vul_knowledge_list)

            total_vul_length += vul_length
            total_non_vul_length += non_vul_length
            
            
            if max_items > 0:
                total_max_items += max_items #this is the number of max items for only a single side (vul / non_vul)
                total_vul_items_found += vul_items_found
                total_non_vul_items_found += non_vul_items_found

            total_results.append({
                "id": id,
                "cve_id": cve_id,
                "vul_length": vul_length,
                "non_vul_length": non_vul_length,
                "vul_knowledge": vul_knowledge_list,
                "non_vul_knowledge": non_vul_knowledge_list,
            })

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(total_results, f, indent=2)
        
        end_time = datetime.now()
        runtime = ((end_time - start_time).total_seconds()) / 60 # gets runtime in minutes

        num_possible_items += total_max_items
        output_log_path = output_dir / "metrics" / f"{cwe}log.json"
        input_log_path = input_dir / 'metrics' / f"{cwe}log.json"

        fill_search_log(f"Searching elasticsearch for {cwe}", 
                        len(test_data)*2, 
                        total_vul_length + total_non_vul_length, 
                        search_type, 
                        str(input_log_path), 
                        str(output_log_path), 
                        runtime, 
                        k,
                        total_max_items,
                        total_non_vul_items_found,
                        total_vul_items_found
                        )

    print("Done searching all files")

    if search_type < 3:
        if search_type == 0:
            real_field = ["purpose", "function", "code"]
        elif search_type == 1:
            real_field = ["purpose", "function", "code",
                        "purpose_emb", "function_emb", "code_emb"]
        elif search_type == 2:
            real_field = ["purpose_emb", "function_emb", "code_emb"]

        recall_at_k = {1: 0, 3: 0, 5: 0, 10: 0}
        total_relevant_items = 0 

        for item in all_items:
            if item["max_items"] == 0:
                continue  # skip items with no possible relevant entries
            
            total_relevant_items += 2  # count this item once

            for field in ["vul_knowledge", "non_vul_knowledge"]:
                fused = rrf_fuse(item[field], fields=real_field)
                ordered_fused = sorted(fused.items(), key=lambda x: x[1]["score"], reverse=True)

                for K in [1, 3, 5, 10]:
                    top_k_list = ordered_fused[:K]
                    num_correct = sum(
                        1 for _, entry in top_k_list if entry["cve_id"] == item["target_cve"]
                    )
                    recall_at_k[K] += num_correct / item["max_items"]

        # average across all valid items
        for K in [1, 3, 5, 10]:
            recall_at_k[K] /= total_relevant_items
        
    else:
        recall_at_k = {}

    merge_search_log((output_dir / "metrics"), 
                    (input_dir / 'metrics' / "final_log.json"),
                   
                    search_type,
                    k,
                    (output_dir / 'metrics' / 'final_log.json'),
                    recall_at_k
                    )

def rerank(benchmark, rerank_type, k, model, top_N, subdir, new_dir):

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

    #define input path, and output path
    for cwe in cwes:
        input_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        output_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        input_path = input_dir / input_file
        output_path = output_dir / output_file  
        knowledge_path = knowledge_dir / f'gpt-3.5-turbo_{cwe}_316_pattern_all.json'

        VulD = VulRAGDetector(model_name=model, summary_model_name=model,knowledge_path=knowledge_path)
        VulD.update_retrievers(cwe)
        
        VulD.add_test_knowledge(input_path)
        total_result = []
        output_len = 0
        start_time = datetime.now()

        for item in VulD.test_knowledge:
            id = item["id"]
            target_cve = item["cve_id"]

            vul = item.get("vul_knowledge", {})
            nvul = item.get("non_vul_knowledge", {})

            if rerank_type > 7: #using the learned reranker
                vul_final = VulD.final_format(item["vul_knowledge"])
                non_vul_final = VulD.final_format(item["non_vul_knowledge"])
            
            else: #load RRF and single signal rerankers
                raw_v_purpose = item["vul_knowledge"]["purpose"]
                raw_v_function = item["vul_knowledge"]["function"]
                raw_v_code = item["vul_knowledge"]["code"]

                raw_nv_purpose = item["non_vul_knowledge"]["purpose"]
                raw_nv_function = item["non_vul_knowledge"]["function"]
                raw_nv_code = item["non_vul_knowledge"]["code"]

            elif rerank_type == 7: #testing reranking based only on purpose
                raw_v_purpose = item["vul_knowledge"][]
            elif rerank_type == 6: #reranking only on function

            elif rerank_type == 5: #reranking only on code

            else: #reranking using RRF

                
                
                
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
        if args.all:
            #search(args.benchmark, args.model, args.top_K, 0, "FINAL_bm25")
            #search(args.benchmark, args.model, args.top_K, 1, "FINAL_bm25+embed")
            #search(args.benchmark, args.model, args.top_K, 2, "FINAL_embed")
            #search(args.benchmark, args.model, args.top_K, 3, "FINAL_partial_learnedrerank")
            search(args.benchmark, args.model, args.top_K, 4, "FINAL_full_learnedrerank")
        else:
            search(args.benchmark, args.model, args.top_K, args.action_type, args.new_directory)

    elif args.action == 'rerank':
        rerank(args.benchmark, args.action_type, args.top_K, args.model, args.top_N, args.input_dir, args.new_directory)

        if args.all:
            rerank()
            rerank()

    elif args.action == 'decision':
        decision(args.benchmark, args.input_dir, args.model, args.resume, args.prompt, args.desc)
    elif args.action == 'test':
        output_dir = 'C:/Coding/Work/Vul-RAG/Vul-RAG/partial/PairVul/6_decision_results/gpt-3.5-turbo_prompt=0_test_run/10_maxentries_results'
        cut_down(output_dir)
    else:
        raise Exception("There is an incorrect action verb here")