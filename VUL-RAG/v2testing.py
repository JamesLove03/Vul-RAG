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
from common import constant
from pathlib import Path
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from components.knowledge_extractor import KnowledgeExtractor
from common.util.track_util import Tracker
from components.VulRAG import VulRAGDetector
from common import common_prompt
from common.model_manager import ModelManager
from common.util.common_util import fill_batch_log, merge_batch_logs
from components.knowledge_extractor import KnowledgeExtractor
from components.VulRAG import VulRAGDetector


def get_cwes(benchmark): #returns a list of CWE values

    if benchmark == "PairVul":
        cwes = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
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
        help = 'file descriptor of the specific test being run'
    )

    parser.add_argument(
        '--learned',
        action= 'store_true',
        default=False,
        help='triggers using the learned reranker and embeddings'
    )

    parser.add_argument(
        '--top_num',
        type=int,
        default=3,
        help='amount of items to store'
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

    args = parser.parse_args()

    return args


def enrich_test(benchmark, model, resume):

    #load from partial/{benchmark}/3_enhanced_data/test_set
    cwe_list = get_cwes(benchmark)
    testset_dir = Path(constant.V2_TESTSET_DIR.format(benchmark=benchmark))
    enhanced_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))
    

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

            batch_output_path = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark)) /constant.BATCH_OUTPUT_NAME.format(cwe=cwe)

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

    KnowledgeE = KnowledgeExtractor(model_name = 'gpt-3.5-turbo')

    KnowledgeE.document_store(cwe_name_list=cwes, V2=True)


def search(benchmark, desc, k, learned):
    cwes = get_cwes(benchmark)
    input_dir = Path(constant.V2_ENHANCED_DATA_DIR.format(benchmark=benchmark))
    output_dir = Path(constant.V2_SEARCH_RESULTS_DIR.format(benchmark=benchmark, k=k, search_method=desc))
    orig_data_dir = Path(constant.V2_TESTSET_DIR.format(benchmark=benchmark))

    #define input path, and output path
    for cwe in cwes:
        input_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        output_file = constant.PROCESSED_OUTPUT.format(cwe=cwe)
        input_path = input_dir / input_file
        output_path = output_dir / output_file
        orig_data_file = constant.TEST_DATA_FILE_NAME.format(cwe_id=cwe)
        orig_data_path = orig_data_dir / orig_data_file

        with open(orig_data_path, "r", encoding="utf-8") as f:
            test_data = json.load(f)

        VulD = VulRAGDetector("gpt-3.5-turbo", "gpt-3.5-turbo", input_path)
        start_time = datetime.now()

        total_results = []

        for value in tqdm(test_data):
            
            id = value["id"]
            vul_code_snippet = value["code_before_change"]
            non_vul_code_snippet = value["code_after_change"]

            vul_purpose = VulD.data.get(f"{id}PV")
            non_vul_purpose = VulD.data.get(f"{id}PN")

            vul_function = VulD.data.get(f"{id}FV")
            non_vul_function = VulD.data.get(f"{id}FN")

            if learned:
                vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, vul_code_snippet, vul_purpose, vul_function, k, True)
                non_vul_knowledge_list = VulD.retrieve_learned_knowledge(cwe, non_vul_code_snippet, non_vul_purpose, non_vul_function, k, True)
            else:
                vul_knowledge_list = VulD.retrieve_knowledge()
                non_vul_knowledge_list = VulD.retrieve_knowledge()

            total_results.append({
                "id": id,
                "vul_knowledge": vul_knowledge_list,
                "non_vul_knowledge": non_vul_knowledge_list,
            })

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(total_results, f, indent=2)
            



def rerank(benchmark):

    return 0


def decision(benchmark):

    return 0


if __name__ == '__main__':

    args = parse_command_line_arguments()

    if args.action == None:
        raise Exception("Forgot to put an action into this")
    

    if args.action == 'enrich_test':
        enrich_test(args.benchmark, args.model, args.resume)

    elif args.action == 'load':
        load_elastic(args.benchmark)

    elif args.action == 'search':
        search(args.benchmark, args.model, args.top_num, args.learned)

    elif args.action == 'rerank':
        rerank(args.benchmark, args.resume)

    elif args.action == 'decision':
        decision(args.benchmark, args.model, args.resume)

    else:
        raise Exception("There is an incorrect action verb here")