import json
from tqdm import tqdm
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from .es_retrival import LLM4DetectionRetrieval
from common import constant
from common.util import common_util

import common.constant as constant
from common.constant import KnowledgeDocumentName as kdn
from common.model_manager import ModelManager
import logging
import pdb
from common.common_prompt import ExtractionPrompt
from pathlib import Path

# "CWE-416": "Use After Free", !!
# "CWE-125": "Out-of-bounds Read",
# "CWE-787": "Out-of-bounds Write",
# "CWE-476": "NULL Pointer Dereference",
# "CWE-401": "Missing Release of Memory after Effective Lifetime",
# "CWE-190": "Integer Overflow or Wraparound", !!
# "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"
# "CWE-122": "Heap-based Buffer Overflow",
# "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer", !!
# "CWE-120": "Buffer Copy without Checking Size of Input ('Classic  ')",

class KnowledgeExtractor:
    def __init__(self, model_name, V2=False, benchmark="PairVul"):
        self.model_instance = ModelManager.get_model_instance(model_name)
        self.data_lst = []

        self.benchmark = benchmark
        self.V2 = V2

        print("knowledge extractor initialized")

    def get_dict(self, vul_knowledge_output):
        vul_knowledge_output = vul_knowledge_output.split("\"vulnerability_behavior\"")[1]
        vul_knowledge_output = "{\"vulnerability_behavior\"" + vul_knowledge_output
        if "\n```" in vul_knowledge_output:
            vul_knowledge_output = vul_knowledge_output.split("\n```")[0]
        return json.loads(vul_knowledge_output)

    def format_knowledge_file(self, path):
        kno_dict = DataUtils.load_json(path)
        answer = {}
        for cve in kno_dict:
            answer[cve] = []
            for item in kno_dict[cve]:
                item[kdn.PRECONDITIONS.value] = item[kdn.VUL_BEHAVIOR.value][kdn.PRECONDITIONS.value]
                item[kdn.TRIGGER.value] = item[kdn.VUL_BEHAVIOR.value][kdn.TRIGGER.value]
                item[kdn.CODE_BEHAVIOR.value] = item[kdn.VUL_BEHAVIOR.value][kdn.CODE_BEHAVIOR.value]
                if kdn.SOLUTION.value in item:
                    item[kdn.SOLUTION.value] = item[kdn.SOLUTION.value]
                answer[cve].append(item)

        DataUtils.save_json(path, answer)

    def extract_knowledge_from_cwe(self, CWE_name, extract_only_once, resume, **kwargs):
        
        if self.V2: #sets the input and output paths
            try:
                self.data_lst = DataUtils.load_json(PathUtil.clean_dataV2(constant.TEST_DATA_FILE_NAME.format(cwe_id = CWE_name), "json", self.benchmark))
            except Exception as e:
                logging.error(f"Error in loading data: {e}")

            model_settings_dict = kwargs.get("model_settings_dict", {})

            output_path = PathUtil.knowledge_extraction_output_V2( 
                constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                    model_name = self.model_instance.get_model_name(),
                    cwe_id = CWE_name
            ), 
            "json", self.benchmark
            )

        else:
            try:
                self.data_lst = DataUtils.load_json(PathUtil.clean_data(
                    constant.CLEAN_DATA_FILE_NAME.format(cwe_id = CWE_name), "json"
                ))
            except Exception as e:
                logging.error(f"Error in loading data: {e}")

            model_settings_dict = kwargs.get("model_settings_dict", {})
            
            output_path = PathUtil.knowledge_extraction_output(
                constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                    model_name = self.model_instance.get_model_name(), 
                    cwe_id = CWE_name
                ),
                "json"
            )
            
        #add json file so that resuming can go normally
        if PathUtil.check_file_exists(output_path) and resume:
            current_knowledge_pattern = DataUtils.load_json(output_path)
            output_list = current_knowledge_pattern
            processed_path = PathUtil.knowledge_extraction_output_V2(
                "metrics/processed_ids",
                "json", self.benchmark
            )
            with open(processed_path, "r") as f:
                processed_ids = set(json.load(f))
            print(processed_ids)

        else:
            output_list = {}
            processed_ids = set()
        batch_items = []

        for item in tqdm(self.data_lst):
            entry_id = item["id"]
            cve_id = item["cve_id"]

            if entry_id in processed_ids:
                continue
            
            if cve_id not in output_list:
                output_list[cve_id] = []
            (
                purpose_prompt, 
                function_prompt, 
                analysis_prompt, 
                knowledge_extraction_prompt
            ) = ExtractionPrompt.generate_extract_prompt(
                item["cve_id"], 
                item["cve_description"], 
                item["function_modified_lines"], 
                item["code_before_change"], 
                item["code_after_change"]
            )
            try:
                # get purpose
                purpose_messages = self.model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
                function_messages = self.model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
                messages = self.model_instance.get_messages(analysis_prompt, constant.DEFAULT_SYS_PROMPT)

                if self.V2:
                    #Add prompts to batch list
                    poop = fart
                else:
                    processed_ids.add(item["id"])

                    purpose_output = self.model_instance.get_response_with_messages(purpose_messages, **model_settings_dict)
                    if(purpose_output is None):
                        logging.warning(f"Skipping{item['cve_id']} due to missing purpose_output")
                        continue
                    # get function
                    function_output = self.model_instance.get_response_with_messages(function_messages, **model_settings_dict)
                    if(function_output is None):
                        logging.warning(f"Skipping{item['cve_id']} due to missing function_output")
                        continue
                    
                    # get analysis
                    analysis_output = self.model_instance.get_response_with_messages(messages, **model_settings_dict)
                    if(analysis_output is None):
                        logging.warning(f"Skipping{item['cve_id']} due to missing analysis_output")
                        continue
                    
                    messages.append({"role": "assistant", "content": analysis_output})
                    messages.append({"role": "user", "content": knowledge_extraction_prompt})
                    vul_knowledge_output = self.model_instance.get_response_with_messages(messages, **model_settings_dict)
                    if(vul_knowledge_output is None):
                        logging.warning(f"Skipping{item['cve_id']} due to missing vul_knowledge_output")
                        continue

                    output_dict = self.get_dict(vul_knowledge_output)
                    output_dict["GPT_analysis"] = analysis_output
                    output_dict["GPT_purpose"] = common_util.extract_LLM_response_by_prefix(
                        purpose_output,
                        constant.LLMResponseSeparator.FUN_PURPOSE_SEP.value
                    )
                    output_dict["GPT_function"] = common_util.extract_LLM_response_by_prefix(
                        function_output,
                        constant.LLMResponseSeparator.FUN_FUNCTION_SEP.value
                    )
                    output_dict["CVE_id"] = item["cve_id"]
                    output_dict["code_before_change"] = item["code_before_change"]
                    output_dict["code_after_change"] = item["code_after_change"]
                    output_dict["modified_lines"] = item["function_modified_lines"]
                    output_dict["true_id"] = item["id"]
                    output_list[item["cve_id"]].append(output_dict)
                
                    #save progress to the dumpfile
                    with open(processed_path, "w") as f:
                        json.dump(list(processed_ids), f)

            except Exception as e:
                logging.error(f"Error in extracting knowledge for {item['cve_id']}: {e}")
                pdb.set_trace()
            
            if not self.V2:
                DataUtils.save_json(output_path, output_list)
                self.format_knowledge_file(output_path)

        if self.V2:
            #run the batch request
            self.model_instance.start_batch()
            
            #poll until the batch returns
            self.model_instance.check_batch()
            #generate and run the second batch (to generate the final item)

            #iterate through returned item and generate the output dict UPDATE PROCESSED IDS CORRECTLY

            #write the output dict and call format_knowledge_file

    def document_store(self, cwe_name_list):
        for cwe_name in cwe_name_list:
            doc_path = PathUtil.knowledge_extraction_output(
                constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                    model_name = self.model_instance.get_model_name(), 
                    cwe_id = cwe_name
                ), 
                "json"
            )
            #this line has document_name as in get_es_document_values
            for document_name in constant.KnowledgeDocumentName.get_es_document_values():
                es_retrieval = LLM4DetectionRetrieval(
                    constant.ES_INDEX_NAME_TEMPLATE.format(
                        lower_cwe_id = cwe_name.lower(), 
                        lower_document_name = document_name.lower()
                    ),
                    document_name
                )
                es_retrieval.update_new_documents(doc_path = doc_path, cwe_name=cwe_name, document_name=document_name)
