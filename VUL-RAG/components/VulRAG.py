from common.util.data_utils import DataUtils
import common.config as cfg
import logging
from .es_retrival import LLM4DetectionRetrieval
from common.util import common_util
from common import constant
from common.constant import KnowledgeDocumentName as kdn
from common.model_manager import ModelManager
from common import common_prompt
from common.util.track_util import Tracker
import pdb
import logging
import json
import openai
import tiktoken
from tqdm import tqdm
from elasticsearch import Elasticsearch
import numpy as np
import lightgbm as lgb
import os
import datetime

class VulRAGDetector:
    def __init__(
            self, 
            model_name: str,
            summary_model_name: str,
            knowledge_path: str,
            retrieval_rank_weight: list = cfg.DEFAULT_RETRIEVAL_RANK_WEIGHT
        ):
        self.vul_knowledge = DataUtils.load_json(knowledge_path)
        self.retrieval_rank_weight = retrieval_rank_weight
        self.model_instance = ModelManager.get_model_instance(model_name)
        self.summary_model_instance = ModelManager.get_model_instance(summary_model_name)
        self.purp = None
        self.func = None
        self.code = None
    
    def update_retrievers(self, cwe_name):
        self.func = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.FUNCTION.value.lower()
        ), kdn.FUNCTION.value.lower())

        self.purp = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.PURPOSE.value.lower()
        ), kdn.PURPOSE.value.lower())

        self.code = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.CODE_BEFORE.value.lower()
        ), kdn.CODE_BEFORE.value.lower())
    
    def add_test_knowledge(self, path):
        self.test_knowledge = DataUtils.load_json(path)

    def rerank_by_rank(self, purpose_result: list, function_result: list, code_result: list):
        '''
        rerank the cve_id by the rank of three results
        :param purpose_result:
        :param function_result:
        :param code_result:
        :return:
        '''
        cve_id_list = function_result + purpose_result + code_result
        cve_id_list = list(set(cve_id_list))
        weight = self.retrieval_rank_weight[:3]
        cve_id_dict = {}
        for cve_id in cve_id_list:
            try:
                cve_id_dict[cve_id] = 0
                purpose_index = purpose_result.index(cve_id) if cve_id in purpose_result else len(purpose_result)
                function_index = function_result.index(cve_id) if cve_id in function_result else len(function_result)
                code_index = code_result.index(cve_id) if cve_id in code_result else len(code_result)
                cve_id_dict[cve_id] += purpose_index * weight[0] + function_index * weight[1] + code_index * weight[2]

            except Exception as e:
                logging.error(f"Error: {e}")

        cve_id_dict = sorted(cve_id_dict.items(), key = lambda x: x[1], reverse = False)

        final_result = []
        for item in cve_id_dict:
            id_info = {}
            id_info["cve_id"] = item[0]
            id_info["count"] = item[1]
            final_result.append(id_info)

        return final_result

    def format_retrieved_answer(self, purpose_answer, function_answer, code_answer):
        '''
        format the retrieval answer
        :param purpose_answer:
        :param function_answer:
        :param code_answer:
        :return:
        '''
        purpose_list = []
        purpose_dict = {}
        function_list = []
        function_dict = {}
        code_list = []
        code_dict = {}

        for item in purpose_answer:
            purpose_list.append(item["cve_id"])
            purpose_dict[item["cve_id"]] = item["content"]
        for item in function_answer:
            function_list.append(item["cve_id"])
            function_dict[item["cve_id"]] = item["content"]
        for item in code_answer:
            code_list.append(item["cve_id"])
            code_dict[item["cve_id"]] = item["content"]
        #This line cuts the list from potentially 30 down to 10
        rerank_result = self.rerank_by_rank(purpose_list, function_list, code_list)

        #enriches these 10 lines with all the total data
        knowledge_list = []
        for item in rerank_result:
            try:
                cve_knowledge = self.vul_knowledge[item["cve_id"]]
                for knowledege_item in cve_knowledge:
                    if (item["cve_id"] in purpose_dict.keys() and 
                        purpose_dict[item["cve_id"]] == knowledege_item[kdn.PURPOSE.value]) \
                    or (item["cve_id"] in function_dict.keys() and 
                        function_dict[item["cve_id"]] == knowledege_item[kdn.FUNCTION.value]) \
                    or (item["cve_id"] in code_dict.keys() and 
                        code_dict[item["cve_id"]] == knowledege_item[kdn.CODE_BEFORE.value]):

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
                        break

            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Error cve_id: {item['cve_id']}")

        return knowledge_list
    
    def truncate_to_limit(self, text, max_tokens=8192, model="text-embedding-3-small"):
        encoding = tiktoken.encoding_for_model(model)
        tokens = encoding.encode(text)
        if len(tokens) > 8192:
            print(f"truncated a text that was at {len(tokens)}")
        truncated = tokens[:max_tokens]
        return encoding.decode(truncated)
    
    def embedder(self, query):
        logging.disable(logging.CRITICAL)

        openai.api_key = cfg.openkey_openai_api_key

        truncated = self.truncate_to_limit(query)
        try:    
            response = openai.embeddings.create( 
                input= truncated,
                model="text-embedding-3-small"
            )
        except Exception as e:
            print(f"Failed to embed document: {e}")
        
        embedding = response.data[0].embedding
        return embedding
    
    def format_embeddings(self, embed):
        formatted_answer_list = []
        for answer in embed["hits"]["hits"]:
            formatted_answer_list.append({
                "content": answer["_source"].get("content", ""),
                "cve_id": answer["_source"].get("cve_id", "N/A"),
                "score": answer.get("_score", 0)
            })
        return formatted_answer_list

    def retrieve_knowledge(self, cwe_name, code_snippet, purpose, function, top_N=10, early_exit=False):
        logging.disable(logging.INFO)
        
        es_purpose = self.purp
        es_function = self.func
        es_code = self.code

        #search bm25 results
        purpose_answer = es_purpose.search_cve(query = purpose, idx = 2, filteridx = 2, cve_id=1, top_k=top_N)
        function_answer = es_function.search_cve(query = function, idx = 1, filteridx = 2, cve_id=1, top_k=top_N)        
        code_answer = es_code.search_cve(query = code_snippet, idx = 0, filteridx = 2, cve_id=1, top_k=top_N)   

        # enable logging info
        logging.disable(logging.NOTSET)

        if early_exit:
            return (purpose_answer, function_answer, code_answer)

        return self.format_retrieved_answer(purpose_answer, function_answer, code_answer)

    def format_retrieved_answer_by_code(self, code_before_answer, code_after_answer):
        assert len(code_before_answer) == len(code_after_answer)
        code_list = []
        for i in range(len(code_before_answer)):
            code_list.append({
                "code_before_change": code_before_answer[i]["content"], 
                "code_after_change": code_after_answer[i]["content"], 
                "cve_id": code_before_answer[i]["cve_id"]}
            )
        return code_list

    def learned_reranker(self, input_dict, top_N=10):
        #create a np.array of the vectors and also create a second array that holds the keys
        ordered_keys = list(input_dict.keys())
        scores_array = np.array([input_dict[key]["scores"] for key in input_dict])
        
        #iterate through the 5 different models
        output_dir = constant.V2_LEARNED_RERANKER_DIR.format(benchmark="PairVul")
        models = []
        for fold_idx in range(1,6):
            model_path = os.path.join(output_dir, f"model_fold_{fold_idx}.txt")
            assert os.path.exists(model_path), f"Model file not found: {model_path}"
            model = lgb.Booster(model_file=model_path)
            models.append(model)
        #call predict on the np.array
        all_scores = [model.predict(scores_array) for model in models]
        avg_scores = np.mean(all_scores, axis=0)
        #iterate through the returned list and find the 10 highest values after taking the average
        key_score_pairs = list(zip(ordered_keys, avg_scores))
        top_10_pairs = sorted(key_score_pairs, key=lambda x: x[1], reverse=True)[:top_N] 
        #after iterating through all 5 models choose the models with the 10 highest scores and place in dict
        top_10_dict = {k: v for k, v in top_10_pairs}
        
        return top_10_dict

    def final_format(self, response):

        reranked_results = self.learned_reranker(response)

        #swap the id field in this top k variable with the cve_id that can be used to fill out info
        true_id_list = [int(key) for key in reranked_results.keys()]
                    
        #fill in info to match the original return value of retrieve_knowledge()
        knowledge_list = []
        for tid in true_id_list:
            found = False
            for cve_id, entries in self.vul_knowledge.items():
                for entry in entries:
                    if entry.get("true_id") == tid:
                        vul_behavior = entry.get(kdn.VUL_BEHAVIOR.value, {})
                        knowledge_list.append({
                            "cve_id": entry.get(kdn.CVE_ID.value),
                            "vulnerability_behavior": {
                                kdn.PRECONDITIONS.value: vul_behavior.get(kdn.PRECONDITIONS.value),
                                kdn.TRIGGER.value: vul_behavior.get(kdn.TRIGGER.value),
                                kdn.CODE_BEHAVIOR.value: vul_behavior.get(kdn.CODE_BEHAVIOR.value)
                            },
                            "solution_behavior": entry.get(kdn.SOLUTION.value),
                        })
                        found = True
                        break
                if found:
                    break
        return knowledge_list        

    def retrieve_similar_code(self, cwe_name, code_snippet, top_N):
        
        #THIS FUNCTION IS DEPRECATED DUE TO NOT SETTING UP A CODE_AFTER_CHANGE RETRIEVER
        function_query = code_snippet
        es_retrieval = self.code
        try:
            code_before_change_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)
        except:
            code_before_change_answer = es_retrieval.search(
                query = function_query[:cfg.ES_SEARCH_MAX_TOKEN_LENGTH], 
                retrieve_top_k = top_N
            )

        es_retrieval = "This is where the new retriever has to go"
        try:
            code_after_change_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)
        except:
            code_after_change_answer = es_retrieval.search(
                query = function_query[:cfg.ES_SEARCH_MAX_TOKEN_LENGTH], 
                retrieve_top_k = top_N
            )
        return self.format_retrieved_answer_by_code(code_before_change_answer, code_after_change_answer)
    
    def fill_empty_blanks(self, dicts):
        all_keys = set()
        combined = {}
        
        # Collect all keys from all dicts
        for d in dicts:
            all_keys.update(d.keys())

        for key in tqdm(all_keys):
            scores = []
            for d in dicts:
                if key not in d:
                    # Fill missing key with 0
                    d[key] = {"cve_id": "blank", "score": 0, "id": key}
                scores.append(d[key]["score"])
            
            combined[key] = {"scores": scores}

        return combined

    def fill_blanks(self, purpose_ds, function_ds, code_ds, dicts, queries):
        all_keys = set()
        combined = {}
        for d in dicts:
            all_keys.update(d.keys())

        for key in tqdm(all_keys):
            scores = []
            for i, d in enumerate(dicts):
                if key not in d:
                    if i == 0: #code dict missing
                        res = code_ds.search_cve(query = queries[i], idx = 0, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                            print("Empty code on: ", key)
                    elif i == 1: #code embed dict missing
                        res = code_ds.search_embed_cve(query = queries[i], idx = 0, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                            print("Empty code emb on: ", key)
                    elif i == 2: #function dict missing
                        res = function_ds.search_cve(query = queries[i], idx = 1, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                            print("Empty function on: ", key)
                    elif i == 3: #function embed dict missing
                        res = function_ds.search_embed_cve(query = queries[i], idx = 1, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                            print("Empty emb function on: ", key)
                    elif i == 4: #purpose dict missing
                        res = purpose_ds.search_cve(query = queries[i], idx = 2, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                    elif i == 5: #purpose embed dict missing
                        res = purpose_ds.search_embed_cve(query = queries[i], idx = 2, filteridx = 3, cve_id = key)
                        if res is not None and key in res and res[key] is not None:
                            d[key] = res[key]
                        else:
                            d[key] = {"cve_id": "Whoops", "score": 0, "id": key}
                            print("Empty emb purpose on: ", key)
                    else:
                        print("Passed too many dicts")
                scores.append(d[key]["score"])
            
            combined[key] = {"scores": scores}
        return combined

    def retrieve_learned_knowledge(self, cwe_name, code_snippet, purpose, function, top_N=10, early_exit=False):

        #generate embeddings for passed queries
        purpose_embed = self.embedder(purpose)
        function_embed = self.embedder(function)
        code_embed = self.embedder(code_snippet)

        #generate the three es_retrieval items
        es_purpose = self.purp
        es_function = self.func
        es_code = self.code

        #search bm25 results
        purpose_answer = es_purpose.search_cve(query = purpose, idx = 2, filteridx = 2, cve_id=1, top_k=top_N)
        function_answer = es_function.search_cve(query = function, idx = 1, filteridx = 2, cve_id=1, top_k=top_N)        
        code_answer = es_code.search_cve(query = code_snippet, idx = 0, filteridx = 2, cve_id=1, top_k=top_N)   

        #search emb results
        purpose_embed_answer = es_purpose.search_embed_cve(query = purpose_embed, idx = 2, filteridx = 2, cve_id=1, top_k=top_N)
        function_embed_answer = es_function.search_embed_cve(query = function_embed, idx = 1, filteridx = 2, cve_id=1, top_k=top_N)        
        code_embed_answer = es_code.search_embed_cve(query = code_embed, idx = 0, filteridx = 2, cve_id=1, top_k=top_N)
        #call fill_blanks
        dicts = [code_answer, code_embed_answer, function_answer, function_embed_answer, purpose_answer, purpose_embed_answer]
        queries = [code_snippet, code_embed, function, function_embed, purpose, purpose_embed]
        response = self.fill_blanks(es_purpose, es_function, es_code, dicts, queries)  

        #if we want a early return perform that here
        if early_exit:
            return response
        #return the formatted list
        return self.final_format(response)

    def detect_pipeline_retrival_by_code(self, code_snippet, cwe_name, top_N, **kwargs):
        sample_id = kwargs.get('sample_id')
        model_settings_dict = kwargs.get('model_settings_dict', {})
        query_cve = kwargs.get('cve_id')

        vul_knowledge_list = self.retrieve_similar_code(cwe_name, code_snippet, top_N)

        detect_result = []

        for vul_knowledge in vul_knowledge_list[:min(cfg.MAX_RETRIEVE_CODE_NUM, len(vul_knowledge_list))]:
            vul_detect_prompt = common_prompt.VulRAGPrompt.generate_detect_prompt_for_code_retrieval(
                code_snippet,
                vul_knowledge["code_before_change"],
                vul_knowledge["code_after_change"]
            )
            vul_messages = self.model_instance.get_messages(
                vul_detect_prompt, 
                constant.DEFAULT_SYS_PROMPT
            )
            vul_output = self.model_instance.get_response_with_messages(
                vul_messages,
                **model_settings_dict
            )
            detect_result.append({
                "vul_knowledge": vul_knowledge, 
                "vul_detect_prompt": vul_detect_prompt,
                "vul_output": vul_output
            })
            if constant.LLMResponseKeywords.POS_ANS.value in vul_output:
                return {
                    "id": sample_id,
                    "cve_id": query_cve, 
                    "code_snippet": code_snippet, 
                    "detect_result": detect_result, 
                    "detection_model": self.model_instance.get_model_name(),
                    "model_settings": model_settings_dict,
                    "final_result": 1
                }

        return {
            "id": sample_id,
            "cve_id": query_cve, 
            "code_snippet": code_snippet, 
            "detect_result": detect_result, 
            "detection_model": self.model_instance.get_model_name(),
            "model_settings": model_settings_dict,
            "final_result": 0
        }

    def detection_pipeline(self, code_snippet, state, cwe_name, top_N, tracker, **kwargs):
        """
        Detects vulnerabilities in a given code snippet using a pipeline that leverages multiple models and knowledge bases.
        This method processes a code snippet to identify potential vulnerabilities by extracting its purpose and function,
        retrieving relevant knowledge, and evaluating the code against this knowledge to determine the presence of vulnerabilities.
        Args:
            code_snippet (str): The code snippet to be analyzed for vulnerabilities.
            state (Any): The current state or context required for detection (details depend on implementation).
            cwe_name (str): The Common Weakness Enumeration (CWE) name associated with the vulnerability.
            top_N (int): The number of top knowledge entries to retrieve and evaluate.
            **kwargs:
                sample_id (str, optional): The unique identifier for the sample being analyzed.\n
                model_settings_dict (dict, optional): A dictionary of settings to configure the model instances.\n
                query_cve (str): The CVE identifier related to the vulnerability being queried.\n
                no_explanation (bool, optional): A flag indicating whether to include explanations in the detection prompt.
        Returns:
            dict: A dictionary containing the results of the vulnerability detection process with the following keys:
                - id (str): The unique identifier for the sample.
                - cve_id (str): The CVE identifier associated with the detection.
                - purpose (str): The extracted purpose of the code snippet.
                - function (str): The extracted function of the code snippet.
                - code_snippet (str): The original code snippet analyzed.
                - detect_result (list): A list of detection results for each knowledge entry evaluated.
                - detection_model (str): The name of the detection model used.
                - summary_model (str): The name of the summary model used.
                - model_settings (dict): The settings used for the models during detection.
                - final_result (int): The final result of the detection process:
                    - 1 indicates a confirmed vulnerability.
                    - 0 indicates no vulnerability detected.
                    - -1 indicates possibly no vulnerability detected.
        """
        sample_id = kwargs.get('sample_id')
        model_settings_dict = kwargs.get('model_settings_dict', {})
        query_cve = kwargs.get('cve_id')
        no_explanation = kwargs.get('no_explanation', False)

        #log the beginning of a query
        start_time = datetime.now()

        # get purpose and function
        purpose_prompt, function_prompt = common_prompt.ExtractionPrompt.generate_extraction_prompt_for_vulrag(code_snippet)
        purpose_messages = self.summary_model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
        function_messages = self.summary_model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
        response, p_inp_tokens, p_out_tokens = self.summary_model_instance.get_response_with_messages(
                purpose_messages,
                **model_settings_dict
            )
        purpose = common_util.extract_LLM_response_by_prefix(
            response,
            constant.LLMResponseSeparator.FUN_PURPOSE_SEP.value
        )
        response, f_inp_tokens, f_out_tokens = self.summary_model_instance.get_response_with_messages(
                function_messages,
                **model_settings_dict
            )
        function = common_util.extract_LLM_response_by_prefix(
            response,
            constant.LLMResponseSeparator.FUN_FUNCTION_SEP.value
        )
        
        #call tracker.log with query type to make sure we note the latency of the query
        end_time = datetime.now()
        tracker.log("query", (end_time - start_time).total_seconds() * 1000, (p_inp_tokens + f_inp_tokens), (p_out_tokens + f_out_tokens))

        print("calling retrieve learned knowledge")
        # retrieve knowledge
        start_time = datetime.now()
        vul_knowledge_list = self.retrieve_learned_knowledge(cwe_name, code_snippet, purpose, function, top_N)
        end_time = datetime.now()
        
        tracker.log("retrieval", (end_time - start_time).total_seconds() * 1000)
        
        # logging.info("len(vul_knowledge_list): %d", len(vul_knowledge_list))
        # detect vulnerability with the ranking knowledge list, 
        # if Yes/No is detected, return the result, 
        # else, continue to detect the next knowledge
        detect_result = []
        flag = 0
        counter = 0
        lib_counter = 0
        lib = 0
        dec = 0
        print("returned with my knowledge")
        for vul_knowledge in vul_knowledge_list[:min(cfg.MAX_RETRIEVE_KNOWLEDGE_NUM, len(vul_knowledge_list))]:
            counter += 1
            start_time = datetime.now()
            if no_explanation:
                vul_detect_prompt = common_prompt.VulRAGPrompt.generate_detect_vul_prompt_without_explanation(
                    code_snippet, 
                    vul_knowledge
                )
                sol_detect_prompt = common_prompt.VulRAGPrompt.generate_detect_sol_prompt_without_explanation(
                    code_snippet, 
                    vul_knowledge
                )
            else:
                vul_detect_prompt = common_prompt.VulRAGPrompt.generate_detect_vul_prompt(code_snippet, vul_knowledge)
                sol_detect_prompt = common_prompt.VulRAGPrompt.generate_detect_sol_prompt(code_snippet, vul_knowledge)
            
            vul_messages = self.model_instance.get_messages(vul_detect_prompt, constant.DEFAULT_SYS_PROMPT)
            sol_messages = self.model_instance.get_messages(sol_detect_prompt, constant.DEFAULT_SYS_PROMPT)
            vul_output, v_inp_tokens, v_out_tokens = self.model_instance.get_response_with_messages(
                vul_messages,
                **model_settings_dict
            )
            sol_output, s_inp_tokens, s_out_tokens = self.model_instance.get_response_with_messages(
                sol_messages,
                **model_settings_dict
            )
            result = {
                "vul_knowledge": vul_knowledge,
                "vul_detect_prompt": vul_detect_prompt,
                "vul_output": vul_output,
                "sol_detect_prompt": sol_detect_prompt,
                "sol_output": sol_output
            }
            end_time = datetime.now()
            tracker.log("query", (end_time - start_time).total_seconds() * 1000, (s_inp_tokens + v_inp_tokens), (s_out_tokens + v_out_tokens))

            if(query_cve == result["vul_knowledge"]["cve_id"]):
                lib = 1
                lib_counter = counter
                if (constant.LLMResponseKeywords.POS_ANS.value in vul_output and 
                constant.LLMResponseKeywords.NEG_ANS.value in sol_output):
                    dec = 1

            detect_result.append(result)
            if (constant.LLMResponseKeywords.POS_ANS.value in vul_output and 
                constant.LLMResponseKeywords.NEG_ANS.value in sol_output):
                return {
                    "id": sample_id,
                    "cve_id": query_cve,
                    "purpose": purpose, 
                    "function": function, 
                    "code_snippet": code_snippet, 
                    "detect_result": detect_result, 
                    "detection_model": self.model_instance.get_model_name(),
                    "summary_model": self.summary_model_instance.get_model_name(),
                    "model_settings": model_settings_dict,
                    "final_result": 1,
                    "lib_present": lib,
                    "lib_decision": dec,
                    "Counter": lib_counter
                }
            elif constant.LLMResponseKeywords.POS_ANS.value in sol_output:
                {
                    "id": sample_id,
                    "cve_id": query_cve,
                    "purpose": purpose, 
                    "function": function, 
                    "code_snippet": code_snippet, 
                    "detect_result": detect_result, 
                    "detection_model": self.model_instance.get_model_name(),
                    "summary_model": self.summary_model_instance.get_model_name(),
                    "model_settings": model_settings_dict,
                    "final_result": 0,
                    "lib_present": lib,
                    "lib_decision": dec,
                    "Counter": lib_counter
                }
            else:
                continue

        #if the whole list has been iterated and no vulns then mark non-vulnerable
        if (lib == 1):
            dec = 1
        if(lib == 0):
            lib_counter = 0
        return {
            "id": sample_id,
            "cve_id": query_cve, 
            "purpose": purpose, 
            "function": function, 
            "code_snippet": code_snippet, 
            "detect_result": detect_result, 
            "detection_model": self.model_instance.get_model_name(),
            "summary_model": self.summary_model_instance.get_model_name(),
            "model_settings": model_settings_dict,
            "final_result": 0,
            "lib_present": lib,
            "lib_decision": dec,
            "Counter": lib_counter
        }

    def training_pipeline(self, code_snippet, state, cwe_name, top_N, **kwargs):
        final_data = []
        #generate purpose, function based on prompt
        sample_id = kwargs.get('sample_id')
        model_settings_dict = kwargs.get('model_settings_dict', {})
        query_cve = kwargs.get('cve_id')
        no_explanation = kwargs.get('no_explanation', False)

        # get purpose and function
        purpose_prompt, function_prompt = common_prompt.ExtractionPrompt.generate_extraction_prompt_for_vulrag(code_snippet)
        purpose_messages = self.summary_model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
        function_messages = self.summary_model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
        purpose = common_util.extract_LLM_response_by_prefix(
            self.summary_model_instance.get_response_with_messages(
                purpose_messages,
                **model_settings_dict
            ),
            constant.LLMResponseSeparator.FUN_PURPOSE_SEP.value
        )
        function = common_util.extract_LLM_response_by_prefix(
            self.summary_model_instance.get_response_with_messages(
                function_messages,
                **model_settings_dict
            ),
            constant.LLMResponseSeparator.FUN_FUNCTION_SEP.value
        )
        
        #Create the es items that will be used to access all of our retrievers
        es_purpose = self.purp
        es_function = self.func
        es_code = self.code

        #Search for incorrect examples (label == 0, filteridx == 1)
        purpose_answer = es_purpose.search_cve(query = purpose, idx = 2, filteridx = 1, cve_id=query_cve)
        if not purpose_answer:
            print("Something went wrong purpose not found for non-matching")
            return
        purpose_embed = self.embedder(purpose)
        purpose_embed_answer = es_purpose.search_embed_cve(query = purpose_embed, idx = 2, filteridx = 1, cve_id=query_cve)

        function_answer = es_function.search_cve(query = function, idx = 1, filteridx = 1, cve_id=query_cve)        
        function_embed = self.embedder(function)
        function_embed_answer = es_function.search_embed_cve(query = function_embed, idx = 1, filteridx = 1, cve_id=query_cve)        

        code_answer = es_code.search_cve(query = code_snippet, idx = 0, filteridx = 1, cve_id=query_cve)   
        code_embed = self.embedder(code_snippet)
        code_embed_answer = es_code.search_embed_cve(query = code_embed, idx = 0, filteridx = 1, cve_id=query_cve)

        #gather dicts of answers and queries to pass to response
        dicts = [code_answer, code_embed_answer, function_answer, function_embed_answer, purpose_answer, purpose_embed_answer]
        queries = [code_snippet, code_embed, function, function_embed, purpose, purpose_embed]
        
        response = self.fill_blanks(es_purpose, es_function, es_code, dicts, queries)

        #load final data with response + label 1
        label = 0
        for key, entry in response.items():
            final_data.append(({
                "scores": entry["scores"],
                "label": label,
            }))

        #SEARCH FOR MATCHES CVE NUMS (label == 1, filteridx == 0)
        purpose_answer = es_purpose.search_cve(query = purpose, idx = 2, filteridx = 0, cve_id=query_cve)
        #if the dictionary is empty we will be unable to use this example and return the incorrect answer
        if not purpose_answer:
            print(f"No positive example for {query_cve}")
            print(f"Generated {len(final_data)} negative examples for {query_cve}")
            return final_data
        purpose_embed = self.embedder(purpose)
        purpose_embed_answer = es_purpose.search_embed_cve(query = purpose_embed, idx = 2, filteridx = 0, cve_id=query_cve)

        #function_answer = es_retrieval.search_cve()
        function_answer = es_function.search_cve(query = function, idx = 1, filteridx = 0, cve_id=query_cve)        
        function_embed = self.embedder(function)
        function_embed_answer = es_function.search_embed_cve(query = function_embed, idx = 1, filteridx = 0, cve_id=query_cve)        

        #code_answer = es_retrieval.search_cve()
        code_answer = es_code.search_cve(query = code_snippet, idx = 0, filteridx = 0, cve_id=query_cve)   
        code_embed = self.embedder(code_snippet)
        code_embed_answer = es_code.search_embed_cve(query = code_embed, idx = 0, filteridx = 0, cve_id=query_cve)

        dicts = [code_answer, code_embed_answer, function_answer, function_embed_answer, purpose_answer, purpose_embed_answer]
        queries = [code_snippet, code_embed, function, function_embed, purpose, purpose_embed]
        response = self.fill_blanks(es_purpose, es_function, es_code, dicts, queries)        
        #load final data with label 1
        label = 1
        for key, entry in response.items():
            final_data.append(({
                "scores": entry["scores"],
                "label": label,
            }))

        print(f"Generated {len(final_data)} positive/negative examples for {query_cve}")
        return final_data