from common.util.data_utils import DataUtils
import common.config as cfg
import logging
from .es_retrival import LLM4DetectionRetrieval
from common.util import common_util
from common import constant
from common.constant import KnowledgeDocumentName as kdn
from common.model_manager import ModelManager
from common import common_prompt
import pdb
import logging
import json
import openai
import tiktoken
from elasticsearch import Elasticsearch
from .learned_reranker import LearnedReranker
import numpy as np

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
                pdb.set_trace()

        cve_id_dict = sorted(cve_id_dict.items(), key = lambda x: x[1], reverse = False)

        final_result = []
        for item in cve_id_dict:
            id_info = {}
            id_info["cve_id"] = item[0]
            id_info["count"] = item[1]
            final_result.append(id_info)

        return final_result

    def format_embed_answer(self, purpose_bm25, function_bm25, code_bm25, purpose_embed, function_embed, code_embed):
        #This function will handle the formatting of the code in a similiar way to the original format_retrieved_answer, but will call a different rerank function
        purpose_list = []
        purpose_dict = {}
        function_list = []
        function_dict = {}
        code_list = []
        code_dict = {}
        purpose_E_list = []
        purpose_E_dict = {}
        function_E_list = []
        function_E_dict = {}
        code_E_list = []
        code_E_dict = {}

        for item in purpose_bm25:
            purpose_list.append(item["cve_id"])
            purpose_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) } #add score to the dictionary
        for item in function_bm25:
            function_list.append(item["cve_id"])
            function_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) }
        for item in code_bm25:
            code_list.append(item["cve_id"])
            code_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) }
        for item in purpose_embed:
            purpose_E_list.append(item["cve_id"])
            purpose_E_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) }
        for item in function_embed:
            function_E_list.append(item["cve_id"])
            function_E_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) }
        for item in code_embed:
            code_E_list.append(item["cve_id"])
            code_E_dict[item["cve_id"]] = {"content": item["content"], "score": item.get("score",0) }

        reranker = LearnedReranker("model.txt")

        cve_id_list = function_list + purpose_list + code_list + purpose_E_list + function_E_list + code_E_list
        cve_id_list = list(set(cve_id_list)) #deleted any duplicates

        indexed_data = {}
        for idx, cve in enumerate(cve_id_list):
            input_vector = [
                purpose_dict.get(cve, {}).get("score", 0),
                function_dict.get(cve, {}).get("score", 0),
                code_dict.get(cve, {}).get("score", 0),
                purpose_E_dict.get(cve, {}).get("score", 0),
                function_E_dict.get(cve, {}).get("score", 0),
                code_E_dict.get(cve, {}).get("score", 0),
            ]
            indexed_data[idx] = {
                "cve_id": cve,
                "input_vector": input_vector,
                "score": 0  # Placeholder for prediction score
            }
        
        rerank_result = reranker.rerank(indexed_data)

        knowledge_list = []

        for item in rerank_result:
            try:
                cve_knowledge = self.vul_knowledge[item["cve_id"]]
                for knowledge_item in cve_knowledge:
                    if (item["cve_id"] in purpose_dict.keys() and 
                        purpose_dict[item["cve_id"]] == knowledge_item[kdn.PURPOSE.value]) \
                    or (item["cve_id"] in function_dict.keys() and 
                        function_dict[item["cve_id"]] == knowledge_item[kdn.FUNCTION.value]) \
                    or (item["cve_id"] in code_dict.keys() and 
                        code_dict[item["cve_id"]] == knowledge_item[kdn.CODE_BEFORE.value]):

                        knowledge_list.append({
                            "cve_id": knowledge_item.get(kdn.CVE_ID.value), 
                            "vulnerability_behavior": 
                            {
                                kdn.PRECONDITIONS.value: knowledge_item.get(kdn.PRECONDITIONS.value),
                                kdn.TRIGGER.value: knowledge_item.get(kdn.TRIGGER.value), 
                                kdn.CODE_BEHAVIOR.value: knowledge_item.get(kdn.CODE_BEHAVIOR.value)
                            }, 
                            "solution_behavior": knowledge_item.get(kdn.SOLUTION.value),
                        })
                        break

            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Error cve_id: {item['cve_id']}")
        
        return knowledge_list


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
        truncated = tokens[:max_tokens]
        return encoding.decode(truncated)
    
    def embedder(self, query):
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

    def retrieve_knowledge(self, cwe_name, code_snippet, purpose, function, top_N):
        logging.disable(logging.INFO)
        #declare elasticsearch item for the embedding search
        es = Elasticsearch([{"host": "localhost", "port": 9201}])

        purpose_query = purpose
        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.PURPOSE.value.lower()
        ), kdn.PURPOSE.value.lower())
        purpose_answer = es_retrieval.search(query = purpose_query, retrieve_top_k = top_N)

        #create embedding for purpose_answer
        purpose_embed = self.embedder(purpose_query)
        query_body = {
            "size": top_N,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": purpose_embed,
                        "k": top_N
                    }
                }
            }
        }
        purpose_embed = es.search(es_retrieval.index, body=query_body)
        purpose_emb_answer = self.format_embeddings(purpose_embed)

        function_query = function
        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.FUNCTION.value.lower()
        ), kdn.FUNCTION.value.lower())
        function_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)

        #create embedding for function_answer
        function_embed = self.embedder(function_query)
        query_body = {
            "size": top_N,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": function_embed,
                        "k": top_N
                    }
                }
            }
        }
        function_embed = es.search(es_retrieval.index, body=query_body)
        function_emb_answer = self.format_embeddings(function_embed)

        function_query = code_snippet
        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.CODE_BEFORE.value.lower()
        ), kdn.CODE_BEFORE.value.lower())
        try:
            code_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)
        except:
            code_answer = es_retrieval.search(query = function_query[:cfg.ES_SEARCH_MAX_TOKEN_LENGTH], retrieve_top_k = top_N)

        #create embedding for code_answer
        code_embed = self.embedder(function_query)
        query_body = {
            "size": top_N,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": code_embed,
                        "k": top_N
                    }
                }
            }
        }
        code_embed = es.search(es_retrieval.index, body=query_body)
        code_emb_answer = self.format_embeddings(code_embed)


        # enable logging info
        logging.disable(logging.NOTSET)

        return self.format_embed_answer(purpose_answer, function_answer, code_answer, purpose_emb_answer, function_emb_answer, code_emb_answer)

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

    def retrieve_similar_code(self, cwe_name, code_snippet, top_N):
        function_query = code_snippet
        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.CODE_BEFORE.value.lower()
        ), kdn.CODE_BEFORE.value.lower())
        try:
            code_before_change_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)
        except:
            code_before_change_answer = es_retrieval.search(
                query = function_query[:cfg.ES_SEARCH_MAX_TOKEN_LENGTH], 
                retrieve_top_k = top_N
            )

        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.CODE_AFTER.value.lower()
        ), kdn.CODE_AFTER.value.lower())
        try:
            code_after_change_answer = es_retrieval.search(query = function_query, retrieve_top_k = top_N)
        except:
            code_after_change_answer = es_retrieval.search(
                query = function_query[:cfg.ES_SEARCH_MAX_TOKEN_LENGTH], 
                retrieve_top_k = top_N
            )
        return self.format_retrieved_answer_by_code(code_before_change_answer, code_after_change_answer)

       
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

    def detection_pipeline(self, code_snippet, state, cwe_name, top_N, **kwargs):
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


        # retrieve knowledge
        vul_knowledge_list = self.retrieve_knowledge(cwe_name, code_snippet, purpose, function, top_N)
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
        for vul_knowledge in vul_knowledge_list[:min(cfg.MAX_RETRIEVE_KNOWLEDGE_NUM, len(vul_knowledge_list))]:
            counter += 1
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
            vul_output = self.model_instance.get_response_with_messages(
                vul_messages,
                **model_settings_dict
            )
            sol_output = self.model_instance.get_response_with_messages(
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
        

        #Perform BM25 search for matching CVEs (for purpose, function, and code)
        es_retrieval = LLM4DetectionRetrieval(constant.ES_INDEX_NAME_TEMPLATE.format(
            lower_cwe_id = cwe_name.lower(), 
            lower_document_name = kdn.PURPOSE.value.lower()
        ), kdn.PURPOSE.value.lower())
        
        print("This is whats being passed from", query_cve, purpose)
        #search with bm25 and then embeddings
        purpose_answer = es_retrieval.search_cve(query = purpose, idx = 2, cve_id=query_cve)
        #if the dictionary is empty we will be unable to use this example and move on
        if not purpose_answer:
            return
        purpose_embed = self.embedder(purpose)
        purpose_embed_answer = es_retrieval.search_embed_cve(query = purpose_embed, idx = 2, cve_id=query_cve)

        #function_answer = es_retrieval.search_cve()
        function_answer = es_retrieval.search_cve(query = purpose, idx = 1, cve_id=query_cve)        
        function_embed = self.embedder(function)
        function_embed_answer = es_retrieval.search_embed_cve(query = function_embed, idx = 1, cve_id=query_cve)        

        #code_answer = es_retrieval.search_cve()
        code_answer = es_retrieval.search_cve(query = code_snippet, idx = 0, cve_id=query_cve)   
        print("code snippet:", code_answer)
        code_embed = self.embedder(code_snippet)
        code_embed_answer = es_retrieval.search_embed_cve(query = code_embed, idx = 0, cve_id=query_cve)

        
        #iterate through results while combining into a list        
        data = {}
        raw = {}
        print(type(code_answer))
        print(code_answer)
        raw.update(code_answer)
        raw.update(code_embed_answer)
        raw.update(function_answer)
        raw.update(function_embed_answer)
        raw.update(purpose_answer)
        raw.update(purpose_embed_answer)
        
        print(str(len(raw)) + " <- should be a multiple of 6")
        print(type(raw))
        print(type(code_answer))
        for item in raw:
            print(type(item))
            data[item["id"]].append(item["score"])

        label = 1
        final_data = [[scores, label] for scores in data.values() if len(scores) == 6]        
        data.append({"scores": [], "label": []})

        #re-search for results that are similiar, but not accurate to mark as inaccurate results
        #search with bm25 and then embeddings
        purpose_answer = es_retrieval.search_cve(query = purpose, idx = 5, cve_id=query_cve)
        #if the dictionary is empty we will be unable to use this example and move on
        if not purpose_answer:
            return
        purpose_embed = self.embedder(purpose)
        purpose_embed_answer = es_retrieval.search_embed_cve(query = purpose_embed, idx = 5, cve_id=query_cve)

        #function_answer = es_retrieval.search_cve()
        function_answer = es_retrieval.search_cve(query = purpose, idx = 4, cve_id=query_cve)        
        function_embed = self.embedder(function)
        function_embed_answer = es_retrieval.search_embed_cve(query = function_embed, idx = 4, cve_id=query_cve)        

        #code_answer = es_retrieval.search_cve()
        code_answer = es_retrieval.search_cve(query = code_snippet, idx = 3, cve_id=query_cve)   
        code_embed = self.embedder(code_snippet)
        code_embed_answer = es_retrieval.search_embed_cve(query = code_embed, idx = 3, cve_id=query_cve)

        data = []
        raw = []

        raw.extend(code_answer + code_embed_answer + function_answer + function_embed_answer + purpose_answer + purpose_embed_answer)
        print(len(raw) + " <- should be a multiple of 6")

        for item in raw:
            data[item["id"]].append(item["score"])

        label = 0
        final_wrong_data = [[scores, label] for scores in data.values() if len(scores) == 6] 

        final_data.extend(final_wrong_data)
        
        print(final_data)
        return final_data