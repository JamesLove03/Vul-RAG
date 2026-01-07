#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import tiktoken
from haystack_integrations.document_stores.elasticsearch import ElasticsearchDocumentStore
from haystack_integrations.components.retrievers.elasticsearch import ElasticsearchEmbeddingRetriever
import pdb
#try:
from haystack_integrations.components.retrievers.elasticsearch import ElasticsearchBM25Retriever as ElasticsearchRetriever
#except:
    # In a higher version of farm-haystack, ElasticsearchRetriever does not exist
    #from haystack.nodes import BM25Retriever as ElasticsearchRetriever

from common.constant import PreSufConstant
from common.util.data_utils import DataUtils
from common.util.path_util import PathUtil
import common.config as cfg
import logging
import openai
from haystack import Document
import common.constant as constant
import uuid
logging.basicConfig(level=logging.DEBUG)
from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings()


class ESRetrieval:
    def __init__(self, index_name: str, custom_settings: bool = False):
        if cfg.DISABLE_ES_LOGGING:
            logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

        self.index = f'{PreSufConstant.DB_NAME_PREFIX_ES.value}{index_name}{PreSufConstant.DB_INDEX_SUFFIX.value}'
        self.cwe = None

        if custom_settings:
            es = Elasticsearch(
                hosts=[f"http://{cfg.ES_CONFIG['host']}:{cfg.ES_CONFIG['port']}"]
            )
            if not es.indices.exists(index = self.index):
                es.indices.create(index = self.index)
            es.indices.put_settings(index = self.index, body = cfg.ES_SETTINGS)

        self.doc_store: ElasticsearchDocumentStore = ElasticsearchDocumentStore(
            hosts=[f"http://{cfg.ES_CONFIG['host']}:{cfg.ES_CONFIG['port']}"],
            verify_certs = False,
            index = self.index,
            timeout=120,
        )

        self.retriever: ElasticsearchRetriever = ElasticsearchRetriever(
            document_store = self.doc_store
        )
        self.embed_retriever: ElasticsearchEmbeddingRetriever = ElasticsearchEmbeddingRetriever(
            document_store = self.doc_store
        )

    def truncate_to_limit(self, text, max_tokens=8192, model="text-embedding-3-small"):
        encoding = tiktoken.encoding_for_model(model)
        tokens = encoding.encode(text)
        truncated = tokens[:max_tokens]
        return encoding.decode(truncated)

    def generate_embedding(self, documents):
        openai.api_key = cfg.openkey_openai_api_key
        try:
            inputs = []
            for doc in documents:    
                #get the content from the documents json file
                truncated = self.truncate_to_limit(doc["content"])
                inputs.append(truncated)
            #create our embedding
            try:    
                response = openai.embeddings.create( 
                    input= inputs,
                    model="text-embedding-3-small"
                )
            except Exception as e:
                print(f"Failed to embed document: {e}")
            #return the embedding to the json file
            for doc, response in zip(documents, response.data):
                doc["embedding"] = response.embedding
        except Exception as e:
            print("problem is in generate embedding")    
        #return to the write function
        return documents

    def write_document(self, documents, cwe_name, document_name, batch_size = 512):
        try:
            self.index = constant.ES_INDEX_NAME_TEMPLATE.format(
                        lower_cwe_id = cwe_name.lower(), 
                        lower_document_name = document_name.lower()
                    )

            keywords = ["gpt_purpose", "code_before_change", "gpt_function"]
            
            if any(keyword in self.index for keyword in keywords):
                documents = self.generate_embedding(documents = documents)

            for doc in documents:
                if "id" not in doc or not doc["id"]:
                    doc["id"] = str(doc["true_id"])

            documents = [Document(**doc) for doc in documents]

            start_time = time.time()
            
            keyword_to_key = {
                "preconditions_for_vulnerability": 0,
                "trigger_condition": 1,
                "specific_code_behavior_causing_vulnerability": 2,
                "solution": 3,
                "gpt_purpose": 4,
                "gpt_function": 5,
                "code_before_change": 6,
                "code_after_change": 7,
            }
            key = next((v for k, v in keyword_to_key.items() if k in document_name.lower()), None)

            if key is not None:
                if key == 0:
                    print("adding to preconditions")
                    self.ds_preconditions_for_vulnerability.write_documents(
                        documents = documents,
                    )
                elif key == 1:
                    print("adding to trigger")
                    self.ds_trigger_condition.write_documents(
                        documents = documents,
                    )
                elif key == 2:
                    print("adding to code bahvior")
                    self.ds_specific_code_behavior_causing_vulnerability.write_documents(
                        documents = documents,
                    )
                elif key == 3:
                    print("adding to solution")
                    self.ds_solution.write_documents(
                        documents = documents,
                    )
                elif key == 4:
                    print("adding to purpose")
                    self.ds_gpt_purpose.write_documents(
                        documents = documents,
                    )
                elif key == 5:
                    print("adding to function")
                    self.ds_gpt_function.write_documents(
                        documents = documents,
                    )
                elif key == 6:
                    print("adding to code before")
                    self.ds_code_before_change.write_documents(
                        documents = documents,
                    )
                elif key == 7:
                    print("adding to code after")
                    self.ds_code_after_change.write_documents(
                        documents = documents,
                    )

            # self.document_store.write_documents(
            #     documents = documents,
            #     index = self.index,
            #     batch_size = batch_size,
            #     duplicate_documents = 'skip'
            # )
            end_time = time.time()
            logging.info("Write documents finish in %f s." % (end_time - start_time))
        
        except Exception as e:
            logging.error(f"Error: {e}")

    def __format_retrieved_answers(self, answers):
        formatted_answer_list = []
        for answer in answers:
                formatted_answer_list.append({
                    "content": answer.content,
                    "cve_id": answer.meta["cve_id"],
                    "score": answer.score
                })
        return formatted_answer_list
    
    def format(self, answers):
        
        formatted_answer_dict = {}
        for answer in answers["documents"]:
            formatted_answer_dict[answer.id] = {
                "cve_id": answer.meta["cve_id"],
                "score": answer.score,
                "id": answer.id
            }
        return formatted_answer_dict

    def search_embed_cve(self, query, idx, filteridx, cve_id, top_k=10):
#Searches for results with a matching cve
        logging.disable(logging.CRITICAL)

        if filteridx == 0: #Search for specific CVE-ID for training
            filters = {
            "operator": "AND",
            "conditions": [
                    {
                        "field": "cve_id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }   
        elif filteridx == 1: #Search for specifically NOT a CVE-ID for training
            filters = {
                "operator": "NOT",
                "conditions": [
                    {
                        "field": "cve_id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }
            top_k = 1
        elif filteridx == 2: #General search for detection
            filters = {}
        elif filteridx == 3: #Search for a specific ID for filling in blanks
            filters = {
            "operator": "AND",
            "conditions": [
                    {
                        "field": "id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }
        else:
            print("Invalid filteridx")

        answers = self.embed_retriever.run(
            query_embedding=query,
            filters = filters,
            top_k=top_k,
        )     

        if answers is None or len(answers["documents"]) == 0:
            return None  
        
        return self.format(answers)

    def search_cve(self, query, idx, filteridx, cve_id, top_k=10):
        #Searches for results with a matching cve
        logging.disable(logging.CRITICAL)

        if filteridx == 0: #Search for specific CVE-ID for training
            filters = {
            "operator": "AND",
            "conditions": [
                    {
                        "field": "cve_id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }   
        elif filteridx == 1: #Search for specifically NOT a CVE-ID for training
            filters = {
                "operator": "NOT",
                "conditions": [
                    {
                        "field": "cve_id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }
            top_k = 1
        elif filteridx == 2: #General search for detection
            filters = {}
        elif filteridx == 3: #Search for a specific ID for filling in blanks
            filters = {
            "operator": "AND",
            "conditions": [
                    {
                        "field": "id",
                        "operator": "in",
                        "value": [cve_id],
                    }
                ]
            }
        else:
            print("Invalid filteridx")
          
        answers = self.retriever.run(
            query=query,
            filters = filters,
            top_k=top_k,
        )
    
        #check for nonexistant matches (ie in test set and not training set)
        if answers is None or len(answers["documents"]) == 0:
            return None

        return self.format(answers)

    def search(self, query, retrieve_top_k = 10):
        """
        Searches for the given query in the specified index and retrieves the top-k results.

        Args:
            query (str): The search query string.
            retrieve_top_k (int, optional): The number of top results to retrieve. Defaults to 10.

        Returns:
            list: A list of formatted retrieved answers. Each answer in the list is a dictionary 
                  containing the following attributes:
                  - 'content' (str): The retrieved document text.
                  - 'cve_id' (str): The CVE ID of the document.
        """
        answers = self.retriever.retrieve(
            query = query, 
            top_k = retrieve_top_k, 
            index = self.index
        )
        return self.__format_retrieved_answers(answers)

class LLM4DetectionRetrieval(ESRetrieval):
    def __init__(self, index_name: str, document_name: str):
        super().__init__(index_name, custom_settings = cfg.ES_USE_CUSTOM_SETTINGS)
        self.retrieval_id = 1
        self.document_name = document_name

    def load_knowledge_documents(self, knowledge_file: str = None):
        if not knowledge_file:
            return []

        vul_knowledge_map = DataUtils.load_json(knowledge_file)
        knowledge_documents = []
        for _, knowledge_list in vul_knowledge_map.items():
            for vul_knowledge_item in knowledge_list:
                try:
                    knowledge_documents.append({
                        "id": str(vul_knowledge_item["true_id"]),
                        "content": vul_knowledge_item[self.document_name],
                        "meta": {
                            "cve_id": vul_knowledge_item['CVE_id']
                        }
                    })
                except Exception as e:
                    logging.error(f"Error: {e}")
        return knowledge_documents


    def update_new_documents(self, doc_path, cwe_name, document_name, documents = None):
        if not documents:
            documents = self.load_knowledge_documents(knowledge_file = doc_path)
        if not documents:
            logging.info(f'No documents to update')
            return
        self.write_document(documents, cwe_name=cwe_name, document_name=document_name)


def test_es_retrieval(self):

    self.cbc_retriever.run() 

    filters = {
            "operator": "AND",
            "conditions": [
                    {
                        "field": "cve_id",
                        "operator": "in",
                        "value": [cve_id],
                    }
             ]
        }
    
    

if __name__ == '__main__':
    test_es_retrieval()

