# My personal notes to help understand and run this code


benchmark/test: Contains json files with test sets that cover a specific CWE. Each json file contains cveid, unpatched and patched code, and a description. This is the test data that was randomly selected to test the effectiveness of our Vul-RAG model.

benchmark/train: Same as above except this data was used to train the model by building its knowledge database. 

common/model_manager.py: Creates a base model class, then has seperate classes for initializing a DeepSeek, GPT, Quen, and Claude model. Also contains get_model_instance which checks if the model is already in the cache or it will create one.

common/constant.py: Contians definitions of some variables that will be used to help the LLM understand what we are asking it and rate its knowledge on the subject.

common/config.py: Holds configs for elasticsearch and openai as well as others.

common/common_prompt.py: Holds the prompts that the LLMs will be prompted with. Includes baseline prompts; without explanation, with explanation, a cot prompt, an advanced cot prompt, a prompt with cwe provided. Also holds the extraction prompts; extract purpose and extract function for use on the test code. Also a function that builds the database of knowledge by extracting CVE postings into json files.

common/util/common_util.py: Has a bunch of functions that do things like parsing and lexing responses from the LLM. Also contains code to calculate all of our metrics based upon the logging that has been going on as we run the tests. As well as a function to clean up our json data and help create the test/train data.

common/util/data_utils.py: Contains functions to load/save json and load/save pickle files.

common/util/path_util.py: Sets a bunch of paths up to create the different directories where data will be stored.

dataset: holds the cleaned version of the data on linux kernel vulnerablities

images: holds images dummy

results/baseline_results: Holds a directory for each model {claude, GPT, qwen, deepseek}. Within these directories is a json file with the results of the tests including the final result and which type of prompt was used {basic, codeRAG, cot-1, cot-2, cwe-enhanced}.

results/vul-rag_results: Holds a directory for each model {claude, GPT, qwen, deepseek}. Within these directories is a json file with the results of the tests for each CWE. Includes all responses from the multiple steps in the vul-rag process and the final result.

user study: contains information about the user studies performed

VUL-RAG/ChatGPT_Extraction.py: Holds knowledge extractor which takes the responses from the LLMs and converts it into a json file using document_store.

VUL-RAG/LLM4Detection_baseline.py: Loads the test data and parses it. Then sends the prefix code and postfix code to the model to be judged. Writes the outputs into a json file {results}. Also calculates the metrics. This only does for the non-rag detection ie results/baseline

VUL-RAG/VulRAG_detection.py: Does the same as above except for the VulRAG process. Saves results to json and calculates metrics.

VUL-RAG/components/es_retrieval.py: Seems to hold all the functions used when looking up background information on a given problem with the LLM4 versions.

VUL-RAG/components/knowledge_extractor.py: Holds all of the functions to find background information for the Vul-RAG. Aka generates our library of knowledge.

VUL-RAG/components/VulRAG_detection.py: Is the engine that does the vulnerability checking by first generating the purpose and function of the given code snippet. Then it retrieves the knowledge relevant to the specific problem. Then for each knowledge entry it will generate a prompt (with that knowledge) to check if that specific entry is going to be found in the code snippet. It then writes all of the results to a json file again. 

vulnerability knowledge: Holds all the generated knowledge for the Vul-RAG process.




DEPENDENCIES NEEDED:
    
    External Modules: openai, anthropic, elasticsearch, urllib3, haystack
    
    API Keys: gpt-3.5 turbo 0125, GPT 4o, claude-3-5-sonnet, deepseek-reasoner, qwen-max
    
    Data Collection: CVEs collected from https://github.com/nluedtke/linux_kernel_cves. Data enriched from National Vulnerability Database with classifications and descriptions as well. Find patched and unpatched code from project links related to CVE-IDs. Data is checked for accuracy (not still vulnerable) by checking if further patches were done.
    
    Physical Requirements: None