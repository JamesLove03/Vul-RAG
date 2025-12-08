import os
import json
import sys
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common import constant
from pathlib import Path
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from components.knowledge_extractor import KnowledgeExtractor


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
        default = "Pairvul",
        help = 'which benchmark to test on',
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

    args = parser.parse_args()

    return args


def enrich_test(benchmark, model):

    #load from partial/{benchmark}/3_enhanced_data/test_set
    cwe_list = get_cwes(benchmark)

    KnowledgeE = KnowledgeExtractor(model_name = args.model, V2=True)

    for cwe in cwe_list:

        KnowledgeE.extract_knowledge_from_cwe(
                CWE_name = cwe,
                extract_only_once = True,
                resume = True,
                model_settings_dict = None
            )
            
    #create the prompts and make a list of prompts & id numbers

    #call the a-sync openai system with gpt-3-turbo

    #parse out the data

    #save the data in a json object in partial/{benchmark}/3_enhanced_data

    return 0

def load_elastic(benchmark):

    #import the load function
    
    #iterate through just like in ChatGPT_Extraction.py


    return 0



def search(benchmark):

    return 0


def rerank(benchmark):

    return 0


def decision(benchmark):

    return 0


if __name__ == '__main__':

    args = parse_command_line_arguments()

    if args.action == None:
        raise Exception("Forgot to put an action into this")
    

    if args.action == 'enrich_test':
        enrich_test(args.benchmark, args.model)

    elif args.action == 'search':
        search(args.benchmark)

    elif args.action == 'rerank':
        rerank(args.benchmark)

    elif args.action == 'decision':
        decision(args.benchmark, args.model)

    else:
        raise Exception("There is an incorrect action verb here")