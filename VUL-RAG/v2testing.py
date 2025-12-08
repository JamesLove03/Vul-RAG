import os
import sys
import argparse
from common import constant


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

    args = parser.parse_args()

    return args


def enrich_test(benchmark):

    #load from partial/{benchmark}/3_enhanced_data/test_set

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
        enrich_test(args.benchmark)

    elif args.action == 'search':
        search(args.benchmark)

    elif args.action == 'rerank':
        rerank(args.benchmark)

    elif args.action == 'decision':
        decision(args.benchmark)

    else:
        raise Exception("There is an incorrect action verb here")