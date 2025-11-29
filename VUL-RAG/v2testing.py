import os
import sys
import argparse


def parse_command_line_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--benchmark', 
        type = str, 
        default = "Pairvul",
        help = 'which benchmark to test on',
    )

    args = parser.parse_args()

    return args





def load_reranker(reranker):
    if reranker == 'Pairvul':

    elif reranker == 'TruePairvul':

    elif reranker == 'Missing_CWE':
    
    else:
        print("invalid reranker name")
        exit(1)

def load_benchmark(benchmark):
    if benchmark == 'Pairvul':

    elif benchmark == 'TruePairvul':

    else:
        print("invalid benchmark name")
        exit(1)

def v2_pipeline(benchmark):

    #load benchmark 
    load_benchmark(benchmark)
    #load benchmark reranker 
    load_reranker(benchmark)
    #run test with



    #load missing CWE reranker

    #run test with VulRAG+ settings

    return True




if __name__ == '__main__':

    args = parse_command_line_arguments()

    v2_pipeline(args.benchmark)