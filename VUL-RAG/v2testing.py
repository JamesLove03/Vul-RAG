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

    parser.add_argument(
        '--action',
        type = str,
        default = None,
        help = "Should be one of the following actions: enrich_test, search, rerank, decision"
    )

    args = parser.parse_args()

    return args


def enrich_test(benchmark):

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