import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score
from common.util import common_util
from common import constant
from components.VulRAG import VulRAGDetector
from common.constant import PreSufConstant
from common.util.data_utils import DataUtils
from common.util.path_util import PathUtil
import common.config as cfg
import logging
import openai
from tqdm import tqdm
import random
import json
import pdb
output_dir = os.path.join(os.path.dirname(__file__), '..', 'output', 'reranker_data')

used_path = os.path.join(output_dir, "used.json")
final_data_path = os.path.join(output_dir, "final_data.json")
kfold_results_path = os.path.join(output_dir, "kfold_results.json")

def train_model(benchmark):
    X = [] #holds the lists of 6 ratings
    y = [] #holds 1/0 for correct or incorrect
    #Get CWE Item from test file
    CWE_list = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787", "CWE-20", "CWE-125", "CWE-200", "CWE-264", "CWE-401"]
    
    raw_list = []
    pos_reg_fin = 0
    neg_reg_fin = 0
    group = []
    already_ran = []


    if os.path.exists(used_path):
        with open(used_path, "r", encoding='utf-8') as f:
            already_ran = json.load(f)
    if os.path.exists(final_data_path):
        with open(final_data_path, 'r', encoding='utf-8') as f:
            raw_list = json.load(f)
            group = [item["group_id"] for item in raw_list]

    #Iterate through each CVE
    for cwe_id in CWE_list:
        knowledge_path = PathUtil.knowledge_extraction_output(
            constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                model_name = cfg.DEFAULT_BEHAVIOR_SUMMARY_MODEL,
                cwe_id = cwe_id
            ), "json"
        )
        
        VulD = VulRAGDetector("gpt-4o", "gpt-4o", knowledge_path)
        VulD.update_retrievers(cwe_id)

        #test_clean_data_path = PathUtil.test_data(constant.TEST_DATA_FILE_NAME.format(cwe_id = cwe_id), "json")
        test_clean_data_path = PathUtil.reranker_test(constant.TEST_DATA_FILE_NAME.format(cwe_id = cwe_id), 'json', benchmark)
        test_clean_data = DataUtils.load_json(test_clean_data_path)
        cve_list = test_clean_data
        
        pos_reg = 0
        neg_reg = 0
        #Divide each CVE item item into vul and non-vul
        for cve_item in tqdm(cve_list):
            if cve_item["id"] in already_ran:
                continue
                
            vulresult = VulD.training_pipeline(
                    cve_item['code_before_change'],
                    "code_before_change",    
                    cwe_id,
                    10,
                    sample_id = cve_item['id'],
                    cve_id = cve_item['cve_id'],
                )
            nonvulresult = VulD.training_pipeline(
                cve_item['code_after_change'],
                    "code_after_change",    
                        cwe_id,
                        10,
                        sample_id = cve_item['id'],
                        cve_id = cve_item['cve_id'],
                    )
            
            if vulresult is not None:
                for entry in vulresult:
                    entry["group_id"] = cve_item["id"]
                raw_list.extend(vulresult)
            if nonvulresult is not None:
                for entry in nonvulresult:
                    entry["group_id"] = cve_item["id"]
                raw_list.extend(nonvulresult)

            for entry in vulresult:
                X.append(entry["scores"])
                y.append(int(entry["label"]))
                if entry["label"] == 0:
                    neg_reg += 1
                if entry["label"] == 1:
                    pos_reg += 1
                group.append(entry["group_id"])
            for entry in nonvulresult:
                X.append(entry["scores"])
                y.append(int(entry["label"]))
                if entry["label"] == 0:
                    neg_reg += 1
                if entry["label"] == 1:
                    pos_reg += 1
                group.append(entry["group_id"])

            with open(final_data_path, "w") as f:
                json.dump(raw_list, f, indent=2)
    
            already_ran.append(cve_item["id"])
            with open(used_path, "w") as f:
                json.dump(already_ran, f, indent=2)
            

            print(f"So far at {pos_reg} positive and {neg_reg} negative examples for {cwe_id}")

        pos_reg_fin += pos_reg
        neg_reg_fin += neg_reg
        
    print("Final Positive Count: ", pos_reg_fin)
    print("Final Negative Count: ", neg_reg_fin)
    #convert X list and y list to numpy arrays
    
    X = np.array(X)
    y = np.array(y)     

    #call lgb.train
    group_kf = GroupKFold(n_splits=5)
    fold_idx = 0

    #This code will create sample to group mapping
    sample_to_group = np.array(group)
    results = []
    for train_index, val_index in group_kf.split(X, y, groups = sample_to_group):
        fold_idx += 1
        #divide the data into folds
        X_train, X_val = X[train_index], X[val_index]
        y_train, y_val = y[train_index], y[val_index]
        
        train_groups, train_counts = np.unique(sample_to_group[train_index], return_counts=True)
        val_groups, val_counts = np.unique(sample_to_group[val_index], return_counts=True)

        train_group_sizes = train_counts.tolist()
        val_group_sizes = val_counts.tolist()
        

        #use Dataset wrapper
        train_data = lgb.Dataset(X_train, label=y_train, group=train_group_sizes)
        valid_data = lgb.Dataset(X_val, label=y_val, reference=train_data, group=val_group_sizes)
        #set params to be binary 1/0
        params = {
            'objective': 'lambdarank',
            'metric': 'ndcg',
            'ndcg_eval_at': [1, 3, 5],
            'learning_rate': 0.1,
            'num_leaves': 31,
            'min_data_in_leaf': 20,
            'verbose': -1
        }
        #train the model on data using one fold to 
        model = lgb.train(params, 
                      train_data, 
                      num_boost_round=100,
                      valid_sets=[valid_data],
                      callbacks=[lgb.early_stopping(stopping_rounds=10)],
                      )
        #output info about scoring across folds
        y_pred = model.predict(X_val)
        y_pred_labels = (y_pred > 0.5).astype(int)
        acc = accuracy_score(y_val, y_pred_labels)
        model.save_model(os.path.join(output_dir, (f"model_fold_{fold_idx}.txt")))     
        train_len = len(train_index)
        val_len = len(val_index)
        
        fold_result = {
            "fold": fold_idx,
            "train_size": train_len,
            "valid_size": val_len,
            "accuracy": acc,
        }
        results.append(fold_result)

    with open(kfold_results_path, "w") as f:
        f.write(json.dumps(results, indent=4)) 
        f.write(f"\n\nPositive: {pos_reg_fin}\nNegative: {neg_reg_fin}")
    
    return

def test_model():

    with open(final_data_path, "r") as f:
        raw_list = json.load(f)

    scores = [item["scores"] for item in raw_list]
    labels = [item["label"] for item in raw_list]
    group = [item["group_id"] for item in raw_list]

    X = np.array(scores)
    y = np.array(labels)
    sample_to_group = np.array(group)

    group_kf = GroupKFold(n_splits=5)

    # Keep track of the best average NDCG
    best_avg_ndcg = -np.inf
    best_params = None

    # Placeholder loops for parameter grid
    for learning_rate in [0.01, 0.03, 0.05, 0.1, 0.15, 0.2]:  # fill values later
        for num_leaves in [7, 15, 31, 63, 127]:  # fill values later
            for min_data_in_leaf in [5, 10, 20, 30, 50]:  # fill values later
                for stopping_rounds in [5, 10, 20]:
                    params = {
                        'objective': 'lambdarank',
                        'metric': 'ndcg',
                        'ndcg_eval_at': [1, 3, 5, 10],
                        'learning_rate': learning_rate,
                        'num_leaves': num_leaves,
                        'min_data_in_leaf': min_data_in_leaf,
                        'verbose': -1
                    }

                    # Store per-fold results temporarily
                    fold_results = []
                    fold_ndcgs = []
                    fold_idx = 0

                    for train_index, val_index in group_kf.split(X, y, groups=sample_to_group):
                        fold_idx += 1
                        # Split data
                        X_train, X_val = X[train_index], X[val_index]
                        y_train, y_val = y[train_index], y[val_index]

                        # Compute group sizes for LambdaRank
                        _, train_counts = np.unique(sample_to_group[train_index], return_counts=True)
                        _, val_counts = np.unique(sample_to_group[val_index], return_counts=True)
                        train_group_sizes = train_counts.tolist()
                        val_group_sizes = val_counts.tolist()

                        # Prepare LightGBM datasets
                        train_data = lgb.Dataset(X_train, label=y_train, group=train_group_sizes)
                        valid_data = lgb.Dataset(X_val, label=y_val, reference=train_data, group=val_group_sizes)

                        evals_result = {}
                        record_callback = lgb.record_evaluation(evals_result)
                        # Train the model with early stopping
                        model = lgb.train(
                            params,
                            train_data,
                            num_boost_round=500,
                            valid_sets=[valid_data],
                            callbacks=[lgb.early_stopping(stopping_rounds=stopping_rounds), record_callback]
                        )

                        # Predictions & accuracy
                        y_pred = model.predict(X_val)
                        y_pred_labels = (y_pred > 0.5).astype(int)
                        acc = accuracy_score(y_val, y_pred_labels)

                        # Capture NDCG at best iteration
                        ndcg_best = {}
                        if "valid_0" in evals_result:
                            for metric_name, values in evals_result["valid_0"].items():
                                # values is a list of metric per iteration
                                ndcg_best[metric_name] = values[model.best_iteration - 1]  # get best iteration

                        # Compute average NDCG for this fold
                        ndcg_values = list(ndcg_best.values())  # [0.8275, 0.7803, 0.7898, 0.8461]
                        fold_ndcg = float(np.mean(ndcg_values))  # average across @1,3,5,10
                        fold_ndcgs.append(fold_ndcg)

                        # Prepare fold result (not yet written)
                        fold_result = {
                            "fold": fold_idx,
                            "train_size": len(train_index),
                            "valid_size": len(val_index),
                            "accuracy": acc,
                            "best_iteration": model.best_iteration,
                            "best_score": model.best_score,
                            "ndcg_average_score": fold_ndcg,
                            "parameters": params,
                            "early_stopping": stopping_rounds
                        }

                        fold_results.append((fold_result, model))  # keep model reference for saving if best

                    # Compute average NDCG across folds
                    avg_ndcg_across_folds = np.mean(fold_ndcgs)

                    # Compare to previous best
                    if avg_ndcg_across_folds > best_avg_ndcg:
                        best_avg_ndcg = avg_ndcg_across_folds
                        best_params = params

                        # Save fold models and results only for best
                        for fold_result, model in fold_results:
                            fold_idx = fold_result["fold"]
                            model_path = os.path.join(output_dir, f"model_fold_{fold_idx}.txt")
                            model.save_model(model_path)

                        # Append new best folds
                        all_results = [fold_result for fold_result, _ in fold_results]

                        with open(kfold_results_path, "w") as f:
                            json.dump(all_results, f, indent=4)

    return best_avg_ndcg, best_params


if __name__ == '__main__':
    test_model()
