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
import os




def train_model():
    X = [] #holds the lists of 6 ratings
    y = [] #holds 1/0 for correct or incorrect
    #Get CWE Item from test file
    CWE_list = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787", "CWE-20", "CWE-125", "CWE-200", "CWE-264", "CWE-401"]
    
    raw_list = []
    pos_reg_fin = 0
    neg_reg_fin = 0
    group = []
    already_ran = []
    if os.path.exists("used.json"):
        with open("used.json", "r", encoding='utf-8') as f:
            already_ran = json.load(f)
    if os.path.exists("final_data.json"):
        with open("final_data.json", 'r', encoding='utf-8') as f:
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
        test_clean_data_path = PathUtil.test_data(constant.TEST_DATA_FILE_NAME.format(cwe_id = cwe_id), "json")
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



            with open("final_data.json", "w") as f:
                json.dump(raw_list, f, indent=2)
            already_ran.append(cve_item["id"])
            with open("used.json", "w") as f:
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
        model.save_model(f"model_fold_{fold_idx}.txt")
        train_len = len(train_index)
        val_len = len(val_index)
        
        fold_result = {
            "fold": fold_idx,
            "train_size": train_len,
            "valid_size": val_len,
            "accuracy": acc,
        }
        results.append(fold_result)

    with open("kfold_results.json", "w") as f:
        json.dump(results, f, indent=4)
    
    return

def load_model():
    
    with open("final_data.json", "r") as f:
        raw_list = json.load(f)

    scores = [item["scores"] for item in raw_list]
    labels = [item["label"] for item in raw_list]
    group = [item["group_id"] for item in raw_list]


    X = np.array(scores)
    y = np.array(labels)

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
        model.save_model(f"model_fold_{fold_idx}.txt")
        train_len = len(train_index)
        val_len = len(val_index)
        
        fold_result = {
            "fold": fold_idx,
            "train_size": train_len,
            "valid_size": val_len,
            "accuracy": acc,
        }
        results.append(fold_result)

    with open("kfold_results.json", "w") as f:
        json.dump(results, f, indent=4)
    
    return

if __name__ == '__main__':
    load_model()
