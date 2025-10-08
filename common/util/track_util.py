import json
import os
import time
from datetime import datetime
from common import constant
from typing import Dict, Any, Optional, List
import statistics


SubItem = Dict[str, Any]

class Tracker:

    def __init__(self, filepath: str):
        """
        This will initialize the file tracker file and folder
        This will be run in VulRAG_detection.py 
        One folder and file will be created for each full test
        """
        log_dir = os.path.join(filepath, constant.LOG_DIR_NAME)
        self.raw_filepath = os.path.join(log_dir, constant.LOG_FILE_NAME, '.jsonl')
        self.final_path = os.path.join(log_dir, constant.LOG_FINAL_NAME, '.json')

        self._ensure_directory_exists(log_dir)

        if os.path.exists(self.filepath):
            try:
                with open(self.final_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                self.start_time = data.get("start_time", datetime.now().isoformat)

            except (IOError, json.JSONDecodeError) as e:
                # If file exists but is corrupt, start a new session
                print(f"Error loading existing log file ({self.filepath}): {e}. Starting a new session.")
        else:
            self.start_time = datetime.now().isoformat
            self.sub_items: List[SubItem] = []

        print("RunTracker Initialized to {self.filepath}")


    def _ensure_directory_exists(self, directory: str):
        """Checks if the directory for the log file exists and creates it if not."""
        if directory and not os.path.exists(directory):
            try:
                # Use os.makedirs with exist_ok=True just in case, though the check above handles it
                os.makedirs(directory, exist_ok=True)
                print(f"Created log directory: {directory}")
            except OSError as e:
                print(f"Error creating directory {directory}: {e}")


    def log(self, type, runtime: float, input_tok: int = 0, output_tok: int = 0):

        log_entry = {
            "type" : type,
            "runtime" : runtime,
            "input_tokens" : input_tok,
            "output_tokens" : output_tok
        }

        try:
            # Use 'a' mode (append) and write each JSON object followed by a newline
            with open(self.raw_filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except IOError as e:
            print(f"Error writing to raw log file {self.raw_filepath}: {e}")

    def create_final(self, final_time):

        start_dt = datetime.fromisoformat(self.start_time)
        final_dt = datetime.fromisoformat(final_time)

        sub_items: List[SubItem] = []
        
        # 1. READ ALL RAW DATA FROM JSON LINES FILE
        try:
            with open(self.raw_filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            sub_items.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"Skipping malformed line in raw log: {line.strip()}. Error: {e}")
        except IOError:
            # File doesn't exist or cannot be read
            print(f"Warning: Raw log file not found or empty at {self.raw_filepath}. Cannot create summary.")
            return

        if not sub_items:
            print("Warning: Raw log file was empty. Final file will contain only start/end times.")

        queries = [item for item in sub_items if item['type'] == 'query']
        retrievals = [item for item in sub_items if item['type'] == 'retrieval']

        all_runtimes = [float(item['runtime']) for item in sub_items]
        query_runtimes = [float(item['runtime']) for item in queries]
        retrieval_runtimes = [float(item['runtime']) for item in retrievals]

        total_input_tokens = sum(item['input_tokens'] for item in queries)
        total_output_tokens = sum(item['output_tokens'] for item in queries)

        avg_query_time_ms = statistics.mean(query_runtimes) if query_runtimes else 0.0
        avg_retrieval_time_ms = statistics.mean(retrieval_runtimes) if retrieval_runtimes else 0.0

        output = {
            "start_time": self.start_time,
            "end_time": final_time,
            "total_runtime": (final_dt - start_dt),
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "avg_query_time": avg_query_time_ms,
            "avg_retrieval_time": avg_retrieval_time_ms,
            "num_queries": len(queries),
            "num_retrievals": len(retrievals),
        }

        try:
            with open(self.final_path, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=4) 
            print(f"\n✅ Final metrics calculated and saved successfully to summary file: {self.summary_filepath}")
        except IOError as e:
            print(f"\n❌ Error writing final summary log file {self.summary_filepath}: {e}")