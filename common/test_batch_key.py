import config as cfg
from model_manager import ModelManager
from pathlib import Path
import json
import pdb
import traceback
import constant

try:
    
    model = ModelManager.get_model_instance("claude-haiku-4-5-20251001")

    message1 = model.get_messages("recite a poem for me", "You are a beautiful poet")
    message2 = model.get_messages("recite a sad poem for me", "You are a beautiful poet")
    message3 = model.get_messages("recite a happy poem for me", "You are a beautiful poet")
    
    messages = [message1, message2, message3]
    current_dir = Path(__file__).parent / "input.jsonl"
    output_dir = Path(__file__).parent / "processed_output.jsonl"
    id_nums = [0, 1, 2]

    model.create_batch_file(messages, current_dir, id_nums)

    file = model.upload_file(str(current_dir))

    inputtok, outputtok = model.run_batch(file, str(output_dir))

    print(f"Input tokens: {inputtok}, Outpot tokens: {outputtok}")

except Exception as e:
    traceback.print_exc()
    raise