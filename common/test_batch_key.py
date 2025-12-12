import openai
import config as cfg
import model_manager
from pathlib import Path
import json
import pdb
import asyncio

try:
    
    model = model_manager.GeminiModel("gemini-2.0-flash-lite")

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
    print("⚠️ An unexpected error occurred.")
    print(e)