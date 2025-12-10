import config as cfg
import openai
import logging
import json
import time
from util.common_util import fill_template
from google import genai
from google.genai import types
try:
    from anthropic import Anthropic
except:
    logging.warning("Anthropic package is not installed. Please install it to use Claude model.")
import os

class BaseModel:
    def __init__(self, model_name, base_url, api_key = None):
        self.__base_url = base_url
        self.__model_name = model_name
        self.__api_key = api_key
        self.__client = None
        # if api_key:
        #     try:
        #         self.__client = openai.OpenAI(api_key = api_key, base_url = base_url)
        #     except:
        #         # Lower version of openai package does not support openai.OpenAI
        #         openai.api_key = api_key
        #         openai.api_base = base_url
        #         logging.warning("Outdated openai package. Use the Module-level global client instead.")

    def _set_client(self, client):
        self.__client = client

    def get_client(self):
        return self.__client
    
    def get_api_key(self):
        return self.__api_key
    
    def get_base_url(self):
        return self.__base_url

    @staticmethod
    def get_messages(user_prompt: str, sys_prompt: str = None) -> list:
        if sys_prompt:
            messages = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt}
            ]
        else:
            messages = [{"role": "user", "content": user_prompt}]
        return messages

    def get_response_with_messages(self, messages: list, **kwargs) -> str:
        logging.disable(logging.INFO)
        response_content = None
        input_tokens = 0
        output_tokens = 0

        try:
            if self.__client:
                response = self.__client.chat.completions.create(
                    model = self.__model_name,
                    messages = messages,
                    stream = False,
                    **kwargs
                )
                if response.usage:
                    input_tokens = response.usage.prompt_tokens
                    output_tokens = response.usage.completion_tokens

                response_content = response.choices[0].message.content
            else:
                # use the module-level global client
                openai.api_key = self.__api_key
                openai.api_base = self.__base_url
                response = openai.ChatCompletion.create(
                    model = self.__model_name,
                    messages = messages,
                    **kwargs
                )
                if response.usage:
                    input_tokens = response.usage.prompt_tokens
                    output_tokens = response.usage.completion_tokens

                response_content = response.choices[0]["message"]["content"]
        except Exception as e:
            logging.error(f"Error while calling {self.__model_name} API: {e}")
        logging.disable(logging.NOTSET)
        return response_content, input_tokens, output_tokens
    
    def get_model_name(self):
        return self.__model_name

    def set_proxy(self, proxy: str = cfg.OPENAI_API_CONNECTION_PROXY):
        if "http_proxy" not in os.environ:
            os.environ["http_proxy"] = proxy
        if "https_proxy" not in os.environ:
            os.environ["https_proxy"] = proxy

    def unset_proxy(self):
        if "http_proxy" in os.environ:
            del os.environ["http_proxy"]
        if "https_proxy" in os.environ:
            del os.environ["https_proxy"]

    def create_batch_file(self, messages, output_path, id_nums):
        #create the jsonl batch file in the output_dir
        custom_id = 0
        batch = []
        
        for message in messages:
            batch.append(fill_template(self.__model_name, message, id_nums[custom_id]))
            custom_id +=1
        
        with open(output_path, "w") as f:
            for obj in batch:
                f.write(json.dumps(obj) + "\n")

        

class DeepSeekModel(BaseModel):
    def __init__(self, model_name):
        super().__init__(
            model_name = model_name,
            base_url = cfg.deepseek_api_base,
            api_key = cfg.deepseek_api_key
        )

class GPTModel(BaseModel):
    def __init__(self, model_name):
        super().__init__(
            model_name = model_name,
            base_url = cfg.openkey_openai_api_base,
            api_key = cfg.openkey_openai_api_key
        )
        self._set_client(openai.OpenAI(api_key = self.get_api_key(), base_url = self.get_base_url()))


    def upload_file(self, filepath):
        client = self.get_client()

        batch_input_file = client.files.create(
            file=open(filepath, "rb"),
            purpose="batch"
        )
        return batch_input_file
    
    def run_batch(self, inputfile, output_path):
        client = self.get_client()
        
        batch = client.batches.create(
            input_file_id= inputfile.id,
            endpoint="/v1/chat/completions",
            completion_window="24h",
            metadata={
                "description": "test upload"
            }
        )
        
        while(batch.status != "completed"):
            if batch.status == "failed":
                raise Exception(f"Batch Job Failed: {batch.errors}")
            time.sleep(60)
            batch = client.batches.retrieve(batch.id)            
        
        file_response = client.files.content(batch.output_file_id)

        with open(output_path, "w") as f:
            f.write(file_response.read().decode("utf-8"))

        data = json.loads(batch)
        return data["usage"]["input_tokens"], data["usage"]["output_tokens"]


class QwenModel(BaseModel):
    def __init__(self, model_name):
        super().__init__(
            model_name = model_name,
            base_url = cfg.qwen_api_base,
            api_key = cfg.qwen_api_key
        )


class GeminiModel(BaseModel): 
    def __init__(self, model_name):
        super().__init__(
            model_name = model_name,
            base_url = cfg.gemini_api_base,
            api_key = cfg.gemini_api_key
        )
        self._set_client(genai.Client(api_key = self.get_api_key()))

    def upload_file(self, filepath): #uploads a jsonl file to the API 
        client = self.get_client()
        
        batch_input_file = client.files.upload(
            file=filepath,
            config=types.UploadFileConfig(display_name=f'{filepath}/output!', mime_type='jsonl')
        )
        return batch_input_file
    
    def run_batch(self, inputfile, output_path): #runs the batch and writes the output. Also returns the Input and Output Tokens 
        model_name = self.get_model_name()
        client = self.get_client()

        batch = client.batches.create(
            model = model_name,
            src= inputfile.name
            )
        
        while(batch.state.name != "JOB_STATE_SUCCEEDED"):
            if batch.state.name == "JOB_STATE_FAILED":
                raise Exception(f"Batch Job Failed: {batch.error}")
            time.sleep(60)
            batch = client.batches.get(name=batch.name)            
            print(batch)
        
        file_content_bytes = client.files.download(batch.dest.file_name)
        file_content = file_content_bytes.decode('utf-8')

        with open(output_path, "w") as f:
            f.write(file_content)

        return 

        
class ClaudeModel(BaseModel):
    def __init__(self, model_name):
        super().__init__(
            model_name = model_name,
            base_url = cfg.claude_api_base,
            api_key = cfg.claude_api_key
        )
        self._set_client = Anthropic(api_key = cfg.claude_api_key, base_url = cfg.claude_api_base)
        self.__sys_prompt = None
    
    def get_messages(self, user_prompt: str, sys_prompt: str = None) -> list:
        messages = [{"role": "user", "content": user_prompt}]
        self.__sys_prompt = sys_prompt
        return messages

    def get_response_with_messages(self, messages: list, **kwargs) -> str:
        logging.disable(logging.INFO)
        try:
            max_tokens = kwargs.pop("max_tokens", cfg.CLAUDE_DEFAULT_MAX_TOKENS)
            # system prompt in kwargs will override the default system prompt
            sys_prompt = kwargs.pop("system", self.__sys_prompt)
            response = self._client.messages.create(
                model = self.get_model_name(),
                messages = messages,
                max_tokens = max_tokens,
                system = sys_prompt,
                **kwargs
            )
            logging.disable(logging.NOTSET)
            return response.content[0].text
        except Exception as e:
            logging.error(f"Error while calling {self.get_model_name()} API: {e}")
            logging.disable(logging.NOTSET)
            return None

class ModelManager:
    __models = {
        "qwen": QwenModel,
        "deepseek": DeepSeekModel,
        "gpt": GPTModel,
        "claude": ClaudeModel, 
    }

    __instances_cache = {}

    @classmethod
    def get_model_instance(cls, model_name: str) -> BaseModel:
        model_name_kw = ""
        if "qwen" in model_name.lower():
            model_name_kw = "qwen"
        elif "deepseek" in model_name.lower():
            model_name_kw = "deepseek"
        elif "gpt" in model_name.lower():
            model_name_kw = "gpt"
        elif "claude" in model_name.lower():  
            model_name_kw = "claude"
        
        if model_name_kw not in cls.__models:
            raise ValueError("Unsupported model name")

        if model_name not in cls.__instances_cache:
            model_class = cls.__models.get(model_name_kw, None)
            if not model_class:
                raise ValueError("Unsupported model name")
            cls.__instances_cache[model_name] = model_class(model_name)
        model_instance = cls.__instances_cache[model_name]
        return model_instance