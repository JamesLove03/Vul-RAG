import openai
import config as cfg


# Replace with your actual key or set it via environment variable
openai.api_key = cfg.openkey_openai_api_key
openai.api_base = cfg.openkey_openai_api_base

try:
    # List available models to test the key
    models = openai.models.list()
    print("✅ API key is working. Available models:")
    for model in models.data[:5]:  # show first 5 models
        print("-", model.id)
except openai.error.AuthenticationError as e:
    print("❌ Authentication failed. Check your API key.")
    print(e)
except Exception as e:
    print("⚠️ An unexpected error occurred.")
    print(e)