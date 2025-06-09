#please dont forget to put this directory in the gitignore tomorrow.
#Add the following line to the gitignore
#common/api-keys/
#also run this command
#git rm --cached common/api-keys/*
#keys to look for specifically

#openai: gpt-3.5-turbo-0125 AND GPT-4

#focus only on using 3.5 turbo for library gen and GPT-4 for diagnosing.

import pickle
from pathlib import Path

openai_key = ""

#write all of the keys
with open(openkey_openai_api_key.pkl, "wb") as f:
    pickle.dump(openai_key, f)


#read all the keys to make sure
with open(openkey_openai_api_key.pkl, "rb") as f:
    print(pickle.load(f))
