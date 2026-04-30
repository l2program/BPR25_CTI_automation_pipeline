import os
import vt #import requests VT instead?
#import pandas as pd
from dotenv import load_dotenv
load_dotenv()

# obsidian vault path

#authentication must include x-apikey apikey

#C:\Users\WindowsHawk\Documents\Obsidian_BPR\CTI-Test\VirusTotal Test.md

API_KEY = os.getenv("vt_api_key")

if not API_KEY:
    raise RuntimeError("vt_api_key not found")


client = vt.Client(API_KEY)

try:
    file = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")
    print("MD5:", file.md5)
    print("SHA256:", file.sha256)
    print("Malicious:", file.last_analysis_stats["malicious"])
    print("Size:", file.size)
    print("Tag:", file.type_tag)

    comments = client.iterator("/files/44d88612fea8a8f36de82e1278abb02f/comments")
    for x, comment in enumerate(comments):
        if x == 20:
            break
        print(comment.text)
    comment_test = next(client.iterator("/files/44d88612fea8a8f36de82e1278abb02f/comments"))
    print(comment_test.to_dict())
finally:
    client.close()
