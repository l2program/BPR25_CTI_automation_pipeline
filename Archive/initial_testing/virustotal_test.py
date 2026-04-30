import os
import vt
from dotenv import load_dotenv
load_dotenv()


API_KEY = os.getenv("vt_api_key")



if not API_KEY:
    raise RuntimeError("vt_api_key not found")


client = vt.Client(API_KEY)

try:
    file = client.get_object("/ip_addresses/")
    print("IP:", file.md5)


   