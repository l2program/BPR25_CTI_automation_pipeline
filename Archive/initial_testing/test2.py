import os
import vt
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("vt_api_key")
if not API_KEY:
    raise RuntimeError("vt_api_key not found")

ip = "1.1.1.1"

with vt.Client(API_KEY) as client:
    obj = client.get_object(f"/ip_addresses/{ip}")
    print("IP:", obj.id)
    print("Country:", getattr(obj, "country", None))
    print("ASN:", getattr(obj, "asn", None))
    print("AS owner:", getattr(obj, "as_owner", None))
    print("Last analysis stats:", getattr(obj, "last_analysis_stats", None))