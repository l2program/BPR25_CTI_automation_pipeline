import os, json
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
#load environment variables from .env
load_dotenv()


API_KEY = os.getenv("urlhaus_api_key")
if not API_KEY:
    raise RuntimeError("urlhaus_api_key not found")

#limit entries to 200 in the url path, max is 1000
limit = 200
url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"

#HTTP request
r = requests.get(url, headers={"Auth-Key": API_KEY}, timeout=30)

#possible error types 
r.raise_for_status()

#parse JSON response into a py dictionary
raw = r.json()

#test internal status
query_status = raw.get("query_status")
if query_status != "ok":
    raise RuntimeError(f"Urlhaus query status={query_status}!r")

print("query_status:", query_status)
urls = raw.get("urls", [])
print("entries:", len(urls))

#attempting to add temporal traceability
now = datetime.now(timezone.utc)
day = now.date().isoformat()
timestamp = now.strftime("%H%M%S")
fetched_at = now.strftime("%Y-%m-%d%T%H:%M:%SZ")

data_dir = Path(os.getenv("DATA_DIR", "./data"))
output_dir = data_dir / "raw" /"urlhaus" / day
output_dir.mkdir(parents=True, exist_ok=True)

raw_path = output_dir / f"recent_urls_{timestamp}.json"
meta_path = output_dir / f"meta_{timestamp}.json"

raw_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False, encoding="utf-8")
                    