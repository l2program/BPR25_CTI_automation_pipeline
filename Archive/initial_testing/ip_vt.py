import requests

VT_API_KEY = "INSERT_API_KEY" 

ip = "165.22.247.105"

def get_vt_ip_report(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()


report = get_vt_ip_report(ip)

import json
print(json.dumps(report, indent=2))
