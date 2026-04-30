import os
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

#save to json test
def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


#load json from file, return as object
def read_json(path):
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

#load API key from .env to avoid hardcoding
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("urlhaus_api_key")
if not API_KEY:
    raise RuntimeError("urlhaus_api_key not found")

#limit entries in the url path, max is 1000
LIMIT = 1000
RECENT_URLS = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{LIMIT}/"
RECENT_PAYLOADS = f"https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/{LIMIT}/"

#HTTP request

HEADERS = {"Auth-Key": API_KEY}

def fetch_json(url):
    response = requests.get(url, headers=HEADERS, timeout=30)
    response.raise_for_status()
    raw = response.json()

    query_status = raw.get("query_status")
    if query_status != "ok":
        raise RuntimeError(f"{url} query_status={query_status!r}")
    return raw

# Establish initial normalizing functionality

def clean_text(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None

def clean_host(host):
    host = clean_text(host)
    return host.lower() if host else None

def clean_status(status):
    status = clean_text(status)
    return status.lower() if status else None

def clean_tags(tags):
    if not tags:
        return []
    cleaned = []
    for tag in tags:
        tag = clean_text(tag)
        if tag:
            cleaned.append(tag.lower())
    return sorted(set(cleaned))

#ensure boolean values are not strings, catch-all attempt 
def clean_boolean(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    value = str(value).strip().lower()
    if value in {"1", "yes", "true"}:
        return True
    if value in {"0", "no", "false"}:
        return False
    return None


#normalization schema for /recent/
def urlhaus_recent_normalization(urls):
    normalized_urls = []

    for item in urls:
        normalized_item = {
            "source": "/urlhaus/urls/recent/",
            "source_id": clean_text(item.get("id")),
            "indicator_type": "url",
            "indicator_value": clean_text(item.get("url")),
            "host": clean_host(item.get("host")),
            "first_seen": clean_text(item.get("date_added")),
            "status": clean_status(item.get("url_status")),
            "tags": clean_tags(item.get("tags")),
            "reporter": clean_text(item.get("reporter")),
            "reference": clean_text(item.get("urlhaus_reference")), 
            "source_metadata": {
                "threat": clean_text(item.get("threat")),
                "reported_to_hosting_provider": clean_boolean(item.get("larted")),
                "blacklists": item.get("blacklists") or {},},
        }
        normalized_urls.append(normalized_item)
    return normalized_urls




#normalization implementation for /payloads/ 

def urlhaus_payloads_normalization(payloads):
    normalized_payloads = []

    for item in payloads:
        normalized_item = {
            "source": "/urlhaus/payloads/recent/",
            "first_seen": clean_text(item.get("firstseen")),
            "filename": clean_text(item.get("filename")),
            "file_type": clean_text(item.get("file_type")),
            "file_size": item.get("file_size"),
            "response_md5": clean_text(item.get("md5_hash")),
            "response_sha256": clean_text(item.get("sha256_hash")),
            "signature": clean_text(item.get("signature")),
            "urlhaus_download": clean_text(item.get("urlhaus_download")),
        
        }
        normalized_payloads.append(normalized_item)
    return normalized_payloads




def run_ingest(BASE):
    recent_urls_raw = fetch_json(RECENT_URLS)
    recent_payloads_raw = fetch_json(RECENT_PAYLOADS)

    write_json(BASE/"raw"/"recent_urls_raw.json", recent_urls_raw)
    write_json(BASE/"raw"/"recent_payloads_raw.json", recent_payloads_raw)
    
    return recent_urls_raw, recent_payloads_raw


def run_normalize(BASE):
    recent_urls_raw = read_json(BASE/"raw"/"recent_urls_raw.json")
    recent_payloads_raw = read_json(BASE/"raw"/"recent_payloads_raw.json")

    recent_urls = recent_urls_raw.get("urls", [])
    recent_payloads = recent_payloads_raw.get("payloads", [])
    
    normalized_urls = urlhaus_recent_normalization(recent_urls)
    normalized_payloads = urlhaus_payloads_normalization(recent_payloads)

    write_json(BASE/"normalized"/"normalized_urls.json", normalized_urls)
    write_json(BASE/"normalized"/"normalized_payloads.json", normalized_payloads)

    return normalized_urls, normalized_payloads



TAG_GLOSSARY = {
    "elf": {
        "category": "file_format",
        "meaning": "Executable and Linkable Format"
    },
    "mozi": {
        "category": "malware_family",
        "meaning": "IoT botnet"
        },
    "clearfake": {
        "category": "malware_campaign",
        "meaning": "social engineering malware campaign"
    },
    "acrstealer": {
        "category": "malware_family",
        "meaning": "credential-stealing malware"
    },
    "mirai": {
        "category": "malware_family",
        "meaning": "IoT botnet"
    },
    "smartloader": {
        "category": "malware_family",
        "meaning": "loader malware family"
    },
    "netsupport": {
        "category": "malware_family",
        "meaning": "remote-access trojan"
    },
    "zip": {
        "category": "archive_format",
        "meaning": "ZIP archive format"
    },
    "mips": {
        "category": "architecture",
        "meaning": "targets MIPS architecture"
    },
    "32-bit": {
        "category": "architecture",
        "meaning": "32-bit architecture or binary"
    },
    "ua-wget": {
        "category": "delivery_pattern",
        "meaning": "user-agent wget usage"
    },
}



def enrich_normalized_urls(normalized_urls):
    enriched_urls = []
    for item in normalized_urls:
        enriched_item = dict(item)
        enriched_item["enriched_tags"] = enrich_tags(item.get("tags", []))
        enriched_urls.append(enriched_item)
    return enriched_urls


def enrich_tags(tags):
    enriched_tags = []

    for tag in tags:
        tag = str(tag).strip().lower()
        glossary_entry = TAG_GLOSSARY.get(tag)

        if glossary_entry:
            enriched_tags.append({
                "raw_tag":tag,
                "mapped": True,
                "category": glossary_entry["category"],
                "meaning": glossary_entry["meaning"],
            })
        else: 
            enriched_tags.append({
                "raw_tag":tag,
                "mapped": False,
                "category": "unmapped",
                "meaning": None,
            })
    return enriched_tags






RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
BASE = Path("output")/RUN_ID

recent_urls_raw, recent_payloads_raw = run_ingest(BASE)
normalized_urls, normalized_payloads = run_normalize(BASE)
enriched_urls = enrich_normalized_urls(normalized_urls)
write_json(BASE/"enriched"/"enriched_url.json", enriched_urls)






def summarize_urls(normalized_urls):
    status_counts = Counter()
    tag_counts = Counter()
    reporter_counts = Counter()
    host_counts = Counter()

    for item in normalized_urls:
        status_counts[item.get("status") or "missing"] += 1
        reporter_counts[item.get("reporter") or "missing"] += 1
        host_counts[item.get("host") or "missing"] += 1

        for tag in item.get("tags") or []:
            tag_counts[tag] += 1
    
    return {
        "number of entries": len(normalized_urls),
        "status_counts": dict(status_counts),
        "top_tags": dict(tag_counts.most_common(10)),
        "top_reporters": dict(reporter_counts.most_common(10)),
        "top_hosts": dict(host_counts.most_common(10)),
    }

def summarize_payloads(normalized_payloads):
    file_type_counts = Counter()
    signature_counts = Counter()
    sha256_counts = Counter()

    for item in normalized_payloads:
        file_type_counts[item.get("file_type") or "missing"] += 1
        signature_counts[item.get("signature") or "missing"] += 1

        sha256_value = item.get("response_sha256")
        if sha256_value:
            sha256_counts[sha256_value] += 1
    
    duplicate_sha256 = sum(count - 1 for count in sha256_counts.values() if count > 1)
    return {
        "number of entries": len(normalized_payloads),
        "unique_sha256_entries": len(sha256_counts),
        "duplicate_sha256_entries": duplicate_sha256,
        "file_type_counts": dict(file_type_counts.most_common(10)),
        "signature_counts": dict(signature_counts.most_common(10)),
    }


def summarize_enrichments(enriched_urls):
    mapped_count = 0
    unmapped_count = 0
    category_counts = Counter()
    mapped_tag_counts = Counter()
    unmapped_tag_counts = Counter()

    for item in enriched_urls:
        for tag in item.get("enriched_tags") or []:
            raw_tag = tag.get("raw_tag") or "missing"
            category = tag.get("category") or "missing"
            if tag.get("mapped"):
                mapped_count +=1
                category_counts[category] += 1
                mapped_tag_counts[raw_tag] += 1
            else:
                unmapped_count += 1
                unmapped_tag_counts[raw_tag] += 1
    
    total = mapped_count + unmapped_count

    return {
        "total_tag_observations": total,
        "mapped_tag_observations": mapped_count,
        "unmapped_tag_observations": unmapped_count,
        "mapping_coverage_percentage": round((mapped_count / total) * 100, 2) if total else 0,
        "unmapped_percent": round((unmapped_count / total) * 100, 2) if total else 0,
        "category_counts": dict(category_counts.most_common()),
        "top_mapped_tags": dict(mapped_tag_counts.most_common(10)),
        "top_unmapped_tags": dict(unmapped_tag_counts.most_common(10))

    }




url_summary = summarize_urls(normalized_urls)
payloads_summary = summarize_payloads(normalized_payloads)
enrichment_summary = summarize_enrichments(enriched_urls)





#save sections to JSON test 
summary_bundle = {
    "url_summary":url_summary,
    "payload_summary": payloads_summary,
    "url_examples": enriched_urls[:10],
    "payload_examples": normalized_payloads[:10],
}


# Testing output printing 




# file write testing 


write_json(BASE/"summary"/"url_summary.json", url_summary)
write_json(BASE/"summary"/"payload_summary.json", payloads_summary)
write_json(BASE/"summary"/"summary_bundle.json", summary_bundle)
write_json(BASE/"summary"/"enrichment_summary.json", enrichment_summary)


