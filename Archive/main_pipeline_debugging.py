# response = requests.get(
#     recent_url, recent_payload,
#     headers={"Auth-Key": API_KEY},
#     timeout=30,
# )

#possible error types 
# 200 ok
# 400 negative
# response.raise_for_status()


#parse JSON response into a py dictionary
# raw = response.json()


#test internal status
# query_status = raw.get("query_status")
# if query_status != "ok":
#     raise RuntimeError(f"urlhaus query_status={query_status!r}")

# urls = raw.get("urls", [])
# recent_payload = raw.get("payloads", [])

# print("query_status:", query_status)
# print("entries:", len(urls))
# print()


# #find existing keys
# all_keys = sorted({key for item in urls for key in item.keys()})
# print("unique keys:")
# for key in all_keys:
#     print("-", key)
# print()


# #count useful fields
# status_counts = Counter()
# threat_counts = Counter()
# tag_counts = Counter()

# for item in urls:
#     status_counts[item.get("url_status", "missing")] += 1
#     threat_counts[item.get("threat", "missing")] += 1
    
#     for tag in item.get("tags") or []:
#         tag_counts[tag] += 1

# print("url status counts:")
# print(dict(status_counts))
# print()

# print("threat counts:")
# print(dict(threat_counts))
# print()

# print("top tags:")
# print(dict(tag_counts.most_common(10)))
# print()


# fields_to_show = [
#     "id",
#     "url",
#     "host",
#     "url_status",
#     "date_added",
#     "threat",
#     "tags",
#     "reporter",
#     "blacklists",
#     "larted",
#     "urlhaus_reference",
# ]

# print("/urls/recent/ sample ingestion:")
# for i, item in enumerate(urls[:5], start=1):
#     print(f"\n record {i} ")
#     preview = {}

#     for field in fields_to_show:
#         if field in item:
#             preview[field] = item[field]

#     print(json.dumps(preview, indent=2, ensure_ascii=False))

# #Look for extra keys
# known = set(fields_to_show)
# extra_keys = sorted(set(all_keys) - known)





# blacklist_keys = sorted({
#     key
#     for item in urls
#     for key in (item.get("blacklists") or {}).keys()
# })

# print("blacklist contents:")
# for key in blacklist_keys:
#     print("-", key)
# print()

# host_counts = Counter()

# for item in urls:
#     host = item.get("host", "missing")
#     host_counts[host] += 1

# print("top hosts:")
# print(dict(host_counts.most_common(10)))
# print()

# reporter_counts = Counter()

# for item in urls:
#     reporter = item.get("reporter", "missing")
#     reporter_counts[reporter] += 1

# print("top reporters:")
# print(dict(reporter_counts.most_common(10)))
# print()

# print()
# print("EXTRA KEYS NOT PRESENT IN FIELDS_TO_SHOW:")
# for key in extra_keys:
#     print("-", key)


#attempt at seeing when url was last online
# last_online_missing = 0
# last_online_present = 0

# for item in urls:
#     if item.get("last_online"):
#         last_online_present += 1
#     else:
#         last_online_missing += 1
# print("last_online present:", last_online_present)
# print("last_online missing:", last_online_missing)
# print()

# Testing output printing 

# # normalized_urls = urlhaus_recent_normalization_test(urls)
# print("normalized URL sample")
# for i, item in enumerate(normalized_urls[:50], start=1):
#     print(f"\n /urls/recent/{LIMIT}/ URL normalization test {i} ---")
#     print(json.dumps(item, indent=2, ensure_ascii=False))
# print()



# print("normalized payload sample:")
# for i, item in enumerate(normalized_payloads[:50], start=1):
#     print(f"\n /payloads/recent/{LIMIT}/ normalization test {i} ")

#     print(json.dumps(item, indent=2, ensure_ascii=False))


# print("\n URLS SUMMARIZED")
# print(json.dumps(url_summary, indent=2, ensure_ascii=False))

# print("\n PAYLOADS SUMMARIZED")
# print(json.dumps(payloads_summary, indent=2, ensure_ascii=False))

# normalized_payloads = urlhaus_payloads_normalization_test(recent_payload)
# print("normalized payloads sample")
# for i, item in enumerate(normalized_payload[:3], start=1):
#     print(f"\n /payloads/recent/{LIMIT}/ normalization test {i} ")
#     print(json.dumps(item, indent=2, ensure_ascii=False))
# print()

#lesson learned: boolean values are lowercase in json, still boolean
#print(isinstance(clean_boolean(item.get("larted")), bool))


#print(json.dumps(
#    enrich_tags(["elf", "mozi", "ua-wget", "unknown_tag"]),
#    indent=2,
#    ensure_ascii=False
#))

#  matplotlib test for initial graph visualization 

# Path("output").mkdir(exist_ok=True)

# pick up later
# def bar_chart_test(data_dict, title, filename, xlabel="", ylabel="Count" ):
#     labels = list(data_dict.keys())
#     values = list(data_dict.values())

#     plt.figure(figsize=(10,5))
#     plt.bar(labels, values)
#     plt.title(title)
#     plt.xlabel(xlabel)
#     plt.ylabel(ylabel)
#     plt.xticks(rotation=45, ha="right")
#     plt.tight_layout()
#     plt.savefig(filename, dpi=200)
#     plt.close()

# bar_chart_test(
#     url_summary["status_counts"],
#     "URL Status Counts",
#     "output/url_status_counts.png",
#     xlabel="Status",
#     ylabel="Count",
    
# )

# bar_chart_test(
#     url_summary["top_tags"],
#     "Top URL Tags",
#     "output/top_url_tags.png",
#     xlabel="Tag",
#     ylabel="Count",
# )

# signature_counts = {
#     k: v for k, v in payloads_summary["signature_counts"].items()
#     if k != "missing"
# }

# bar_chart_test(
#     signature_counts,
#     "Payload Signature Counts", 
#     "output/payload_signature_counts.png",
#     xlabel="Signature",
#     ylabel="Count",
# )


