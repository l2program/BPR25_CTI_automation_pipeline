import json

data = {
    "total_tag_observations": 2816,
    "mapped_tag_observations": 2315,
    "unmapped_tag_observations": 501
}

md = f"""
### Tag Observation Summary

- Total: {data['total_tag_observations']}
- Mapped: {data['mapped_tag_observations']}
- Unmapped: {data['unmapped_tag_observations']}
"""

print(md)