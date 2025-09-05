from collections import defaultdict
import json
import os
from typing import Dict, List


# Load your JSON data from the file
with open("vulntrain/trainers/parent_to_children_mapping.json", "r") as f:
    data = json.load(f)


# Function to recursively determine hierarchy level
def build_hierarchy_levels(data):
    hierarchy = {}
    visited = set()

    def dfs(node, level):
        if node in visited:
            return
        visited.add(node)
        hierarchy[node] = level
        for child in data.get(node, []):
            dfs(child, level + 1)

    # Start DFS from each top-level node
    for key in data:
        dfs(key, 0)

    return hierarchy


hierarchy_levels = build_hierarchy_levels(data)

# Organize output by levels
from collections import defaultdict

output_with_levels = defaultdict(dict)
for key, level in hierarchy_levels.items():
    output_with_levels[f"Level {level}"][key] = data.get(key, [])

# Convert back to a regular dict and print
output_with_levels = dict(output_with_levels)

import json

# put the result in a json file
with open("vulntrain/trainers/cwe_hierarchy.json", "w") as f:
    json.dump(output_with_levels, f, indent=4)
