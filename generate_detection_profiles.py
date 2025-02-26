import os
import re
import yaml
import json
from dotenv import load_dotenv

load_dotenv()

SENTINEL_RULES = os.getenv("SENTINEL_RULES")

# This state of code can parse the fields out of queries but there is still a lot of non-field data output. To get around this I chose to identify the good fields as ones containing alphanumeric characters, underscores, or dots via regex ^[a-zA-Z0-9_.]+$. and the bad fields as one that don't match regex, i.e. special characters, spaces, etc.
JSON_OUTPUT_GOOD_FIELDS = os.path.join("good_fields.json")
JSON_OUTPUT_BAD_FIELDS = os.path.join("bad_fields.json")
DETECTION_PROFILES = os.path.join("detection_profiles.json")

# classifcations must be in lower
CLASSIFICATION_MAPPING = {
    "user": "user",
    "username": "user",
    "account": "user",
    "file": "process",
    "process": "process",
    "md5": "process",
    "sha1": "process",
    "sha256": "process",
    "command": "process",
    "path": "process",
    "host": "host",
    "computer": "host",
    "ipaddress": "network",
    "ipv4": "network",
    "ipv6": "network",
    "traffic": "network",
    "classification": "network",
    "tld": "network",
    "port": "network",
    "protocol": "network",
    "ipcustomentity": "network", # added for demonstrative purposes for rule 'nginxknownmaliciousips.yaml'
}

CLASSIFICATIONS = {"user", "process", "host", "network"}

def parse_kql_for_fields(query_text, detection_filename):
    good_fields_data = []
    bad_fields_data = []

    lines = query_text.split('\n')
    for line in lines:
        original_line = line  # Keep the exact line
        line = line.lower().strip()

        if not line.startswith('|'):
            continue

        statement = None
        
        if line.startswith('| extend '):
            statement = "EXTEND"
            extend_part = line[len('| extend '):].strip()
            fields_expressions = re.split(r',(?![^(]*\))', extend_part)
            for expr in fields_expressions:
                expr = expr.strip()
                if '=' in expr:
                    field = expr.split('=')[0].strip()
                    good_field = good_field_names(field)

                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        field_classification = map_field_to_classification(good_field)
                        good_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": good_field,
                            "classification": field_classification
                        })

        elif line.startswith('| summarize '):
            statement = "SUMMARY"
            summarize_part = line[len('| summarize '):].strip()
            parts = summarize_part.split(' by ')
            left_side = parts[0].strip()
            right_side = parts[1].strip() if len(parts) > 1 else ""

            left_expressions = re.split(r',(?![^(]*\))', left_side)
            for seg in left_expressions:
                seg = seg.strip()
                if '=' in seg:
                    field = seg.split('=')[0].strip()
                    good_field = good_field_names(field)
                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        field_classification = map_field_to_classification(good_field)
                        good_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": good_field,
                            "classification": field_classification
                        })

            if right_side:
                group_by_fields = right_side.split(',')
                for group_col in group_by_fields:
                    field = group_col.strip()
                    good_field = good_field_names(field)
                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        field_classification = map_field_to_classification(good_field)
                        good_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": good_field,
                            "classification": field_classification
                        })

        elif line.startswith('| project ') and 'project-away' not in line:
            statement = "PROJECT"
            project_part = line[len('| project '):].strip()
            project_expressions = re.split(r',(?![^(]*\))', project_part)
            for expr in project_expressions:
                expr = expr.strip()
                if '=' in expr:
                    field = expr.split('=')[0].strip()
                else:
                    field = expr

                good_field = good_field_names(field)
                if good_field is None:
                    bad_fields_data.append({
                        "type": statement,
                        "line": original_line,
                        "detection": detection_filename,
                        "field": field
                    })
                else:
                    field_classification = map_field_to_classification(good_field)
                    good_fields_data.append({
                        "type": statement,
                        "line": original_line,
                        "detection": detection_filename,
                        "field": good_field,
                        "classification": field_classification
                    })

    return good_fields_data, bad_fields_data

def good_field_names(field_name):
    if re.match(r'^[a-zA-Z0-9_.]+$', field_name):
        return field_name
    return None

def map_field_to_classification(good_field):
    field_lower = good_field.lower()
    for key, field_classification in CLASSIFICATION_MAPPING.items():
        if key in field_lower:
            if field_classification in CLASSIFICATIONS:
                return field_classification
    return "unknown"

# Just incase we need to map more then one classification to a field to weight fields
"""
def map_field_to_classification(good_field):
    field_lower = good_field.lower()
    classification = [field_classification for key, field_classification in CLASSIFICATION_MAPPING.items() if key in field_lower]
    return classifications if classification else ["unknown"]
"""

def create_detection_profile(detection_filename, good_fields_data):
    classification_counts = {
        "User": 0,
        "Host": 0,
        "Network": 0,
        "Process": 0,
        "Unknown": 0
    }

    for data in good_fields_data:
        classification = data.get("classification")
        if classification == "user":
            classification_counts["User"] += 1
        elif classification == "host":
            classification_counts["Host"] += 1
        elif classification == "network":
            classification_counts["Network"] += 1
        elif classification == "process":
            classification_counts["Process"] += 1
        elif classification == "unknown":
            classification_counts["Unknown"] += 1

    # If all specific counts (User, Host, Network, Process) are zero, overall is Unknown.
    if (classification_counts["User"] == 0 and
        classification_counts["Host"] == 0 and
        classification_counts["Network"] == 0 and
        classification_counts["Process"] == 0):
        overall_classification = "Unknown"
    else:
        # Otherwise, choose the maximum among the specific categories, ignoring Unknown.
        specific_counts = {
            "User": classification_counts["User"],
            "Host": classification_counts["Host"],
            "Network": classification_counts["Network"],
    "Process": classification_counts["Process"]
        }
        overall_classification = max(specific_counts, key=specific_counts.get)

    detection_profile = {
        "detection": detection_filename,
        "classification": {
            "Overall": overall_classification,
            "User": classification_counts["User"],
            "Host": classification_counts["Host"],
            "Network": classification_counts["Network"],
            "Process": classification_counts["Process"],
            "Unknown": classification_counts["Unknown"]
        }
    }

    return detection_profile

def main():
    all_good_fields = []
    all_bad_fields = []
    detection_profiles = []

    if not os.path.exists(SENTINEL_RULES):
        print(f"'{SENTINEL_RULES}' not found")
        exit()

    for root, dirs, files in os.walk(SENTINEL_RULES):
        for file in files:
            if file.endswith(".yaml"):
                yaml_path = os.path.join(root, file)
                print(f"Processing file: {yaml_path}")
                try:
                    with open(yaml_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    print(f"Error reading/parsing file {file}: {e}")
                    continue

                query_text = data.get("query", "")
                if not query_text.strip():
                    print(f"No query found in file: {file}")
                    continue

                rule_name = data.get("name", "")
                if not rule_name.strip():
                    print(f"File format incorrect. No name in file: {file}")
                    continue

                good_fields_data, bad_fields_data = parse_kql_for_fields(query_text, file)

                # Create the detection profile
                detection_profile = create_detection_profile(file, good_fields_data)
                detection_profiles.append(detection_profile)

                all_good_fields.extend(good_fields_data)
                all_bad_fields.extend(bad_fields_data)

    print("Trying to build detection profile")
    try:
        with open("DETECTION_PROFILES.JSON", "w", encoding="utf-8") as jsonfile:
            json.dump(detection_profiles, jsonfile, indent=2)
        print(f"Detection profiles written to {DETECTION_PROFILES}")
    except Exception as e:
        print(f"Failed to write detection profiles: {e}")

    print("Writing good fields to JSON")
    try:
        with open(JSON_OUTPUT_GOOD_FIELDS, "w", encoding="utf-8") as jsonfile:
            json.dump(all_good_fields, jsonfile, indent=2)
        print(f"Good fields written to {JSON_OUTPUT_GOOD_FIELDS}")
    except Exception as e:
        print(f"Failed to write fields to {JSON_OUTPUT_GOOD_FIELDS}: {e}")

    print("Writing bad fields")
    try:
        with open(JSON_OUTPUT_BAD_FIELDS, "w", encoding="utf-8") as jsonfile:
            json.dump(all_bad_fields, jsonfile, indent=2)
        print(f"Bad fields written to {JSON_OUTPUT_BAD_FIELDS}")
    except Exception as e:
        print(f"Failed to write {JSON_OUTPUT_BAD_FIELDS}: {e}")
    
    
    print("Done")

if __name__ == "__main__":
    main()