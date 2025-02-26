import os
import re
import yaml
import json
from dotenv import load_dotenv

load_dotenv()

SENTINEL_RULES = os.getenv("SENTINEL_RULES")
#OUTPUT_DIR = os.getenv("OUTPUT_DIR")
#os.makedirs(OUTPUT_DIR, exist_ok=True)

# This state of code can parse the fields out of queries but there is still a lot of non-field data output. To get around this I chose to identify the good fields as ones containing alphanumeric characters, underscores, or dots via regex ^[a-zA-Z0-9_.]+$. and the bad fields as one that don't match regex, i.e. special characters, spaces, etc.
JSON_OUTPUT_GOOD_FIELDS = os.path.join("good_fields.json")
JSON_OUTPUT_BAD_FIELDS = os.path.join("bad_fields.json")

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
}

CLASSIFICATIONS = {"user", "process", "host", "network"}

def parse_kql_for_fields(query_text, detection_filename):
    good_fields_data = []
    bad_fields_data = []
    # Create a set to track unique fields
    seen_fields = set()

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

                    # Create a unique key for the field
                    key = (detection_filename, statement, good_field)
                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        # Only add if not seen before
                        if key not in seen_fields:
                            seen_fields.add(key)
                            field_classification = map_field_to_classification(good_field)
                            good_fields_data.append({
                                "type": statement,
                                "line": original_line,
                                "detection": detection_filename,
                                "field": good_field,
                                "classification": field_classification
                            })

        # Similar logic applies for other KQL commands, e.g., summarize and project.
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
                    key = (detection_filename, statement, good_field)
                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        if key not in seen_fields:
                            seen_fields.add(key)
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
                    key = (detection_filename, statement, good_field)
                    if good_field is None:
                        bad_fields_data.append({
                            "type": statement,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": field
                        })
                    else:
                        if key not in seen_fields:
                            seen_fields.add(key)
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
                key = (detection_filename, statement, good_field)
                if good_field is None:
                    bad_fields_data.append({
                        "type": statement,
                        "line": original_line,
                        "detection": detection_filename,
                        "field": field
                    })
                else:
                    if key not in seen_fields:
                        seen_fields.add(key)
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

"""
def map_field_to_classification(good_field):
    field_lower = good_field.lower()
    classification = [field_classification for key, field_classification in CLASSIFICATION_MAPPING.items() if key in field_lower]
    return classifications if classification else ["unknown"]

"""

def main():
    all_good_fields = []
    all_bad_fields = []

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

                good_fields_data, bad_fields_data = parse_kql_for_fields(query_text, file)

                all_good_fields.extend(good_fields_data)
                all_bad_fields.extend(bad_fields_data)

    print("Writing clean fields to JSON")
    try:
        with open(JSON_OUTPUT_GOOD_FIELDS, "w", encoding="utf-8") as jsonfile:
            json.dump(all_good_fields, jsonfile, indent=2)
        print(f"Clean fields written to {JSON_OUTPUT_GOOD_FIELDS}")
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