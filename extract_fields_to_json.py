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
JSON_OUTPUT_BAD_FIELDS = os.path.join("dirty_fields.json")

CLASSIFICATION_MAPPING = {
    "user": "user",
    "username": "user",
    "account": "user",
    "file": "process-file",
    "process-file": "process-file",
    "md5": "process-file",
    "sha1": "process-file",
    "sha256": "process-file",
    "command": "process-file",
    "path": "process-file",
    "host": "host",
    "computer": "host",
    "ipaddress": "network",
    "ipv4": "network",
    "ipv6": "network",
    "traffic": "network",
    "domain": "network",
    "tld": "network",
    "port": "network",
    "protocol": "network",
}

KNOWN_DOMAINS = {"user", "process-file", "host", "network"}



# Goes through yaml detection files by line. 
# Parses fields from the lines that start with "| extend", "| summarize", "| project".
def parse_kql_for_fields(query_text, detection_filename):
    clean_fields_data = []
    dirty_fields_data = []

    lines = query_text.split('\n')
    for line in lines:
        original_line = line  # Keep the exact line
        line = line.lower().strip()

        # We only care about lines starting with '|'
        if not line.startswith('|'):
            continue
        
        # Detect the KQL statement type
        statement_type = None
        if line.startswith('| extend '):
            statement_type = "EXTEND"
            extend_part = line[len('| extend '):].strip()
            # Split on commas outside parentheses
            fields_expressions = re.split(r',(?![^(]*\))', extend_part)
            for expr in fields_expressions:
                expr = expr.strip()
                # We only consider expressions with '='
                if '=' in expr:
                    unclean_field = expr.split('=')[0].strip()
                    cleaned_field = clean_field_name(unclean_field)
                    
                    if cleaned_field is None:
                        # This is a dirty (invalid) field
                        dirty_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": unclean_field
                        })
                    else:
                        # Map the domain for this clean field
                        mapped_domain = map_to_domain(cleaned_field)
                        clean_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": cleaned_field,
                            "domain": mapped_domain
                        })

        elif line.startswith('| summarize '):
            statement_type = "SUMMARY"
            summarize_part = line[len('| summarize '):].strip()
            parts = summarize_part.split(' by ')
            left_side = parts[0].strip()
            right_side = parts[1].strip() if len(parts) > 1 else ""

            # Left side (aggregated fields, often have aliases with '=')
            left_expressions = re.split(r',(?![^(]*\))', left_side)
            for seg in left_expressions:
                seg = seg.strip()
                # Example: Count = count()
                if '=' in seg:
                    unclean_field = seg.split('=')[0].strip()
                    cleaned_field = clean_field_name(unclean_field)
                    if cleaned_field is None:
                        dirty_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": unclean_field
                        })
                    else:
                        mapped_domain = map_to_domain(cleaned_field)
                        clean_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": cleaned_field,
                            "domain": mapped_domain
                        })

            # Right side (group-by fields, typically comma-separated)
            if right_side:
                group_by_fields = right_side.split(',')
                for group_col in group_by_fields:
                    unclean_field = group_col.strip()
                    cleaned_field = clean_field_name(unclean_field)
                    if cleaned_field is None:
                        dirty_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": unclean_field
                        })
                    else:
                        mapped_domain = map_to_domain(cleaned_field)
                        clean_fields_data.append({
                            "type": statement_type,
                            "line": original_line,
                            "detection": detection_filename,
                            "field": cleaned_field,
                            "domain": mapped_domain
                        })

        elif line.startswith('| project ') and 'project-away' not in line:
            statement_type = "PROJECT"
            project_part = line[len('| project '):].strip()
            project_expressions = re.split(r',(?![^(]*\))', project_part)
            for expr in project_expressions:
                expr = expr.strip()
                if '=' in expr:
                    # Example: AliasField = OriginalField
                    unclean_field = expr.split('=')[0].strip()
                else:
                    # Single field like "FieldA"
                    unclean_field = expr

                cleaned_field = clean_field_name(unclean_field)
                if cleaned_field is None:
                    dirty_fields_data.append({
                        "type": statement_type,
                        "line": original_line,
                        "detection": detection_filename,
                        "field": unclean_field
                    })
                else:
                    mapped_domain = map_to_domain(cleaned_field)
                    clean_fields_data.append({
                        "type": statement_type,
                        "line": original_line,
                        "detection": detection_filename,
                        "field": cleaned_field,
                        "domain": mapped_domain
                    })

    return clean_fields_data, dirty_fields_data

def clean_field_name(field_name):
    """
    Returns the cleaned field name if it passes the regex check,
    otherwise returns None.
    """
    # Only keep fields with alphanumeric, underscores, or dots
    if re.match(r'^[a-zA-Z0-9_.]+$', field_name):
        return field_name
    return None

def map_to_domain(cleaned_field):
    """
    Given a cleaned field name, map it to a known domain using CLASSIFICATION_MAPPING.
    If no match is found, returns 'unknown'.
    """
    field_lower = cleaned_field.lower()
    for key, mapped_domain in CLASSIFICATION_MAPPING.items():
        if key in field_lower:
            if mapped_domain in KNOWN_DOMAINS:
                return mapped_domain
    return "unknown"

def main():
    print(f"Scanning directory: {SENTINEL_RULES}")

    # Lists to hold all field objects (clean and dirty) across all files
    all_clean_fields = []
    all_dirty_fields = []
    files_processed = 0 #remove when done

    for root, dirs, files in os.walk(SENTINEL_RULES):
        for file in files:
            if file.endswith(".yaml"):
                files_processed += 1 #remove when done
                yaml_path = os.path.join(root, file)
                print(f"\nProcessing file: {yaml_path}")

                try:
                    with open(yaml_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    print(f"   > Error reading/parsing {file}: {e}")
                    continue

                alert_name = data.get("name", os.path.splitext(file)[0])
                print(f"   > Alert name: {alert_name}")

                query_text = data.get("query", "")
                if not query_text.strip():
                    print("   > No query found or query is empty.")
                    # No fields to parse, just continue
                    continue

                # Parse fields by type from the query
                clean_fields_data, dirty_fields_data = parse_kql_for_fields(query_text, file)

                # Accumulate results
                all_clean_fields.extend(clean_fields_data)
                all_dirty_fields.extend(dirty_fields_data)

    if files_processed == 0: #remove when done
        print("No .yaml files found in the directory. Exiting.") #remove when done
        return #remove when done

    try:
        with open(JSON_OUTPUT_GOOD_FIELDS, "w", encoding="utf-8") as jsonfile:
            json.dump(all_clean_fields, jsonfile, indent=2, ensure_ascii=False)
        print(f"\nWrote {JSON_OUTPUT_GOOD_FIELDS}")
    except Exception as e:
        print(f"Could not write {JSON_OUTPUT_GOOD_FIELDS}. Reason: {e}")

    try:
        with open(JSON_OUTPUT_BAD_FIELDS, "w", encoding="utf-8") as jsonfile:
            json.dump(all_dirty_fields, jsonfile, indent=2, ensure_ascii=False)
        print(f"Successfully wrote {JSON_OUTPUT_BAD_FIELDS}")
    except Exception as e:
        print(f"Could not write {JSON_OUTPUT_BAD_FIELDS}. Reason: {e}")

    print("\nDone.")

if __name__ == "__main__":
    main()