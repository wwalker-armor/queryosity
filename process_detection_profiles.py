import json
import csv

def load_detection_profiles(json_file):
    """Load detection profiles from the given JSON file."""
    with open(json_file, 'r', encoding='utf-8') as f:
        profiles = json.load(f)
    return profiles

def get_joined_classification(profile):
    """
    Given a detection profile, compute the joined classification string based on the
    counts for 'User', 'Process', 'Host', and 'Network'. Returns None if none of these counts are nonzero.
    """
    class_data = profile.get("classification", {})
    specific = {}
    for key in ["User", "Process", "Host", "Network"]:
        count = class_data.get(key, 0)
        if count > 0:
            specific[key.lower()] = count

    if not specific:
        return None

    # Sort by count descending; if equal, the sort is by key.
    sorted_classifications = sorted(specific.items(), key=lambda x: x[1], reverse=True)
    return "-".join([item[0] for item in sorted_classifications])

def create_grouped_csv(profiles, output_csv):
    """
    three columns csv
      - classification - user, process, host, network get 1 row each
      - detection count - the number of detections for a classification
      - detection - a JSON array (as a string) of all detection rule names with that overall classification
    *discarding unknown classifications*
    """
    groups = {"user": [], "process": [], "host": [], "network": []}
    
    for profile in profiles:
        overall = profile.get("classification", {}).get("Overall", "").lower()
        if overall in groups:
            groups[overall].append(profile.get("detection", ""))
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["classification", "detection count", "detection"])
        for cl in ["user", "process", "host", "network"]:
            detection_list = groups[cl]
            detection_count = len(detection_list)
            detections_str = json.dumps(detection_list)
            writer.writerow([cl, detection_count, detections_str])

def create_joined_classifications_csv(profiles, output_csv):
    """
    Create a CSV with two columns:
      - detection: the detection rule (e.g. file name)
      - classification: a joined string based on nonzero counts among the four types.
    
    Each row represents one detection. Profiles that have no nonzero counts for 'User', 'Process',
    'Host', or 'Network' are skipped.
    """
    rows = []
    for profile in profiles:
        joined = get_joined_classification(profile)
        if joined is None:
            continue
        rows.append((profile.get("detection", ""), joined))
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["detection", "classification"])
        for detection, classification in rows:
            writer.writerow([detection, classification])

def create_grouped_joined_classifications_csv(profiles, output_csv):
    """
    Create a CSV with three columns:
      - classification: the joined classification string (e.g. 'user', 'process-user', 'user-process-host-network', etc.)
      - detection count: the number of detections with that joined classification.
      - detection: a JSON array (as a string) of detection rule names with that joined classification.
    
    This groups detections by their joined classification (ignoring profiles that have no nonzero counts
    for 'User', 'Process', 'Host', or 'Network').
    """
    groups = {}
    for profile in profiles:
        joined = get_joined_classification(profile)
        if joined is None:
            continue
        detection = profile.get("detection", "")
        groups.setdefault(joined, []).append(detection)
    
    # Optionally, sort the groups (here, sorted alphabetically by the classification key)
    sorted_groups = sorted(groups.items(), key=lambda x: x[0])
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["classification", "detection count", "detection"])
        for classification, detections in sorted_groups:
            writer.writerow([classification, len(detections), json.dumps(detections)])

def main():
    # File names (adjust as needed)
    json_file = "DETECTION_PROFILES.json"
    grouped_csv_file = "grouped_classifications.csv"
    joined_csv_file = "joined_classifications.csv"
    grouped_joined_csv_file = "grouped_joined_classifications.csv"
    
    profiles = load_detection_profiles(json_file)
    
    create_grouped_csv(profiles, grouped_csv_file)
    create_joined_classifications_csv(profiles, joined_csv_file)
    create_grouped_joined_classifications_csv(profiles, grouped_joined_csv_file)
    
    print("CSV files created:")
    print(f" - {grouped_csv_file}")
    print(f" - {joined_csv_file}")
    print(f" - {grouped_joined_csv_file}")

if __name__ == '__main__':
    main()