import subprocess

def run_script(script_name):
    try:
        print(f"Running {script_name}...")
        subprocess.run(["python", script_name], check=True)
        print(f"{script_name} completed successfully.\n")
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}: {e}")
        exit(1)

def main():
    # Order of execution based on dependencies:
    # 1. discover_fields.py (field discovery from YAML files)
    # 2. extract_fields_to_json.py (alternative or additional field extraction)
    # 3. generate_detection_profiles.py (creates detection profiles from fields)
    # 4. process_detection_profiles.py (produces CSV reports from profiles)
    scripts = [
        "discover_fields.py",
        "extract_fields_to_json.py",
        "generate_detection_profiles.py",
        "process_detection_profiles.py"
    ]
    
    for script in scripts:
        run_script(script)

    print("All scripts executed successfully.")

if __name__ == "__main__":
    main()
