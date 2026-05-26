import os          # Provides functions for interacting with the file system (directories, paths, files)
import yaml        # PyYAML library used to parse YAML files into Python data structures

# Directory containing the YAML validation records.
# Each YAML file represents a validated ATT&CK technique observed in the lab.
VALIDATIONS_DIR = os.path.join(os.path.dirname(__file__), "validations")

def load_validations():
    """
    Load all YAML validation files from the validations directory.

    Returns:
        dict: A dictionary keyed by technique_id where each value
              is the parsed YAML data for that validation.
    """

    # Create an empty dictionary to store validation records.
    # Structure will look like:
    # {
    #   "T1046": {...yaml contents...},
    #   "T1059.001": {...yaml contents...}
    # }
    validations = {}

    # Iterate through every file in the validations directory
    for filename in os.listdir(VALIDATIONS_DIR):

        # Only process YAML files
        if filename.endswith(".yaml"):

            # Construct the full file path
            filepath = os.path.join(VALIDATIONS_DIR, filename)

            # Open the YAML file for reading
            # UTF-8 encoding avoids Windows character encoding issues
            with open(filepath, "r", encoding="utf-8") as file:

                # Parse the YAML file into a Python dictionary
                validation_data = yaml.safe_load(file)

                if not isinstance(validation_data, dict):
                    continue # or raise error

                technique_id = validation_data.get("technique_id", "").strip()

                if not technique_id:
                    continue # or raise error

                if technique_id in validations:
                    print(f"Warning: duplicate technique_id detected: {technique_id}")

                # Store the validation data in the dictionary, keyed by technique_id
                validations[technique_id] = validation_data

    # Return the complete dataset of validation records
    return validations

# Filter validated techniques
def get_validated_techniques(validations):
    return {
        k: v for k, v in validations.items()
        if v.get("validated") is True
    }

# Calculate validation coverage percentage
def calculate_coverage(validations):
    validated = get_validated_techniques(validations)

    total_techniques = len(validations)
    validation_count = len(validated)

    tactics = {}
    detection_outcomes = {}

    for v in validated.values():
        # --- TACTIC COUNT ---
        tactic = v.get("tactic", "Unknown").strip()
        tactics[tactic] = tactics.get(tactic, 0) + 1

        # --- OUTCOME COUNT ---
        outcome = v.get("detection_outcome", "unknown").strip()
        detection_outcomes[outcome] = detection_outcomes.get(outcome, 0) + 1

    coverage_percentage = (
        (validation_count / total_techniques) * 100 
        if total_techniques > 0 else 0
    )
    return {
        "total_techniques": total_techniques,
        "validated_techniques": validation_count,
        "coverage_percentage": coverage_percentage,
        "tactics": tactics,
        "detection_outcomes": detection_outcomes,
        "validated_data": validated
    }

# Standard Python entry point.
# This block runs only when the script is executed directly
# (not when imported as a module).
if __name__ == "__main__":

    validations = load_validations()

    coverage = calculate_coverage(validations)

    print("\n=== Coverage Summary ===")
    print(f"Total Techniques: {coverage['total_techniques']}")
    print(f"Validated Techniques: {coverage['validated_techniques']}")
    print(f"Coverage %: {coverage['coverage_percentage']:.2f}%")

    print("\n=== Coverage by Tactic ===")
    for tactic, count in sorted(coverage["tactics"].items()):
        print(f"{tactic}: {count}")

    print("\n=== Detection Outcomes ===")
    for outcome, count in sorted(coverage["detection_outcomes"].items()):
        print(f"{outcome}: {count}")