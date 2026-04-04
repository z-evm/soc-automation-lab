import os          # Provides functions for interacting with the file system (directories, paths, files)
import yaml        # PyYAML library used to parse YAML files into Python data structures

# Directory containing the YAML validation records.
# Each YAML file represents a validated ATT&CK technique observed in the lab.
VALIDATIONS_DIR = "detection-tracker/validations"


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

                # Use the MITRE ATT&CK technique ID as the dictionary key
                # Example: "T1046", "T1059.001"
                validations[validation_data["technique_id"]] = validation_data

    # Return the complete dataset of validation records
    return validations


# Standard Python entry point.
# This block runs only when the script is executed directly
# (not when imported as a module).
if __name__ == "__main__":

    # Load the validation dataset from YAML files
    validations = load_validations()

    # Print a summary showing how many validation records were loaded
    print(f"Loaded {len(validations)} validations.")

    # Iterate through the dataset and print each technique
    # validations.items() returns (key, value) pairs:
    # key = technique_id
    # value = YAML data dictionary
    for validation_id, validation in validations.items():

        # Print a readable summary for each technique
        # technique_name comes from the YAML file fields
        print(f"Validation ID: {validation_id}, Name: {validation['technique_name']}")