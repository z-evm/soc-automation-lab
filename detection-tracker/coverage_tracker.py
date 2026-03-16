import os
import yaml

VALIDATIONS_DIR = "detection-tracker/validations"

def load_validations():
    validations = {}
    for filename in os.listdir(VALIDATIONS_DIR):
        if filename.endswith(".yaml"):
            with open(os.path.join(VALIDATIONS_DIR, filename), 'r', encoding="utf-8") as file:
                validation_data = yaml.safe_load(file)
                validations[validation_data['technique_id']] = validation_data
    return validations

if __name__ == "__main__":
    validations = load_validations()
    print(f"Loaded {len(validations)} validations.")
    for validation_id, validation in validations.items():
        print(f"Validation ID: {validation_id}, Name: {validation['technique_name']}")