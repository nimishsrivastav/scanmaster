import json
from datetime import datetime


def save_report_as_json(data, output_path):
    """Save the data as a JSON file."""

    with open(output_path, "w") as json_file:
        json.dump(data, json_file, indent=4)

def generate_report_filename(is_single_file):
    """Generate a timestamped filename for the report."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if is_single_file:
        return f"analysis_report_{timestamp}.json"
    else:
        return f"directory_analysis_report_{timestamp}.json"