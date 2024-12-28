import os
import logging
import yara


def scan_with_yara(file_path, yara_rules_path):
    """Scan the file using all YARA rules in the specified folder."""

    try:
        print(f"Starting YARA scan for: {file_path}")
        logging.info(f"Starting YARA scan for: {file_path}")
        
        # Compile all the .yar files in the folder
        yara_rules = []

        for root, _, files in os.walk(yara_rules_path):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    rule_file_path = os.path.join(root, file)
                    yara_rules.append(rule_file_path)
        
        if not yara_rules:
            print("No YARA rule files found in the specified directory.")
            logging.error("No YARA rule files found in the specified directory.")
            return []
        
        # Compile the rules
        rules = yara.compile(filepaths={rule_file_path: rule_file_path for rule_file_path in yara_rules})
        
        # Perform YARA scan
        matches = rules.match(file_path)

        print(f"YARA scan completed for: {file_path}")
        logging.info(f"YARA scan completed for: {file_path}")
        
        return [str(match) for match in matches]
    
    except Exception as e:
        print(f"Error scanning with YARA: {e}")
        logging.error(f"Error scanning with YARA: {e}")
        return [f"Error scanning with YARA: {e}"]

