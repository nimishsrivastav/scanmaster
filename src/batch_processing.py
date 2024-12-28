import os
from concurrent.futures import ThreadPoolExecutor

from utility import *
from virustotal import *
from pe_metadata import *
from yara_scanner import *
from disassembly import *


def process_file(file_path, yara_rules_path, api_key):
    """Process a single file."""

    print(f"Starting scan for: {file_path}")
    logging.info(f"Starting scan for: {file_path}")

    file_type = detect_file_type(file_path)
    md5_hash, sha256_hash = calculate_file_hash(file_path)
    pe_metadata = extract_pe_metadata(file_path) if "pe" in file_type.lower() else {}
    yara_matches = scan_with_yara(file_path, yara_rules_path) if yara_rules_path else []
    entropy = analyze_entropy(file_path)
    file_hash = sha256_hash
    vt_data = query_virustotal(file_path, file_hash, api_key)
    disassembly = disassemble_with_radare2(file_path)

    print(f"Scan completed for: {file_path}")
    logging.info(f"Scan completed for: {file_path}")
    
    return {
        "file_name": os.path.basename(file_path),
        "file_path": os.path.abspath(file_path),
        "file_type": file_type,
        "md5_hash": md5_hash,
        "sha256_hash": sha256_hash,
        "pe_metadata": pe_metadata,
        "yara_matches": yara_matches,
        "entropy": entropy,
        "virustotal_analysis": vt_data,
        "disassembly": disassembly
    }

def batch_process_files(file_paths, yara_rules_path, api_key):
    """Batch process multiple files using parallel execution."""
    
    results = []
    
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(process_file, file_path, yara_rules_path, api_key)
            for file_path in file_paths
        ]
        
        for future in futures:
            results.append(future.result())
    
    return results
