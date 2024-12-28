#!/usr/bin/env python3

import os
import sys
import time
import argparse
import pyfiglet

# Add the 'src' directory to the module search path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from batch_processing import *
from report import *
from logging_format import *


def main():
    start_time = time.time()

    ascii_text = pyfiglet.figlet_format("ScanMaster")
    print(ascii_text)

    parser = argparse.ArgumentParser(
        description="ScanMaster: A Static Malware Analysis Framework",
        usage=(
            "\n\t./scanmaster.py -f <file_path> [-y <yara_rules>] [-k <api_key>] [-o <output_dir>]"
            "\n\t./scanmaster.py -d <directory_path> [-y <yara_rules>] [-k <api_key>] [-o <output_dir>]"
        ),
    )
    parser.add_argument("-f", "--file", help="Single file to analyze")
    parser.add_argument("-d", "--directory", help="Directory containing files to analyze")
    parser.add_argument("-y", "--yara", help="Path to YARA rules")
    parser.add_argument("-k", "--api-key", help="VirusTotal API key. Can also be loaded via environment variables")
    parser.add_argument("-o", "--output", default=None, help="Path to save JSON report")

    args = parser.parse_args()

    if args.file:
        # Set default output directory for single file analysis if not provided
        if not args.output:
            args.output = os.path.join("reports", "single-file-analysis")

        output_filename = generate_report_filename(is_single_file=True)
        output_path = os.path.join(args.output if args.output else ".", output_filename)
        
        # Ensure the output is not mistakenly treated as a directory
        if not os.path.isdir(os.path.dirname(output_path)):
            output_dir = os.path.dirname(output_path)

            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

        # Process a single file
        result = process_file(args.file, args.yara, args.api_key)

        save_report_as_json(result, output_path)
        print(f"\nAnalysis completed for single file. Report saved to {output_path}")
        logging.info(f"Analysis completed for single file. Report saved to {output_path}")

        elapsed_time = time.time() - start_time
        print(f"Completion Time: {elapsed_time:.2f} seconds")
        logging.info(f"Completion Time: {elapsed_time:.2f} seconds")

    elif args.directory:
        # Set default output directory for directory analysis if not provided
        if not args.output:
            args.output = os.path.join("reports", "directory-analysis")

        output_filename = generate_report_filename(is_single_file=False)
        output_path = os.path.join(args.output if args.output else ".", output_filename)
        
        # Ensure the output is not mistakenly treated as a directory
        if not os.path.isdir(os.path.dirname(output_path)):
            output_dir = os.path.dirname(output_path)

            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
        
        # Process multiple files from a directory
        file_paths = [
            os.path.join(args.directory, f)
            for f in os.listdir(args.directory)
            if os.path.isfile(os.path.join(args.directory, f))
        ]

        results = batch_process_files(file_paths, args.yara, args.api_key)

        save_report_as_json(results, output_path)
        print(f"\nAnalysis completed for the directory. Report saved to {output_path}")
        logging.info(f"Analysis completed for the directory. Report saved to {output_path}")

        elapsed_time = time.time() - start_time
        print(f"Completion Time: {elapsed_time:.2f} seconds")
        logging.info(f"Completion Time: {elapsed_time:.2f} seconds")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()