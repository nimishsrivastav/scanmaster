# Static Malware Analysis Framework

This framework is designed for static analysis of malware. It supports scanning individual files or entire directories, extracting metadata, performing YARA rule-based analysis, querying VirusTotal for threat intelligence, and disassembling binaries for further analysis. The results are saved in JSON format, which can be used for further investigation and reporting.

## Features

- **File Type Detection:** Automatically detects the file type (e.g., PE, ELF).
- **PE Metadata Extraction:** Extracts metadata from PE files, such as headers and sections.
- **YARA Rule Scanning:** Scan files against custom YARA rules for known malware patterns.
- **VirusTotal Integration:** Queries the VirusTotal API for file analysis and malware intelligence.
- **Disassembly:** Disassembles the binary using Radare2 to examine the code.
- **Multi-File Processing:** Process multiple files from a directory using parallel execution.

## Requirements

- Python 3.x
- `requests` (for VirusTotal API integration)
- `r2pipe*` (for interacting with Radare2)
- `pefile` (for PE file metadata extraction)
- `yara-python` (for YARA rule scanning)
- `python-dotenv` (for storing the API Key as environment variable). Alternatively, the key can be stored in the system environment variable or can be passed as an argument while execution (Refer [Usage](#Usage) section).

Above requirements can be downloaded using below command:
`pip install -r requirements.txt`

*For interacing with Radare2, the system is requried to have Radare2 installed, which can be installed from [here]([https://github.com/radareorg/radare2]).

To make the framework setup hassle-free, user can execute following scripts without installing any other dependencies:
- For Windows, [setup.bat](setup.bat)
- For Linux, [setup.sh](setup.sh)

## Usage

First we need to make the `scanmaster.py` file executable which can be done by using following command on Linux:
`chmod +x scanmaster.py`

```
./scanmaster.py
 ____                  __  __           _            
/ ___|  ___ __ _ _ __ |  \/  | __ _ ___| |_ ___ _ __ 
\___ \ / __/ _` | '_ \| |\/| |/ _` / __| __/ _ \ '__|
 ___) | (_| (_| | | | | |  | | (_| \__ \ ||  __/ |   
|____/ \___\__,_|_| |_|_|  |_|\__,_|___/\__\___|_|   
                                                     

usage: 
        ./scanmaster.py -f <file_path> [-y <yara_rules>] [-k <api_key>] [-o <output_dir>]
        ./scanmaster.py -d <directory_path> [-y <yara_rules>] [-k <api_key>] [-o <output_dir>]

ScanMaster: A Static Malware Analysis Framework

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Single file to analyze
  -d DIRECTORY, --directory DIRECTORY
                        Directory containing files to analyze
  -y YARA, --yara YARA  Path to YARA rules
  -k API_KEY, --api-key API_KEY
                        VirusTotal API key. Can also be loaded via environment variables
  -o OUTPUT, --output OUTPUT
                        Path to save JSON report
```

Example,
- To analyze a single file,
`./scanmaster.py -f /path/to/malware.exe -y /path/to/yara-rules -k <your_virustotal_api_key> -o /path/to/output/directory`
- To analyze all files in a directory,
`./scanmaster.py -d /path/to/directory -y /path/to/yara-rules -k <your_virustotal_api_key> -o /path/to/output/directory`

For running the tool on Windows, simply execute the batch script `scanmaster.bat` with the options being the same as in Linux command.

**Note:** All options are optional except from -f (for file) and -d (for directory).

## Output

The analysis results are saved as a JSON report in the specified output directory. The report includes the following information:

- **File Name:** The name of the analyzed file.
- **File Path:** The full path of the analyzed file.
- **File Type:** The detected type of the file (e.g., PE, ELF).
- **Hashes:** MD5 and SHA-256 hashes of the file.
- **PE Metadata:** Metadata extracted from PE files.
- **YARA Matches:** Matches found using the provided YARA rules.
- **Entropy:** Entropy analysis of the file.
- **VirusTotal Data:** Analysis results from VirusTotal.
- **Disassembly:** Disassembly of the file using Radare2.

## Logging

The framework uses Python’s built-in logging module to log the analysis process. You can configure the logging level by modifying the ```logging_format.py``` file.

- **INFO:** General information about the process.
- **WARNING:** An indication that something unexpected happened.
- **DEBUG:** Detailed information, such as analysis steps.
- **ERROR:** Error messages in case of failure.

## Multi-threading

The framework supports multi-threading for processing multiple files simultaneously. This speeds up the process when analyzing a large number of files in a directory.

## Example Report

```
{
  "file_name": "malware.exe",
  "file_path": "/path/to/malware.exe",
  "file_type": "PE",
  "md5_hash": "c04fd8d9198095192e7d55345966da2e",
  "sha256_hash": "abcd1234efgh5678ijkl9101112mnopqrstuvwx",
  "pe_metadata": {
    "headers": {...},
    "sections": [...]
  },
  "yara_matches": [
    "YARA rule match 1",
    "YARA rule match 2"
  ],
  "entropy": 7.4,
  "virustotal_analysis": {
    "result": "malicious",
    "detection": 45
  },
  "disassembly": [
    "0x00400000: mov eax, 0x10",
    "0x00400004: call 0x00401000"
  ]
}
```

## License

This project is licensed under the MIT License.