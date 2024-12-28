import os
import requests
import logging
from dotenv import load_dotenv


api_key_error_shown = False     # Flag to ensure error message is printed only once

def query_virustotal(file_path, file_hash, api_key=None):
    """Query VirusTotal for file information."""

    global api_key_error_shown

    # Load API key from .env file if not provided directly
    if not api_key:
        load_dotenv()           # Load environment variables from .env
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        if not api_key_error_shown:
            print("[WARNING] - Sample(s) will not be analyzed using VirusTotal since VirusTotal API key not found in .env file.")
            logging.warning("Sample(s) will not be analyzed using VirusTotal since VirusTotal API key not found in .env file.")
            api_key_error_shown = True
            
        return {"error": "API key is missing."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        print(f"Starting analysis on VirusTotal for: {file_path}")
        logging.info(f"Starting analysis on VirusTotal: {file_path}")

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            print(f"Analysis completed on VirusTotal for: {file_path}")
            logging.info(f"Analysis completed on VirusTotal: {file_path}")

            return response.json()
        else:
            print(f"VirusTotal API Error: {response.status_code}")
            logging.error(f"VirusTotal API Error: {response.status_code}")
            return {"error": f"VirusTotal API Error: {response.status_code}"}
        
    except Exception as e:
        logging.error(f"Error querying VirusTotal: {e}")
        return {"error": f"Error querying VirusTotal: {e}"}
