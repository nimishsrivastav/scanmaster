import os
import logging
from datetime import date


# Define the log directory and file
log_dir = "logs"
log_file = f"malware_analysis_{date.today().strftime('%Y%m%d')}.log"

# Create the log directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Change this to the desired level, e.g., logging.INFO
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(log_dir, log_file))  # Save logs to the specified file
    ]
)
