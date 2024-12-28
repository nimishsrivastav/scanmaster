import math
import magic
import hashlib
import logging

def detect_file_type(file_path):
    """Detect the file type using MIME."""
    
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)

        print(f"Detecting file type for: {file_path}")
        logging.info(f"Detecting file type for: {file_path}")

        return file_type
    
    except Exception as e:
        print(f"Error detecting file type: {e}")
        logging.error(f"Error detecting file type: {e}")
        return None

def calculate_file_hash(file_path):
    """Calculate both SHA-256 and MD5 hashes of a file."""

    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
        
        sha256_hash = sha256_hasher.hexdigest()
        md5_hash = md5_hasher.hexdigest()
        
        print(f"Calculating MD5 and SHA-256 hashes for: {file_path}")
        logging.info(f"Calculating MD5 and SHA-256 hashes for: {file_path}")
        
        return sha256_hash, md5_hash
    
    except Exception as e:
        print(f"Error calculating file hash: {e}", f"Error calculating file hash: {e}")
        logging.error(f"Error calculating file hash: {e}", f"Error calculating file hash: {e}")
        return None
    
def calculate_entropy(data):
    """Calculate the entropy of a byte array."""

    if not data:
        return 0
    
    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    data_len = len(data)
    entropy = -sum(
        (freq / data_len) * math.log2(freq / data_len)
        for freq in frequency if freq > 0
    )

    return entropy

def analyze_entropy(file_path):
    """Perform entropy analysis on a file."""

    try:
        with open(file_path, "rb") as f:
            data = f.read()

            print(f"Calculating entropy for: {file_path}")
            logging.info(f"Calculating entropy for: {file_path}")

            return calculate_entropy(data)
        
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        logging.error(f"Error calculating entropy: {e}")
        return None
