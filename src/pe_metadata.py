import pefile
import logging


def extract_pe_metadata(file_path):
    """Extract metadata from a PE file."""
    
    metadata = {}

    try:
        print(f"Extracting PE metadata for: {file_path}")
        logging.info(f"Extracting PE metadata for: {file_path}")
        
        pe = pefile.PE(file_path)
        metadata["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        metadata["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
        metadata["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
        metadata["sections"] = []

        for section in pe.sections:
            metadata["sections"].append({
                "name": section.Name.decode().strip(),
                "entropy": section.get_entropy(),
                "size_of_raw_data": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
            })

        print(f"PE metadata extraction completed for: {file_path}")
        logging.info(f"PE metadata extraction completed for: {file_path}")
        
    except Exception as e:
        metadata["error"] = print(f"Error extracting PE metadata: {e}")
        metadata["error"] = logging.error(f"Error extracting PE metadata: {e}")

    return metadata