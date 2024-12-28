import logging
import r2pipe


def disassemble_with_radare2(file_path):
    """Disassemble the given binary using Radare2."""

    try:
        # Log the start of the disassembly process
        print(f"Starting disassembly for: {file_path}")
        logging.info(f"Starting disassembly for: {file_path}")
        
        # Initialize radare2 pipe
        r2 = r2pipe.open(file_path)
        
        # Perform binary analysis
        r2.cmd("aaa")  # Perform all analysis
        print(f"Radare2 analysis completed for: {file_path}")
        logging.debug(f"Radare2 analysis completed for: {file_path}")
        
        # Get disassembly of the main function or code section
        disassembly = r2.cmd("pd 100")  # Disassemble 100 instructions
        print(f"Disassembly completed for: {file_path}")
        logging.info(f"Disassembly completed for: {file_path}")
        
        # Return the disassembly output
        return disassembly
    
    except Exception as e:
        print(f"Disassembly failed for {file_path}: {e}")
        logging.error(f"Disassembly failed for {file_path}: {e}")
        return None
