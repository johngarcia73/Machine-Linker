import os
import json
import base64
from typing import Dict, Union, List

def serialize_directory(path: str) -> tuple[str, bytes]:
    """
    Serializes a directory into a format suitable for transmission.
    Returns (folder_name, serialized_data)
    """
    folder_name = os.path.basename(path)
    structure: Dict[str, Union[str, Dict]] = {"__type__": "directory", "files": {}}
    
    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, path)
            try:
                with open(full_path, 'rb') as f:
                    # Convert bytes to string 64based
                    file_content = base64.b64encode(f.read()).decode('utf-8')
                    structure["files"][relative_path] = file_content
            except Exception as e:
                print(f"Error reading {full_path}: {e}")
                continue
    
    return folder_name, b"DIR:" + json.dumps(structure).encode()

def reconstruct_directory(save_path: str, content: bytes) -> None:
    """
    Reconstructs a directory from its serialized form
    """
    try:
        structure = json.loads(content[4:].decode())  # Skip "DIR:" prefix
        if structure.get("__type__") != "directory":
            raise ValueError("Invalid directory data")
        
        os.makedirs(save_path, exist_ok=True)
        
        for rel_path, file_content in structure["files"].items():
            full_path = os.path.join(save_path, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            # Decode base64 string back to bytes
            binary_content = base64.b64decode(file_content)
            
            with open(full_path, 'wb') as f:
                f.write(binary_content)
    except Exception as e:
        raise ValueError(f"Error reconstructing directory: {e}")
