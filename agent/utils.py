import os
import hashlib
import platform
import socket
from pathlib import Path

def get_hostname():
    return socket.gethostname()

def compute_file_hashes(file_path):
    """
    Computes MD5 and SHA256 hashes of a file safely.
    """
    if not file_path or not os.path.isfile(file_path):
        return {"md5": "", "sha256": ""}
    
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    except Exception:
        return {"md5": "", "sha256": ""}

def is_suspicious_path(path_str):
    """
    Checks if binary path resides in Temp, AppData, or User Profile temp directories.
    """
    if not path_str:
        return False
    path_lower = path_str.lower()
    suspicious_dirs = [
        "\\temp\\", "/temp/",
        "\\appdata\\local\\temp", "/appdata/local/temp",
        "\\users\\public\\", "/users/public/",
        "\\downloads\\", "/downloads/"
    ]
    return any(s in path_lower for s in suspicious_dirs)

def is_executable_signed(file_path):
    """
    Checks PE digital signature on Windows using win32api or PowerShell Get-AuthenticodeSignature.
    Fallback returns True for standard system binaries or False if unknown.
    """
    if not file_path or not os.path.isfile(file_path):
        return False
    
    if platform.system() == "Windows":
        try:
            import subprocess
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status"'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            status = res.stdout.strip()
            return status in ["Valid", "Signed"]
        except Exception:
            pass
    # Basic fallback heuristic: binaries in System32 / Windows are assumed signed
    p_lower = file_path.lower()
    if "c:\\windows\\system32" in p_lower or "c:\\windows\\syswow64" in p_lower:
        return True
    return False

def sanitize_string(val):
    if val is None:
        return ""
    return str(val).strip()
