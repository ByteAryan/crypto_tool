import os

def read_file_bytes(path: str) -> bytes:
    """Read bytes from a file (cross-platform)."""
    # Normalize path for cross-platform compatibility
    path = os.path.normpath(path)
    with open(path, "rb") as f:
        return f.read()

def write_file_bytes(path: str, data: bytes):
    """Write bytes to a file (cross-platform)."""
    # Normalize path and ensure directory exists
    path = os.path.normpath(path)
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
