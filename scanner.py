from pathlib import Path

def scan_log_files(target_path):
    """Find log files from a single file or directory."""

    path = Path(target_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_file():

        if path.suffix.lower() == ".log":
            return [path]

        return []

    # Search recursively and handle .log, .LOG, and .Log.
    log_files = [
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() == ".log"
    ]

    return sorted(log_files)