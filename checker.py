from pathlib import Path

from hasher import calculate_file_hash
from baseline import load_baseline
from scanner import scan_log_files

def check_file_integrity(file_path):
    """Check the integrity of one monitored file."""

    path = Path(file_path).resolve()
    absolute_path = str(path)

    data = load_baseline()
    stored_files = data["files"]

    # Check existence before attempting to calculate a hash.
    if not path.is_file():

        if absolute_path in stored_files:
            return "MISSING"

        return "NOT_MONITORED"

    if absolute_path not in stored_files:
        return "NOT_MONITORED"

    current_hash = calculate_file_hash(path)
    original_hash = stored_files[absolute_path]

    if current_hash == original_hash:
        return "UNMODIFIED"

    return "MODIFIED"


def check_directory_integrity(directory_path):
    """Check all log files in a directory."""

    directory = Path(directory_path).resolve()

    if not directory.is_dir():
        raise NotADirectoryError(directory_path)

    # Load and authenticate the baseline only once.
    data = load_baseline()
    stored_files = data["files"]

    current_files = scan_log_files(directory)

    results = []
    current_paths = set()

    # Check existing log files.
    for file_path in current_files:

        absolute_path = str(file_path.resolve())
        current_paths.add(absolute_path)

        if absolute_path not in stored_files:
            status = "NEW"

        else:
            current_hash = calculate_file_hash(file_path)
            original_hash = stored_files[absolute_path]

            if current_hash == original_hash:
                status = "UNMODIFIED"
            else:
                status = "MODIFIED"

        results.append({
            "file": absolute_path,
            "status": status
        })

    # Detect previously monitored files that are now missing.
    for stored_path in stored_files:

        baseline_path = Path(stored_path)

        try:
            baseline_path.relative_to(directory)
        except ValueError:
            continue

        if (
            baseline_path.suffix.lower() == ".log"
            and stored_path not in current_paths
        ):
            results.append({
                "file": stored_path,
                "status": "MISSING"
            })

    return results
