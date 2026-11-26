import argparse
from pathlib import Path

from hasher import calculate_file_hash
from baseline import (
    save_baseline,
    display_baseline,
    BaselineIntegrityError
)
from checker import (
    check_file_integrity,
    check_directory_integrity
)
from scanner import scan_log_files


def initialize_baseline(target_path, action="Initialized"):
    """Initialize or update hashes for log files."""

    files = scan_log_files(target_path)

    if not files:
        print("\nNo .log files found.")
        return

    print(f"\nFound {len(files)} log file(s).")

    successful = 0
    failed = 0

    for file_path in files:
        try:
            file_hash = calculate_file_hash(file_path)
            save_baseline(file_path, file_hash)

            print(f"{action}: {file_path.name}")
            successful += 1

        except OSError as error:
            print(f"Could not process {file_path}: {error}")
            failed += 1

    print("\n========== SUMMARY ==========")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print("=============================")


def display_directory_report(results):
    """Display directory integrity results."""

    counts = {
        "UNMODIFIED": 0,
        "MODIFIED": 0,
        "MISSING": 0,
        "NEW": 0
    }

    print("\n========== INTEGRITY REPORT ==========")

    for item in results:
        status = item["status"]
        counts[status] += 1

        print(f"\nFile: {item['file']}")
        print(f"Status: {status}")

    print("\n-------------- SUMMARY --------------")

    for status, count in counts.items():
        print(f"{status}: {count}")

    print(f"Total: {len(results)}")
    print("=====================================")


def check_integrity(target_path):
    """Check file or directory integrity."""

    path = Path(target_path)

    if path.is_dir():
        results = check_directory_integrity(path)
        display_directory_report(results)

    else:
        status = check_file_integrity(path)

        print("\n========== INTEGRITY REPORT ==========")
        print(f"File: {path.resolve()}")
        print(f"Status: {status}")
        print("=====================================")


def update_baseline(target_path):
    """Update trusted hashes after confirmation."""

    print("\nWARNING: This changes trusted baseline hashes.")

    confirmation = input(
        "Type UPDATE to continue: "
    ).strip()

    if confirmation != "UPDATE":
        print("Baseline update cancelled.")
        return

    initialize_baseline(target_path, action="Updated")


def create_parser():
    """Create command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="File Integrity Checker - SHA-256 and HMAC protection"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands"
    )

    init_parser = subparsers.add_parser(
        "init",
        help="Initialize baseline"
    )
    init_parser.add_argument("path", help="File or directory path")

    check_parser = subparsers.add_parser(
        "check",
        help="Check file or directory integrity"
    )
    check_parser.add_argument("path", help="File or directory path")

    subparsers.add_parser(
        "show",
        help="Display authenticated baseline"
    )

    update_parser = subparsers.add_parser(
        "update",
        help="Update existing baseline"
    )
    update_parser.add_argument("path", help="File or directory path")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "init":
            initialize_baseline(args.path)

        elif args.command == "check":
            check_integrity(args.path)

        elif args.command == "show":
            display_baseline()

        elif args.command == "update":
            update_baseline(args.path)

    except BaselineIntegrityError as error:
        print(f"\nSECURITY ERROR: {error}")

    except (OSError, ValueError) as error:
        print(f"\nERROR: {error}")

    except KeyboardInterrupt:
        print("\nOperation cancelled.")


if __name__ == "__main__":
    main()
