"""
Intel Pipeline — Export Verification Script
Standalone script to verify the SHA256 hash of an export file against its sidecar.
Run manually before ingesting an export into the correlation engine.

Usage:
    py verify_export.py                          # Verify most recent export
    py verify_export.py <filename>               # Verify specific export file
    py verify_export.py --list                   # List all retained snapshots

Exit codes:
    0 — Verification passed
    1 — Verification failed or file not found
"""

import sys
import os

# Ensure src is importable from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.exporter import verify_export, list_snapshots

EXPORTS_DIR = os.path.join(os.environ["USERPROFILE"], "Desktop", "Intel", "Exports")


def print_snapshots():
    snapshots = list_snapshots()
    if not snapshots:
        print("No export snapshots found.")
        return
    print(f"{'ID':<5} {'Exported At':<30} {'Type':<12} {'Entries':<10} {'TLP':<12} Filename")
    print("-" * 100)
    for s in snapshots:
        print(
            f"{s['id']:<5} {s['exported_at'][:26]:<30} {s['export_type']:<12} "
            f"{s['entry_count']:<10} {s['tlp']:<12} {s['filename']}"
        )


def run_verification(filename):
    print(f"Verifying: {filename}")
    print("-" * 60)

    result = verify_export(filename)

    if "error" in result:
        print(f"ERROR: {result['error']}")
        return False

    print(f"File:     {result['filename']}")
    print(f"Expected: {result['expected']}")
    print(f"Actual:   {result['actual']}")
    print()

    if result["valid"]:
        print("VERIFICATION PASSED — export integrity confirmed.")
        return True
    else:
        print("VERIFICATION FAILED — hashes do not match.")
        print("Do not ingest this export. Investigate before proceeding.")
        return False


def main():
    args = sys.argv[1:]

    # List mode
    if args and args[0] == "--list":
        print_snapshots()
        sys.exit(0)

    # Specific file
    if args:
        filename = args[0]
        # Strip path if analyst passed a full path
        filename = os.path.basename(filename)
        passed = run_verification(filename)
        sys.exit(0 if passed else 1)

    # Default — most recent snapshot
    snapshots = list_snapshots()
    if not snapshots:
        print("No export snapshots found.")
        sys.exit(1)

    most_recent = snapshots[0]["filename"]
    print(f"No filename specified — verifying most recent export.")
    print()
    passed = run_verification(most_recent)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
