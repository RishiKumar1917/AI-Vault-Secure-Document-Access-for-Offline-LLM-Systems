"""Standalone CLI Tool to verify cryptographic SHA-256 hash-chain integrity of audit logs."""

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.audit import AuditLogger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify cryptographic SHA-256 hash-chain integrity of AI-Vault audit logs."
    )
    parser.add_argument(
        "--log",
        type=str,
        default="logs/audit.log",
        help="Path to the audit log file (default: logs/audit.log)",
    )

    args = parser.parse_args()
    log_path = Path(args.log)

    print("=" * 65)
    print("      AI-VAULT CRYPTOGRAPHIC AUDIT LOG INTEGRITY VERIFIER")
    print("=" * 65)
    print(f"Inspecting file: {log_path.resolve()}")
    print("-" * 65)

    is_valid, records_verified, message = AuditLogger.verify_integrity(str(log_path))

    if is_valid:
        print("[STATUS: PASSED] - Cryptographic Integrity Intact")
        print(f"Total Records Verified: {records_verified}")
        print(f"Details: {message}")
        print("=" * 65)
        sys.exit(0)
    else:
        print("[STATUS: FAILED] - Tampering or Corruption Detected!")
        print(f"Records Verified Before Failure: {records_verified}")
        print(f"Error Diagnostic: {message}")
        print("=" * 65)
        sys.exit(1)


if __name__ == "__main__":
    main()
