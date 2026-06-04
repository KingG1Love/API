"""
Task 4: JSON Schema validation for result_task_2.json
"""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_FILE = "json_schema.json"
DATA_FILE = "result_task_2.json"


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    # Load schema and data
    if not Path(SCHEMA_FILE).exists():
        print(f"ERROR: {SCHEMA_FILE} not found. Run task_4 schema generation first.")
        sys.exit(1)
    if not Path(DATA_FILE).exists():
        print(f"ERROR: {DATA_FILE} not found. Run task_2.py first.")
        sys.exit(1)

    schema = load_json(SCHEMA_FILE)
    data = load_json(DATA_FILE)

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if not errors:
        print("Validation OK: all records pass the schema.")
        return

    print(f"Validation FAILED: {len(errors)} error(s) found.\n")

    # Summarise missing/empty nested fields per CVE
    for field in ["cvss_list", "cpe_list", "cwe"]:
        empty_ids = [row["ID"] for row in data if not row.get(field)]
        if empty_ids:
            print(f"  Empty '{field}' (minItems/minProperties violation):")
            for cve_id in empty_ids:
                print(f"    - {cve_id}")

    # Print other errors
    other = []
    for error in errors:
        path = "$" + "".join(
            f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.path
        )
        is_nested_empty = any(
            path.endswith("." + f) for f in ["cvss_list", "cpe_list", "cwe"]
        )
        if not is_nested_empty:
            other.append((path, error.message))

    if other:
        print("\n  Other errors:")
        for path, message in other:
            print(f"    {path}: {message}")


if __name__ == "__main__":
    print("Starting Task 4 (validation)...")
    main()
