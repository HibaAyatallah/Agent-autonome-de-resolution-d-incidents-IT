from __future__ import annotations

import argparse
import json
from pathlib import Path

from incident_response.dataset.ingest import process_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect and normalize the monitoring dataset.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/source_dataset.zip"),
        help="Path to the supplied .zip archive or extracted .xlsx workbook.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed"))
    args = parser.parse_args()
    report = process_dataset(args.input, args.output_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
