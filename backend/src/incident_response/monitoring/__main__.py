from __future__ import annotations

import argparse
import json
import time

from incident_response.monitoring.service import collect_snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect read-only host metrics periodically.")
    parser.add_argument("--interval", type=float, default=5.0, help="Sampling interval in seconds.")
    args = parser.parse_args()
    if not 1 <= args.interval <= 3600:
        parser.error("--interval must be between 1 and 3600 seconds.")
    try:
        while True:
            print(json.dumps(collect_snapshot().model_dump(mode="json"), ensure_ascii=False), flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
