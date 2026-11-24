from __future__ import annotations

import json
import math
import re
import zipfile
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pandas as pd

PRIMARY_SHEET = "Datos finales"
SUMMARY_SHEET = "Hoja 5"
SOURCE_COLUMNS = (
    "acknowledged_time",
    "completion_time",
    "send_analysis_time",
    "created_at",
    "type",
    "payload",
)
DURATION_COLUMNS = (
    "acknowledged_time",
    "completion_time",
    "send_analysis_time",
)
SAFE_LABELS = {
    "alertname",
    "grafana_folder",
    "type",
    "job",
    "rulename",
    "ref_id",
}
EMPTY_END_TIMESTAMPS = {"0001-01-01T00:00:00Z", "0001-01-01T00:00:00+00:00"}
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


class DatasetValidationError(ValueError):
    """Raised when the supplied workbook does not match the expected schema."""


def _open_excel(source: Path) -> pd.ExcelFile:
    if source.suffix.lower() == ".zip":
        with zipfile.ZipFile(source) as archive:
            workbooks = [
                name for name in archive.namelist() if name.lower().endswith(".xlsx")
            ]
        if len(workbooks) != 1:
            raise DatasetValidationError(
                f"Expected exactly one .xlsx file in {source.name}; found {len(workbooks)}."
            )
        with zipfile.ZipFile(source) as archive:
            return pd.ExcelFile(archive.open(workbooks[0]), engine="openpyxl")
    if source.suffix.lower() != ".xlsx":
        raise DatasetValidationError("Input must be a .zip archive or .xlsx workbook.")
    return pd.ExcelFile(source, engine="openpyxl")


def _read_sheets(source: Path) -> tuple[pd.ExcelFile, pd.DataFrame]:
    if not source.is_file():
        raise FileNotFoundError(f"Dataset file not found: {source}")
    workbook = _open_excel(source)
    if PRIMARY_SHEET not in workbook.sheet_names:
        raise DatasetValidationError(
            f"Required sheet {PRIMARY_SHEET!r} is missing; found {workbook.sheet_names}."
        )
    records = pd.read_excel(workbook, sheet_name=PRIMARY_SHEET)
    missing_columns = sorted(set(SOURCE_COLUMNS) - set(records.columns))
    if missing_columns:
        raise DatasetValidationError(f"Required columns are missing: {missing_columns}.")
    return workbook, records


def _decode_payload(value: Any) -> dict[str, Any]:
    """Decode JSON values that may be serialized once or twice in the workbook."""
    if not isinstance(value, str):
        if isinstance(value, dict):
            return value
        raise DatasetValidationError("Alert payload must be a JSON object or string.")
    decoded: Any = value
    for _ in range(2):
        try:
            decoded = json.loads(decoded)
        except (json.JSONDecodeError, TypeError) as exc:
            raise DatasetValidationError("Alert payload contains invalid JSON.") from exc
        if isinstance(decoded, dict):
            return decoded
    raise DatasetValidationError("Alert payload did not decode to a JSON object.")


def _clean_text(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return text or None


def _redact_ip_addresses(value: Any) -> str | None:
    text = _clean_text(value)
    return IPV4_PATTERN.sub("[IP masquée]", text) if text else None


def _clean_timestamp(value: Any) -> str | None:
    text = _clean_text(value)
    if text is None or text in EMPTY_END_TIMESTAMPS:
        return None
    if isinstance(value, (datetime, date, pd.Timestamp)):
        return value.isoformat()
    return text


def _clean_number(value: Any) -> float | None:
    if value is None or pd.isna(value):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def normalize_record(row: pd.Series, excel_row: int) -> dict[str, Any]:
    payload = _decode_payload(row["payload"])
    labels = payload.get("labels") or {}
    annotations = payload.get("annotations") or {}
    if not isinstance(labels, dict) or not isinstance(annotations, dict):
        raise DatasetValidationError(f"Invalid labels or annotations at Excel row {excel_row}.")

    safe_labels = {
        key: str(labels[key])
        for key in SAFE_LABELS
        if key in labels and labels[key] is not None
    }
    return {
        "source_record_id": f"{PRIMARY_SHEET}:{excel_row}",
        "source_row": excel_row,
        "created_at": _clean_timestamp(row["created_at"]),
        "source_type": _clean_text(row["type"]),
        "alert_family": _clean_text(labels.get("type")),
        "alert_name": _clean_text(labels.get("alertname")),
        "alert_status": _clean_text(payload.get("status")),
        "labels": safe_labels,
        "summary": _redact_ip_addresses(annotations.get("summary")),
        "description": _redact_ip_addresses(annotations.get("description")),
        "starts_at": _clean_timestamp(payload.get("startsAt")),
        "ends_at": _clean_timestamp(payload.get("endsAt")),
        "acknowledged_time": _clean_number(row["acknowledged_time"]),
        "completion_time": _clean_number(row["completion_time"]),
        "send_analysis_time": _clean_number(row["send_analysis_time"]),
    }


def inspect_dataset(source: Path) -> tuple[pd.ExcelFile, pd.DataFrame, dict[str, Any]]:
    workbook, records = _read_sheets(source)
    alert_names: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    source_types: Counter[str] = Counter()
    for _, row in records.iterrows():
        payload = _decode_payload(row["payload"])
        labels = payload.get("labels") or {}
        alert_names[str(labels.get("alertname") or "(missing)")] += 1
        statuses[str(payload.get("status") or "(missing)")] += 1
        source_types[str(row["type"] or "(missing)")] += 1

    sheet_profiles = []
    for sheet in workbook.sheet_names:
        frame = pd.read_excel(workbook, sheet_name=sheet)
        sheet_profiles.append(
            {
                "name": sheet,
                "rows": int(frame.shape[0]),
                "columns_count": int(frame.shape[1]),
                "columns": [
                    {
                        "name": str(column),
                        "dtype": str(frame[column].dtype),
                        "missing": int(frame[column].isna().sum()),
                    }
                    for column in frame.columns
                ],
            }
        )

    duration_summary: dict[str, dict[str, float | None]] = {}
    for column in DURATION_COLUMNS:
        values = pd.to_numeric(records[column], errors="coerce").dropna()
        duration_summary[column] = {
            "mean": float(values.mean()) if not values.empty else None,
            "median": float(values.median()) if not values.empty else None,
            "minimum": float(values.min()) if not values.empty else None,
            "maximum": float(values.max()) if not values.empty else None,
        }

    report = {
        "source_file": source.name,
        "primary_sheet": PRIMARY_SHEET,
        "record_count": len(records),
        "sheets": sheet_profiles,
        "source_type_counts": dict(sorted(source_types.items())),
        "alert_name_counts": dict(sorted(alert_names.items())),
        "alert_status_counts": dict(sorted(statuses.items())),
        "duration_unit": "unknown; not documented in the workbook",
        "duration_summary": duration_summary,
        "privacy": "IP and instance labels are excluded from normalized records.",
        "limitations": [
            "The workbook contains alert events, not raw CPU, RAM, or disk time series.",
            "All records are marked firing; no successful remediation evidence is present.",
            "The summary sheet is descriptive and is not merged into the event records.",
        ],
    }
    return workbook, records, report


def process_dataset(source: Path, output_dir: Path) -> dict[str, Any]:
    _, records, report = inspect_dataset(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / "alerts.jsonl"
    report_path = output_dir / "inspection_report.json"

    with normalized_path.open("w", encoding="utf-8", newline="\n") as stream:
        for excel_row, (_, row) in enumerate(records.iterrows(), start=2):
            normalized = normalize_record(row, excel_row)
            stream.write(json.dumps(normalized, ensure_ascii=False, allow_nan=False) + "\n")

    with report_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return report
