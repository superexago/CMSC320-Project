"""Build the CVE SQLite database from the JSON records in ``cves/``."""
import csv
import json
import sqlite3
from pathlib import Path
from typing import Any
from collections import Counter


# Configuration
DATA_DIRECTORY = Path(__file__).parent / "cves"
DATABASE_PATH = Path(__file__).parent / "database.sqlite"
DROPPED_CSV_PATH = Path(__file__).parent / "dropped.csv"
YEARS = [2022, 2023, 2024, 2025]

# Values that represent missing data and the replacement used for each field.
EMPTY_VALUES = {"NULL", "null", "n/a", "UNKNOWN", "", None}
MISSING_VALUE_REPLACEMENTS = {
    "availabilityImpact": "None",
    "confidentialityImpact": "None",
    "integrityImpact": "None",
    "privilegesRequired": "None",
    "userInteraction": "None",
    "scope": "Unchanged",
}

# Constants
COLUMNS = [
    "cveId",
    "dataVersion",
    "datePublished",
    "product",
    "vendor",
    "cweId",
    "attackComplexity",
    "attackVector",
    "availabilityImpact",
    "baseScore",
    "baseSeverity",
    "confidentialityImpact",
    "integrityImpact",
    "privilegesRequired",
    "scope",
    "userInteraction",
]
STRING_COLUMNS = [column for column in COLUMNS if column != "baseScore"]
VECTOR_KEY_TRANSLATION = {
    "AV": "attackVector",
    "AC": "attackComplexity",
    "PR": "privilegesRequired",
    "UI": "userInteraction",
    "S": "scope",
    "C": "confidentialityImpact",
    "I": "integrityImpact",
    "A": "availabilityImpact",
    "SC": "confidentialityImpact",
    "SI": "integrityImpact",
    "SA": "availabilityImpact",
}
VECTOR_VALUE_TRANSLATION = {
    "attackVector": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "userInteraction": {"N": "None", "R": "Required", "P": "Passive", "A": "Active"},
}
DEFAULT_VECTOR_VALUES = {
    "N": "None",
    "L": "Low",
    "P": "Partial",
    "C": "Complete",
    "M": "Medium",
    "H": "High",
    "U": "Unchanged",
    "R": "Required",
}
KEY_REPLACEMENTS = {
    "subAvailabilityImpact": "availabilityImpact",
    "subConfidentialityImpact": "confidentialityImpact",
    "subIntegrityImpact": "integrityImpact",
}
BASE_SEVERITY_BREAKPOINTS = (
    (4.0, "Low"),
    (7.0, "Medium"),
    (9.0, "High"),
    (10.1, "Critical"),
)
REQUIRED_FIELDS = {
    "cveId": "missing or empty CVE identifier",
    "datePublished": "missing or empty publication date",
    "baseScore": "missing or empty base score",
}
ATTACK_VECTOR_REPLACEMENTS = {
    "Adjacent": "Adjacent",
    "Adjacent network": "Adjacent",
}


class DroppedRecordError(ValueError):
    """Raised when a CVE record cannot be inserted into the database."""


def flatten_value(key: str, value: Any, target: dict[str, Any]) -> None:
    """Flatten nested JSON values into the key/value representation used here."""
    if isinstance(value, dict):
        flatten_dict(value, target)
    elif isinstance(value, list):
        if not value:
            target[key] = ""
        elif len(value) == 1:
            flatten_value(key, value[0], target)
        else:
            for index, item in enumerate(value):
                flatten_value(f"{key}({index})", item, target)
    else:
        target[key] = value


def flatten_dict(source: dict[str, Any], target: dict[str, Any]) -> None:
    """Flatten every value in a CVE JSON object into ``target``."""
    for key, value in source.items():
        flatten_value(key, value, target)


def translate_vector(vector_string: str, target: dict[str, Any]) -> None:
    """Decode CVSS vector abbreviations and add their values to ``target``."""
    for component in vector_string.split("/"):
        if ":" not in component:
            continue
        short_key, value = component.split(":", 1)
        key = VECTOR_KEY_TRANSLATION.get(short_key)
        if key is None:
            continue
        target[key] = VECTOR_VALUE_TRANSLATION.get(key, DEFAULT_VECTOR_VALUES).get(
            value, value
        )


def severity_for_score(score: float) -> str:
    """Return the CVSS severity label corresponding to a base score."""
    if score == 0:
        return "None"
    for breakpoint, severity in BASE_SEVERITY_BREAKPOINTS:
        if score < breakpoint:
            return severity
    raise ValueError(f"base score is outside the CVSS range: {score}")


def replace_missing_value(
    key: str, record: dict[str, Any], flattened: dict[str, Any]
) -> Any:
    """Return the configured replacement for a missing or empty field."""
    if key == "baseSeverity":
        score = flattened.get("baseScore")
        if score is not None and score not in EMPTY_VALUES:
            return severity_for_score(float(score))
    return MISSING_VALUE_REPLACEMENTS.get(key)


def normalize_string_values(record: dict[str, Any]) -> None:
    """Capitalize string columns and standardize attack-vector labels."""
    for column in STRING_COLUMNS:
        value = record[column]
        if isinstance(value, str):
            record[column] = value.capitalize()
    attack_vector = record["attackVector"]
    if isinstance(attack_vector, str):
        record["attackVector"] = ATTACK_VECTOR_REPLACEMENTS.get(attack_vector, attack_vector)


def normalize_record(data: dict[str, Any]) -> dict[str, Any]:
    """Flatten, rename, translate, and validate one CVE record."""
    flattened: dict[str, Any] = {}
    flatten_dict(data, flattened)
    for old_key, new_key in KEY_REPLACEMENTS.items():
        if old_key in flattened and new_key not in flattened:
            flattened[new_key] = flattened[old_key]

    record: dict[str, Any] = {}
    for key in COLUMNS:
        value = flattened.get(key)
        record[key] = (
            replace_missing_value(key, record, flattened)
            if value in EMPTY_VALUES
            else value
        )

    vector = flattened.get("vectorString")
    if vector not in EMPTY_VALUES:
        translate_vector(str(vector), record)
    normalize_string_values(record)

    for key, error_message in REQUIRED_FIELDS.items():
        if record[key] in EMPTY_VALUES:
            raise DroppedRecordError(error_message)
    record["baseScore"] = float(record["baseScore"])
    return record


def create_tables(connection: sqlite3.Connection) -> None:
    """Create the per-year tables with the shared CVE schema."""
    column_sql = ", ".join(
        f"{column} {'REAL' if column == 'baseScore' else 'TEXT'}"
        f"{' PRIMARY KEY' if column == 'cveId' else ''}"
        for column in COLUMNS
    )
    for year in YEARS:
        table = f"YEAR_{year}"
        connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute(f"CREATE TABLE {table} ({column_sql})")


def load_records(connection: sqlite3.Connection) -> list[tuple[str, str]]:
    """Load records into SQLite and return CVE IDs and validation errors."""
    dropped: list[tuple[str, str]] = []
    placeholders = ", ".join("?" for _ in COLUMNS)
    columns = ", ".join(COLUMNS)
    for path in DATA_DIRECTORY.rglob("*.json"):
        with path.open(encoding="utf-8") as file:
            source = json.load(file)
        cve_id = str(source.get("cveMetadata", {}).get("cveId", path.stem))
        try:
            record = normalize_record(source)
        except DroppedRecordError as error:
            dropped.append((cve_id, str(error)))
            continue
        year = path.parts[-3]
        values = [record[column] for column in COLUMNS]
        connection.execute(
            f"INSERT INTO YEAR_{year} ({columns}) VALUES ({placeholders})", values
        )
    return dropped


# DISABLED: writing dropped records to a CSV file
# def write_dropped_records(dropped: list[tuple[str, str]]) -> None:
#     """Write dropped CVE IDs and validation errors to ``dropped.csv``."""
#     with DROPPED_CSV_PATH.open("w", newline="", encoding="utf-8") as file:
#         writer = csv.writer(file)
#         writer.writerow(["cveId", "error"])
#         writer.writerows(dropped)


def main() -> None:
    """Build the SQLite database and log records excluded during normalization."""
    with sqlite3.connect(DATABASE_PATH) as connection:
        create_tables(connection)
        dropped = load_records(connection)
        connection.commit()

    print(f"Loaded CVE data into {DATABASE_PATH}")

    # EXTRA: Summarize the reasons for dropped records
    counts = Counter(item[1] for item in dropped)
    print("Dropped | Reason ")
    print("--------|--------")
    for error, count in counts.items():
        print(f"{count:<7} | {error}")
    
    # DISABLED: Write the dropped records to a CSV file
    # write_dropped_records(dropped)


if __name__ == "__main__":
    main()
