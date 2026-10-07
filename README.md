# Overview

`gather.py` reads the JSON records under `cves/` and builds `database.sqlite`. Run it with `python main.py`. Records that cannot be inserted raise a validation error; the CVE ID and error message are written to `dropped.csv`. The database has one table for each year, named `YEAR_2022`, `YEAR_2023`, `YEAR_2024`, and `YEAR_2025`. Each table uses `cveId` as its primary key and has the same 16 columns.

String columns are normalized with Python's `.capitalize()` behavior. `Adjacent` and `Adjacent Network` attack-vector values are both stored as `Adjacent`.

## Setup
No `requirements.txt` so no need for any python venv setup
```bash
# python3 -m venv .venv
# source .venv/bin/activate
# python -m pip install --upgrade pip
# python -m pip install -r requirements.txt
```

Setup Sqlite Database
```bash
python gather.py    # Creates database.sqlite
```

## CVE Data Database
| Column | Meaning relative to the CVE JSON | Nulls in current database | Missing-data handling | Comment |
| --- | --- | ---: | --- | --- |
| `cveId` | `cveMetadata.cveId` | 0 | **Convert:** missing values become SQL `NULL`; no surviving record has one. | `(idType) (categorical)` Primary key and unique CVE identifier. |
| `dataVersion` | Top-level `dataVersion` | 0 | **Always**: Based on date published to CVES | `(data) (categorical)` JSON schema version, such as `5.1` or `5.2`. |
| `datePublished` | `cveMetadata.datePublished` | 0 | **Drop:** rows with a missing or empty publication date raise an error and are logged in `dropped.csv`. | `(date) (categorical)` ISO-8601 date/time text used for year/month analysis. |
| `product` | `containers.*.affected[].product` (where a flattened `product` key is found) | 11,623 | **Still there:** missing or recognized empty values, including `n/a`, are stored as SQL `NULL`. | `(data) (categorical)` Affected product text; in multiple languages; may have to verify with vendor column. |
| `vendor` | `containers.*.affected[].vendor` (where a flattened `vendor` key is found) | 14,848 | **Still there:** missing or recognized empty values, including `n/a`, are stored as SQL `NULL`. | `(data) (categorical)` Affected vendor text; may have multiple products. `NULL` usually have no product (product is `NULL`) |
| `cweId` | A JSON `cweId` field when present, generally from the CVE problem-type data | 10,165 | **Still there:** missing or recognized empty values are stored as SQL `NULL`. | `(data) (categorical)` CWE weakness identifier, such as `CWE-79`. |
| `attackComplexity` | CVSS `attackComplexity`, or `AC` decoded from `vectorString` | 0 | **Convert:** missing values default to `NONE`; a non-null CVSS vector can replace the default. | `(data) (categorical)` CVSS metric; normally `LOW` or `HIGH`. |
| `attackVector` | CVSS `attackVector`, or `AV` decoded from `vectorString` | 0 | **Convert:** missing values default to `NONE`; a non-null CVSS vector can replace the default. | `(data) (categorical)` CVSS metric; `N`, `A`, `L`, and `P` decode to `NETWORK`, `ADJACENT`, `LOCAL`, and `PHYSICAL`. |
| `availabilityImpact` | CVSS `availabilityImpact`, or `A`/`SA` decoded from `vectorString`; older records may use `subAvailabilityImpact` | 0 | **Convert:** missing values default to `NONE`; a vector can replace the default, and `subAvailabilityImpact` is renamed to this column. | `(data) (categorical)` CVSS impact metric. |
| `baseScore` | CVSS `baseScore` | 0 | **Drop:** rows with a missing or empty base score raise an error and are logged in `dropped.csv`. | `(data) (numerical)` CVSS score stored as SQLite `REAL`; summarizes vector severity. |
| `baseSeverity` | CVSS `baseSeverity` | 0 | **Convert:** if absent but `baseScore` exists, derive `NONE`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` from the score; otherwise convert to SQL `NULL`. | `(data) (categorical)` Severity summary of `baseScore`, not an independent measurement. |
| `confidentialityImpact` | CVSS `confidentialityImpact`, or `C`/`SC` decoded from `vectorString`; older records may use `subConfidentialityImpact` | 0 | **Convert:** missing values default to `NONE`; a vector can replace the default, and `subConfidentialityImpact` is renamed to this column. | `(data) (categorical)` CVSS impact metric. |
| `integrityImpact` | CVSS `integrityImpact`, or `I`/`SI` decoded from `vectorString`; older records may use `subIntegrityImpact` | 0 | **Convert:** missing values default to `NONE`; a vector can replace the default, and `subIntegrityImpact` is renamed to this column. | `(data) (categorical)` CVSS impact metric. |
| `privilegesRequired` | CVSS `privilegesRequired`, or `PR` decoded from `vectorString` | 0 | **Convert:** missing values default to `NONE`; a non-null CVSS vector can replace the default. | `(data) (categorical)` CVSS metric. |
| `scope` | CVSS `scope`, or `S` decoded from `vectorString` | 0 | **Convert:** missing values default to `UNCHANGED`; a non-null CVSS vector can replace the default. | `(data) (categorical)` CVSS metric for crossing a security authority boundary. |
| `userInteraction` | CVSS `userInteraction`, or `UI` decoded from `vectorString` | 0 | **Convert:** missing values default to `NONE`; a non-null CVSS vector can replace the default. | `(data) (categorical)` CVSS metric; `N`, `R`, `P`, and `A` decode to `NONE`, `REQUIRED`, `PASSIVE`, and `ACTIVE`. |
