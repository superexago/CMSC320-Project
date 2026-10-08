import json
import pathlib

from gather import *

# CONFIG
CVE_ID = "CVE-2025-4037"

# Code
record = {}

# Get the path to the CVE JSON file based on the CVE ID and year
year = CVE_ID.split("-")[1]
folder = CVE_ID.split("-")[-1][:-3]
pathname = f"cves/{year}/{folder}xxx/{CVE_ID}.json"
path = pathlib.Path(pathname)

# Load the CVE JSON file and normalize the record
with path.open(encoding="utf-8") as file:
    source = json.load(file)
cve_id = str(source.get("cveMetadata", {}).get("cveId", path.stem))
try:
    record = normalize_record(source)
except DroppedRecordError as error:
    print(f"Error occurred while processing {cve_id}: {error}")

# Print the normalized record
print(f"Normalized record for {cve_id}\n: {record}")