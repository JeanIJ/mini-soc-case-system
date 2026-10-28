import requests
import os
from enum import Enum
from datetime import datetime

API_URL = "https://my.api.mockaroo.com/ironclad-soc-case-artifacts"
API_KEY = os.environ.get("MOCKAROO_API_KEY", "").strip()
if not API_KEY:
    raise SystemExit(
        "Error: MOCKAROO_API_KEY is not set. "
        "Export it before running this script."
    )
headers = {"X-API-Key": API_KEY}

response = requests.get(API_URL, headers=headers, timeout=10)
print("Status:", response.status_code)

if response.status_code != 200:
    print("Request failed:", response.text[:200])
    raise SystemExit

data = response.json()
print("JSON type:", type(data))
print("Records:", len(data) if isinstance(data, list) else "N/A")

if isinstance(data, list) and data:
    print("First record preview:")
    print(data[0])
else:
    print("Unexpected JSON structure. Expected a list of records.")
    raise SystemExit

if isinstance(data[0], dict):
    print("Fields in record:")
    for k in data[0].keys():
        print(" -", k)

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class CaseStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class ArtifactType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    FILE_HASH = "file_hash"
    SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"

class Artifact:
    def __init__(self, raw: dict):
        self.raw = raw
        self.case_id = raw.get("case_id", "UNKNOWN_CASE")
        self.artifact_type = raw.get("indicator_type", "unknown")
        self.value = raw.get(self.artifact_type, "")
        self.note = raw.get("comment", "")
        self.timestamp = raw.get("timestamp", "")
        self.source = raw.get("source", "")
        type_str = self.artifact_type.lower()
        try:
            self.type_enum = ArtifactType(type_str)
        except ValueError:
            self.type_enum = ArtifactType.UNKNOWN

    def is_internal_ip(self) -> bool:
        if self.type_enum != ArtifactType.IP:
            return False
        return self.value.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                       "172.18.", "172.19.", "172.20.", "172.21.",
                                       "172.22.", "172.23.", "172.24.", "172.25.",
                                       "172.26.", "172.27.", "172.28.", "172.29.",
                                       "172.30.", "172.31.", "127."))

    def __str__(self) -> str:
        extra = f" ({self.note})" if self.note else ""
        return f"{self.artifact_type}: {self.value}{extra}"

class Case:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.status = CaseStatus.NEW
        self.severity = Severity.LOW
        self.artifacts: list[Artifact] = []
        self.notes: list[str] = []

    def add_artifact(self, artifact: Artifact):
        self.artifacts.append(artifact)
        self.recalculate_severity()

    def add_note(self, note: str):
        self.notes.append(note)

    def recalculate_severity(self):
        has_hash = any(
            a.artifact_type in ["file_hash", "hash", "sha256"]
            for a in self.artifacts
        )
        if has_hash:
            self.severity = Severity.HIGH
            return

        has_external_ip = any(
            a.artifact_type == "ip" and not a.is_internal_ip()
            for a in self.artifacts
        )
        has_suspicious_domain = any(
            a.artifact_type == "domain"
            and any(word in a.value.lower() for word in ["login", "verify", "secure"])
            for a in self.artifacts
        )

        if has_external_ip or has_suspicious_domain:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW

    def close(self, resolution: CaseStatus):
        if self.severity == Severity.HIGH and self.status != CaseStatus.INVESTIGATING:
            self.status = CaseStatus.INVESTIGATING
            self.notes.append("Escalated to INVESTIGATING - HIGH severity case cannot be closed directly.")
            print(f"[!] Case {self.case_id}: HIGH severity -> status set to INVESTIGATING before closing.")
            return False
        if resolution in (CaseStatus.RESOLVED, CaseStatus.FALSE_POSITIVE):
            self.status = resolution
            self.notes.append(f"Case closed as {resolution.value}.")
            return True
        self.status = resolution
        return True

    def get_iocs(self) -> list[str]:
        ioc_types = {"ip", "domain", "hash", "file_hash", "sha256"}
        seen = set()
        iocs = []
        for a in self.artifacts:
            if a.artifact_type in ioc_types and a.value not in seen:
                seen.add(a.value)
                iocs.append(a.value)
        return iocs

    def days_old(self) -> int | None:
        dates = []
        for a in self.artifacts:
            if a.timestamp:
                try:
                    dates.append(datetime.fromisoformat(a.timestamp.replace("Z", "+00:00")))
                except Exception:
                    pass
        if not dates:
            return None
        oldest = min(dates)
        return (datetime.now().astimezone() - oldest).days

    def summary(self) -> str:
        return f"{self.case_id} | {self.status.value} | {self.severity.value} | artifacts={len(self.artifacts)}"

    def __str__(self) -> str:
        lines = [self.summary(), "-" * 48, "Artifacts:"]
        for a in self.artifacts:
            lines.append(f"  - {a}")
        if self.notes:
            lines.append("Notes:")
            for n in self.notes:
                lines.append(f"  * {n}")
        iocs = self.get_iocs()
        if iocs:
            lines.append("IOCs:")
            for ioc in iocs:
                lines.append(f"  -> {ioc}")
        age = self.days_old()
        if age is not None:
            lines.append(f"Age: {age} day(s) since oldest artifact")
        return "\n".join(lines)

cases_by_id = {}

for record in data:
    artifact = Artifact(record)
    if artifact.case_id not in cases_by_id:
        cases_by_id[artifact.case_id] = Case(artifact.case_id)
    cases_by_id[artifact.case_id].add_artifact(artifact)

print("=== Case Summaries ===")
for c in cases_by_id.values():
    print(c.summary())

severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
sorted_cases = sorted(cases_by_id.values(), key=lambda c: severity_order.get(c.severity, 3))
print("=== Cases Sorted by Severity (HIGH -> MEDIUM -> LOW) ===")
for c in sorted_cases:
    print(c.summary())

with open("case_report.txt", "w", encoding="utf-8") as out:
    for c in cases_by_id.values():
        out.write(str(c))
        out.write("\n\n")

print("Wrote report to case_report.txt")