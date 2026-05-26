# Automation Lab

Structured validation pipeline for lab testing.

Standardises endpoint and network telemetry validation, Splunk ingestion confirmation, and artefact preservation for manual and Atomic Red Team executions.

---

## Purpose

Reduce repetitive analyst overhead while enforcing:

- Consistent validation criteria  
- Structured case artefacts  
- Evidence integrity controls  

Automation supports analysis – it does not replace it.

---

## Components

### Validate-Process.ps1
Windows endpoint validation.

- Queries Sysmon (Event ID 1) and Security (4688)
- Filters by process and time window
- Exports structured JSON
- Controlled exit codes

### run-validation.sh
Linux orchestration script.

- Executes remote validation via SSH  
- Retrieves artefacts via SCP  
- Creates timestamped case directories  
- Validates JSON structure (`jq`)  
- Generates SHA256 hashes  

---

## Case Structure

```
cases/<case_id>/
    metadata.txt
    orchestration.log
    evidence.hash
windows/
    process-validation.json
    splunk/
splunk-validation.csv
suricata-validation.csv
```

Each execution produces a reproducible, hashed case record.

---

## Scope

**Automated**
- Endpoint validation
- Network validation  
- Artefact retrieval  
- Schema checks  
- Integrity hashing  

**Manual (by design)**
- Splunk query review  
- Detection reasoning  
- Alert logic  

---

## Outcome

Reduces per-test workflow time from ~15 minutes to ~2 minutes while improving procedural consistency.


