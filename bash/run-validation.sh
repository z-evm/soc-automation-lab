#!/bin/bash
# run-validation.sh
# Version: 0.6

set -euo pipefail
IFS=$'\n\t'

############################################
# Argument Handling
############################################

if [ $# -lt 1 ]; then
    echo "Usage: ./run_validation.sh <process_name> [case_id]"
    exit 1
fi

PROCESS_NAME="$1"
CASE_ID="${2:-$(date -u +%Y%m%d_%H%M%S)}"

############################################
# Configuration
############################################

WINDOWS_HOST="Zach@10.0.0.20"
WINDOWS_SCRIPT_PATH='C:\Users\Zach\Desktop\Validate-Process.ps1'

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=5
)

BASE_DIR="cases"
CASE_DIR="$BASE_DIR/$CASE_ID"
WINDOWS_DIR="$CASE_DIR/windows"
LOG_FILE="$CASE_DIR/orchestration.log"

############################################
# Case Initialization
############################################

if [ -d "$CASE_DIR" ]; then
    echo "[!] Case directory already exists: $CASE_DIR"
    echo "[!] Refusing to overwrite existing case."
    exit 10
fi

mkdir -p "$WINDOWS_DIR"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

log "=== CASE START ==="
log "Case ID: $CASE_ID"
log "Process Name: $PROCESS_NAME"
log "Target Host: $WINDOWS_HOST"
log "Executed From: $(hostname)"
log "User: $(whoami)"

############################################
# Metadata (Chain of Custody)
############################################

cat <<EOF > "$CASE_DIR/metadata.txt"
Case ID: $CASE_ID
Process: $PROCESS_NAME
Target Host: 10.0.0.20
Executed From: $(hostname)
User: $(whoami)
Timestamp (UTC): $(date -u -Iseconds)
EOF

############################################
# Remote Validation Execution
############################################

log "Triggering remote validation..."

REMOTE_COMMAND="powershell -ExecutionPolicy Bypass -File \"$WINDOWS_SCRIPT_PATH\" -ProcessName \"$PROCESS_NAME\" -ExportEvidence -Quiet"

set +e
REMOTE_PATH=$(ssh "${SSH_OPTS[@]}" "$WINDOWS_HOST" "$REMOTE_COMMAND" 2>/dev/null | tr -d '\r' | tail -n 1)
EXIT_CODE=$?
set -e

log "Remote exit code: $EXIT_CODE"

if [ "$EXIT_CODE" -ne 0 ]; then
    log "Remote validation failed. Output:"
    log "$REMOTE_PATH"
    exit $EXIT_CODE
fi

if [ -z "$REMOTE_PATH" ]; then
    log "No evidence path returned from remote script."
    exit 2
fi

log "Remote evidence path: $REMOTE_PATH"

############################################
# Evidence Retrieval
############################################

# Convert Windows path to SCP-compatible path
SCP_PATH="/${REMOTE_PATH//\\//}"

log "Pulling evidence via SCP..."

set +e
scp "${SSH_OPTS[@]}" -r "$WINDOWS_HOST":"$SCP_PATH"/* "$WINDOWS_DIR" >> "$LOG_FILE" 2>&1
SCP_EXIT=$?
set -e

if [ "$SCP_EXIT" -ne 0 ]; then
    log "SCP failed with exit code $SCP_EXIT"
    exit 5
fi

log "Evidence successfully retrieved."

SPLUNK_DIR="$CASE_DIR/splunk"
mkdir -p "$SPLUNK_DIR"

############################################
# Evidence Validation
############################################

if [ -z "$(ls -A "$WINDOWS_DIR")" ]; then
    log "Evidence directory is empty after SCP."
    exit 6
fi

log "Evidence files present:"
ls -1 "$WINDOWS_DIR" | tee -a "$LOG_FILE"

JSON_FILE="$WINDOWS_DIR/process-validation.json"

if ! command -v jq >/dev/null 2>&1; then
    log "jq not installed. Cannot validate JSON."
    exit 20
fi

log "Validating JSON schema..."

jq -e '
  .Metadata.Timestamp and
  .Metadata.ProcessName and
  .Metadata.MinutesBack and
  .Metadata.LogSource and
  .Metadata.Host and
  .Summary.SysmonFound != null and
  .Summary.SecurityFound != null and
  (.SysmonEvents | type == "array") and
  (.SecurityEvents | type == "array")
' "$JSON_FILE" > /dev/null

if [ $? -ne 0 ]; then
    log "JSON schema validation failed."
    exit 21
fi

log "JSON schema validation passed."

############################################
# Evidence Hashing
############################################

log "Generating SHA256 hashes..."

(
  cd "$CASE_DIR"
  find windows -type f -print0 | while IFS= read -r -d '' file; do
      sha256sum "$file"
  done
) > "$CASE_DIR/evidence.hash"

log "Hashes written to evidence.hash"

############################################
# Completion
############################################

log "=== CASE COMPLETE ==="
log "Final exit code: $EXIT_CODE"

exit $EXIT_CODE
