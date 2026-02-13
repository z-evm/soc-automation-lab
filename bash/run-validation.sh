#!/bin/bash
# run-validation.sh
# Version: 0.3

PROCESS_NAME="$1"

if [ -z "$PROCESS_NAME" ]; then
    echo "Usage: ./run_validation.sh <process_name>"
    exit 1
fi

WINDOWS_HOST="Zach@10.0.0.20"

CASE_TIMESTAMP=$(date -u +%Y-%m-%d_%H-%M-%S)
CASE_DIR="case_$CASE_TIMESTAMP"
WINDOWS_DIR="$CASE_DIR/windows"

mkdir -p "$WINDOWS_DIR"

echo "[*] Triggering remote validation..."

REMOTE_PATH=$(ssh $WINDOWS_HOST \
'powershell -ExecutionPolicy Bypass -File "C:\Users\Zach\Desktop\Validate-Process.ps1" -ProcessName '"$PROCESS_NAME"' -ExportEvidence -Quiet' | tr -d '\r')

EXIT_CODE=$?

if [ -z "$REMOTE_PATH" ]; then
    echo "[!] No evidence path returned"
    exit 2
fi

echo "[*] Remote evidence path:"
printf '%s\n' "$REMOTE_PATH"

SCP_PATH="/${REMOTE_PATH//\\//}"

echo "[*] Pulling evidence..."
scp -r $WINDOWS_HOST:"$SCP_PATH"/* "$WINDOWS_DIR"

if [ $? -ne 0 ]; then
    echo "[!] SCP failed"
    exit 5
fi

echo "[*] Done."
echo "[*] Validation exit code: $EXIT_CODE"

exit $EXIT_CODE
