#!/bin/bash

PROCESS_NAME="$1"

if [ -z "$PROCESS_NAME" ]; then
    echo "Usage: ./run_validation.sh <process_name>"
    exit 1
fi

WINDOWS_HOST="Zach@10.0.0.20"

echo "[*] Triggering remote validation..."

REMOTE_PATH=$(ssh $WINDOWS_HOST \
'powershell -ExecutionPolicy Bypass -File "C:\Users\Zach\Desktop\Validate-Process.ps1" -ProcessName '"$PROCESS_NAME"' -ExportEvidence -Quiet' | tr -d '\r')

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 3 ]; then
    echo "[!] Remote execution failed"
    exit $EXIT_CODE
fi

echo "[*] Remote evidence path:"
printf '%s\n' "$REMOTE_PATH"

SCP_PATH="/${REMOTE_PATH//\\//}"

CASE_DIR="case_$(date -u +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$CASE_DIR"

echo "[*] Pulling evidence..."
scp -r $WINDOWS_HOST:"$SCP_PATH" "$CASE_DIR/"

echo "[*] Done."
echo "[*] Validation exit code: $EXIT_CODE"

exit $EXIT_CODE
