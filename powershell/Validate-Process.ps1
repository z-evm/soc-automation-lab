# Validate-Process.ps1
# Version: 2.0
# Purpose: Validate process creation across Sysmon (Event ID 1) and Security (Event ID 4688)
# Author: Lab – SOC Validation Engine
# Mode: Interactive / Orchestrated
# Exit Codes:
#   0 = Process observed
#   1 = Query failure
#   2 = No relevant events found
#   3 = Process not observed
#   4 = Parameter misuse
#   5 = Export failure

param (
    # Target process name (string match against Image/NewProcess fields)
    # Example: powershell.exe
    [Parameter(Mandatory=$true)]
    [string]$ProcessName,

    # Defines rolling validation window.
    # Script calculates StartTime = Now - MinutesBack.
    # Keeps validation deterministic and bounded.
    [int]$MinutesBack = 10,

    # Controls which log source(s) are queried.
    # Prevents invalid values via ValidateSet.
    [ValidateSet("Sysmon","Security","Both")]
    [string]$LogSource = "Both",

    # Suppresses console output for orchestration mode.
    # Orchestrator expects clean output.
    [switch]$Quiet,

    # Explicit JSON export path (manual mode).
    # Mutually exclusive with -ExportEvidence.
    [string]$ExportJson,

    # Structured evidence mode.
    # Creates time-stamped directory structure automatically.
    [switch]$ExportEvidence
)

############################################
# PHASE 1 — PARAMETER VALIDATION
############################################

# Prevents ambiguous export behaviour.
# Ensures deterministic execution path.
if ($ExportEvidence -and $ExportJson) {
    Write-Host "ERROR: Use either -ExportJson or -ExportEvidence, not both."
    exit 4
}

if ($MinutesBack -le 0 -or $MinutesBack -gt 120) {
    Write-Error "MinutesBack must be between 1 and 120."
    exit 1
}

try {
    $StartTime = (Get-Date).AddMinutes(-$MinutesBack)

    $Events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1
        StartTime = $StartTime
    } -ErrorAction Stop

    if (-not $Events) {
        Write-Warning "No Sysmon ID 1 events found."
        exit 2
    }

    $Normalized = $Events | Select-Object TimeCreated,
        @{Name="Image";Expression={$_.Properties[5].Value}},
        @{Name="CommandLine";Expression={$_.Properties[10].Value}}

    $Normalized | ConvertTo-Json -Depth 3 | Out-File "process-validation.json"

    exit 0
}
catch {
    Write-Error "Query failed: $_"
    exit 1
}

############################################
# PHASE 2 — INITIALISATION
############################################

# Establish rolling time boundary.
# Ensures validation does not scan entire log history.
$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

# Boolean flags used later to determine exit code.
$SysmonFound = $false
$SecurityFound = $false

# Containers for filtered events.
$Filtered = @()
$FilteredSecurity = @()

# Interactive header only shown when not orchestrated.
# Prevents noisy output when called via SSH.
if (-not $Quiet) {
    Write-Host "========================================"
    Write-Host "Process Validation Engine"
    Write-Host "Process: $ProcessName"
    Write-Host "Time Window: Last $MinutesBack Minutes"
    Write-Host "Log Source: $LogSource"
    Write-Host "Execution Mode: $(if ($Quiet) { 'Orchestrated' } else { 'Interactive' })"
    Write-Host "========================================"
}

############################################
# PHASE 3 — SYSMON VALIDATION
############################################

# Only execute if Sysmon included in selected scope.
if ($LogSource -eq "Sysmon" -or $LogSource -eq "Both") {

    # FilterHashtable is significantly faster than piping entire log.
    # Queries only Event ID 1 (Process Creation).
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 1
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    # Sysmon Event ID 1 structure:
    # Properties[] indices map to specific fields.
    # Index 4 = Image
    # This is implicit knowledge and tightly coupled to the schema.
    $Filtered = $Events | Where-Object {
        $_.Properties[4].Value -like "*$ProcessName*"
    }

    if ($Filtered.Count -gt 0) {
        $SysmonFound = $true
    }

    # Interactive-only structured table output.
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "Sysmon Validation"
        Write-Host "------------------"
        Write-Host "Filtered Count: $($Filtered.Count)"

        # Explicit property extraction avoids exposing raw XML blob.
        $Filtered | Select-Object `
        TimeCreated,
        @{Name="Image";Expression={$_.Properties[4].Value}},
        @{Name="CommandLine";Expression={$_.Properties[10].Value}},
        @{Name="User";Expression={$_.Properties[12].Value}},
        @{Name="ParentImage";Expression={$_.Properties[20].Value}} |
        Format-Table -AutoSize
    }
}

############################################
# PHASE 4 — SECURITY 4688 VALIDATION
############################################

if ($LogSource -eq "Security" -or $LogSource -eq "Both") {

    # Security 4688 is noisier and its schema differs from Sysmon.
    # Cannot safely rely on Properties[] index order.
    $SecurityEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    # Convert event XML explicitly to extract named fields.
    # Safer and more readable than index-based extraction.
    $NormalizedSecurity = $SecurityEvents | ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            # Force UTC normalisation for SIEM consistency.
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            NewProcess  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" }).'#text'
            User        = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
            Parent      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessName" }).'#text'
        }
    }

    # Filter after normalisation.
    # Prevents repeated XML parsing.
    $FilteredSecurity = $NormalizedSecurity | Where-Object {
        $_.NewProcess -like "*$ProcessName*"
    }

    if ($FilteredSecurity.Count -gt 0) {
        $SecurityFound = $true
    }

    if(-not $Quiet) {
        Write-Host ""
        Write-Host "Security 4688 Validation"
        Write-Host "-------------------------"
        Write-Host "Filtered Count: $($FilteredSecurity.Count)"

        $FilteredSecurity | Format-Table -AutoSize
    }
}

############################################
# PHASE 5 — NORMALISATION
############################################

# Convert Sysmon raw event objects into structured objects.
# Ensures JSON output is schema-stable and predictable.
$NormalizedSysmon = $Filtered | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Image       = $_.Properties[4].Value
        CommandLine = $_.Properties[10].Value
        User        = $_.Properties[12].Value
        ParentImage = $_.Properties[20].Value
    }
}

# Security already normalised above.
$NormalizedSecurity = $FilteredSecurity

############################################
# PHASE 6 — RESULT OBJECT CONSTRUCTION
############################################

# Single structured object ensures:
# - Deterministic schema
# - Straightforward JSON export
# - Future extensibility
$ResultObject = [PSCustomObject]@{
    Metadata = @{
        Timestamp     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ProcessName   = $ProcessName
        MinutesBack   = $MinutesBack
        LogSource     = $LogSource
        Host          = $env:COMPUTERNAME
    }
    Summary = @{
        SysmonFound   = $SysmonFound
        SecurityFound = $SecurityFound
    }
    SysmonEvents   = $NormalizedSysmon
    SecurityEvents = $NormalizedSecurity
}

############################################
# PHASE 7 — EVIDENCE EXPORT PREPARATION
############################################

# Structured evidence mode builds deterministic folder hierarchy.
# Important for chain-of-custody discipline.
if ($ExportEvidence) {

    $timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
    $basePath = Join-Path -Path (Get-Location) -ChildPath "evidence"
    $processPath = Join-Path -Path $basePath -ChildPath $ProcessName
    $finalPath = Join-Path -Path $processPath -ChildPath $timestamp

    # -Force ensures idempotency if directory already exists.
    New-Item -ItemType Directory -Path $finalPath -Force | Out-Null

    $ExportJson = Join-Path -Path $finalPath -ChildPath "process-validation.json"
    $CreatedEvidencePath = $finalPath
}

############################################
# PHASE 8 — JSON EXPORT + HASHING
############################################

if ($ExportJson) {
    try {
        # Depth 5 ensures nested objects serialise correctly.
        $ResultObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportJson -Encoding UTF8

        # Hashing ensures integrity binding prior to orchestration retrieval.
        $hash = Get-FileHash $ExportJson -Algorithm SHA256

        if (-not $Quiet) {
            Write-Host "JSON evidence exported to: $ExportJson"
            Write-Host "Evidence SHA256: $($hash.Hash)"
        }
    }
    catch {
        Write-Host "ERROR: Failed to export JSON."
        exit 5
    }
}

############################################
# PHASE 9 — UNIFIED RESULT EVALUATION
############################################

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Validation Summary"
    Write-Host "------------------"
    Write-Host "Sysmon Found: $SysmonFound"
    Write-Host "Security Found: $SecurityFound"
}

# Default failure state.
$ExitCode = 3

# Unified success condition.
# Either source is sufficient to confirm process execution.
if ($SysmonFound -or $SecurityFound) {
    $ExitCode = 0
    if (-not $Quiet) {
        Write-Host "Overall Result: PROCESS OBSERVED"
    }
}
else {
    if (-not $Quiet) {
        Write-Host "Overall Result: PROCESS NOT OBSERVED"
    }
}

############################################
# PHASE 10 — ORCHESTRATION OUTPUT
############################################

# Critical orchestration behaviour:
# When called via SSH (Quiet + ExportEvidence),
# ONLY return evidence path.
# Prevents breaking parent bash parsing logic.
if ($ExportEvidence -and $Quiet -and $CreatedEvidencePath) {
    Write-Output $CreatedEvidencePath
}

exit $ExitCode