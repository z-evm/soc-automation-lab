# Validate-Process.ps1
# Version: 1.6
# Purpose: Validate process creation across Sysmon (Event ID 1) and Security (Event ID 4688)

param (
    [Parameter(Mandatory=$true)]
    [string]$ProcessName,

    [int]$MinutesBack = 10,

    [ValidateSet("Sysmon","Security","Both")]
    [string]$LogSource = "Both",

    [switch]$Quiet,

    [string]$ExportJson,

    [switch]$ExportEvidence
)

if ($ExportEvidence -and $ExportJson) {
    Write-Host "ERROR: Use either -ExportJson or -ExportEvidence, not both."
    exit 4
}

$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

$SysmonFound = $false
$SecurityFound = $false

$Filtered = @()
$FilteredSecurity = @()

if (-not $Quiet) {
    Write-Host "========================================"
    Write-Host "Process Validation Engine"
    Write-Host "Process: $ProcessName"
    Write-Host "Time Window: Last $MinutesBack Minutes"
    Write-Host "Log Source: $LogSource"
    Write-Host "========================================"
}

# -----------------------------
# SYS MON VALIDATION
# -----------------------------
if ($LogSource -eq "Sysmon" -or $LogSource -eq "Both") {

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 1
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    $Filtered = $Events | Where-Object {
        $_.Properties[4].Value -like "*$ProcessName*"
    }

    if ($Filtered.Count -gt 0) {
        $SysmonFound = $true
    }

    if (-not $Quiet) {
        Write-Host ""
        Write-Host "Sysmon Validation"
        Write-Host "------------------"
        Write-Host "Filtered Count: $($Filtered.Count)"

        $Filtered | Select-Object `
        TimeCreated,
        @{Name="Image";Expression={$_.Properties[4].Value}},
        @{Name="CommandLine";Expression={$_.Properties[10].Value}},
        @{Name="User";Expression={$_.Properties[12].Value}},
        @{Name="ParentImage";Expression={$_.Properties[20].Value}} |
        Format-Table -AutoSize
    }
}

# -----------------------------
# SECURITY 4688 VALIDATION
# -----------------------------
if ($LogSource -eq "Security" -or $LogSource -eq "Both") {

    $SecurityEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    # Normalize once
    $NormalizedSecurity = $SecurityEvents | ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            NewProcess  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" }).'#text'
            User        = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
            Parent      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessName" }).'#text'
        }
    }

    # Filter after normalization
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

$NormalizedSysmon = $Filtered | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Image       = $_.Properties[4].Value
        CommandLine = $_.Properties[10].Value
        User        = $_.Properties[12].Value
        ParentImage = $_.Properties[20].Value
    }
}

$NormalizedSecurity = $FilteredSecurity

$ResultObject = [PSCustomObject]@{
    Metadata = @{
        Timestamp     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ProcessName   = $ProcessName
        MinutesBack   = $MinutesBack
        LogSource     = $LogSource
    }
    Summary = @{
        SysmonFound   = $SysmonFound
        SecurityFound = $SecurityFound
    }
    SysmonEvents   = $NormalizedSysmon
    SecurityEvents = $NormalizedSecurity
}

if ($ExportEvidence) {

    $timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
    $basePath = Join-Path -Path (Get-Location) -ChildPath "evidence"
    $processPath = Join-Path -Path $basePath -ChildPath $ProcessName
    $finalPath = Join-Path -Path $processPath -ChildPath $timestamp

    New-Item -ItemType Directory -Path $finalPath -Force | Out-Null

    $ExportJson = Join-Path -Path $finalPath -ChildPath "process-validation.json"

    $CreatedEvidencePath = $finalPath
}


if ($ExportJson) {
    try {
        $ResultObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportJson -Encoding UTF8
        $hash = Get-FileHash $ExportJson -Algorithm SHA256

        if (-not $Quiet) {
            Write-Host "JSON evidence exported to: $ExportJson"
            Write-Host "Evidence SHA256: $($hash.Hash)"
        }
    }
    catch {
        Write-Host "ERROR: Failed to export JSON."
    }
}

# -----------------------------
# UNIFIED RESULT
# -----------------------------
if (-not $Quiet) {
    Write-Host ""
    Write-Host "Validation Summary"
    Write-Host "------------------"
    Write-Host "Sysmon Found: $SysmonFound"
    Write-Host "Security Found: $SecurityFound"
}

$ExitCode = 3
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

# If running orchestration mode (ExportEvidence + Quiet),
# return only the created evidence path
if ($ExportEvidence -and $Quiet -and $CreatedEvidencePath) {
    Write-Output $CreatedEvidencePath
}

exit $ExitCode

