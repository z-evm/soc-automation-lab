# Validate-Process.ps1
# Version: 1.0
# Purpose: Validate process creation across Sysmon (Event ID 1) and Security (Event ID 4688)

param (
    [Parameter(Mandatory=$true)]
    [string]$ProcessName,

    [int]$MinutesBack = 10,

    [ValidateSet("Sysmon","Security","Both")]
    [string]$LogSource = "Both"
)

$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

$SysmonFound = $false
$SecurityFound = $false

Write-Host "========================================"
Write-Host "Process Validation Engine"
Write-Host "Process: $ProcessName"
Write-Host "Time Window: Last $MinutesBack Minutes"
Write-Host "Log Source: $LogSource"
Write-Host "========================================"

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
            TimeCreated = $_.TimeCreated
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

    Write-Host ""
    Write-Host "Security 4688 Validation"
    Write-Host "-------------------------"
    Write-Host "Filtered Count: $($FilteredSecurity.Count)"

    $FilteredSecurity | Format-Table -AutoSize
}

# -----------------------------
# UNIFIED RESULT
# -----------------------------
Write-Host ""
Write-Host "Validation Summary"
Write-Host "------------------"
Write-Host "Sysmon Found: $SysmonFound"
Write-Host "Security Found: $SecurityFound"

if ($SysmonFound -or $SecurityFound) {
    Write-Host "Overall Result: PROCESS OBSERVED"
    exit 0
}
else {
    Write-Host "Overall Result: PROCESS NOT OBSERVED"
    exit 3
}
