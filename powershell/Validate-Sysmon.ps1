# Validate-Sysmon.ps1
# Version: 0.1
# Purpose: Basic validation of Sysmon Event ID 1 within last 10 minutes

$StartTime = (Get-Date).AddMinutes(-10)

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $StartTime
}

$Count = $Events.Count

Write-Host "----------------------------------------"
Write-Host "Sysmon Event ID 1 Validation"
Write-Host "Time Window: Last 10 Minutes"
Write-Host "Event Count: $Count"
Write-Host "----------------------------------------"
