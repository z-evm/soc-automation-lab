# Validate-Sysmon.ps1
# Version: 0.3
# Purpose: Validate Sysmon Event ID 1 within last 10 minutes and filter by process name

$TargetProcess = "notepad.exe"  # Change per test
$StartTime = (Get-Date).AddMinutes(-10)

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# Filter by Image field (index 4 in your environment)
$Filtered = $Events | Where-Object {
    $_.Properties[4].Value -like "*$TargetProcess*"
}

Write-Host "----------------------------------------"
Write-Host "Sysmon Event ID 1 Validation"
Write-Host "Time Window: Last 10 Minutes"
Write-Host "Total Event Count: $($Events.Count)"
Write-Host "Filtered Count ($TargetProcess): $($Filtered.Count)"
Write-Host "----------------------------------------"

$Filtered | Select-Object `
    TimeCreated,
    @{Name="Image";Expression={$_.Properties[4].Value}},
    @{Name="CommandLine";Expression={$_.Properties[10].Value}},
    @{Name="User";Expression={$_.Properties[12].Value}},
    @{Name="ParentImage";Expression={$_.Properties[20].Value}} |
    Format-Table -AutoSize
