# Validate-Sysmon.ps1
# Version: 0.4
# Purpose: Validate Sysmon Event ID 1 within last 10 minutes and filter by process name

param (
    [string]$ProcessName,
    [int]$MinutesBack = 10
)

if (-not $ProcessName) {
    Write-Host "ERROR: You must provide -ProcessName"
    exit
}

$StartTime = (Get-Date).AddMinutes(-$MinutesBack)

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# Filter by Image field
$Filtered = $Events | Where-Object {
    $_.Properties[4].Value -like "*$ProcessName*"
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

if (-not $Events) {
    Write-Host "No Sysmon Event ID 1 events found in time window."
    exit 1
}

if ($Filtered.Count -eq 0) {
    Write-Host "Process '$ProcessName' NOT FOUND in time window."
    exit 2
}

Write-Host "Process '$ProcessName' FOUND in time window."

# Retrieve Security 4688 events
$SecurityEvents = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4688
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$FilteredSecurity = $SecurityEvents | Where-Object {
    $xml = [xml]$_.ToXml()
    ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" }).'#text' -like "*$ProcessName*"
}

Write-Host ""
Write-Host "Security Log (4688) Validation"
Write-Host "Total Security Events: $($SecurityEvents.Count)"
Write-Host "Filtered Security Count: $($FilteredSecurity.Count)"
Write-Host "----------------------------------------"

$FilteredSecurity | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        NewProcess  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" }).'#text'
        User        = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        Parent      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessName" }).'#text'
    }
} | Format-Table -AutoSize
