#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Regression checks for quarantine release alert scheduling.

.DESCRIPTION
    These tests intentionally inspect the source because the scheduler depends on
    Azure Table and Durable Functions runtime state. They protect the behavior
    involved in the quarantine release alert failure mode:
    - the alert polls release requests, not every quarantined message
    - the requested-release queue uses a broad enough lookback for pending work
    - recurring failed scheduled tasks are eligible to run again
#>

[CmdletBinding()]
param()

$pass = 0
$fail = 0

function Assert-SourceContains {
    param(
        [string]$Label,
        [string]$Source,
        [string]$Pattern
    )

    if ($Source -match $Pattern) {
        Write-Host "  [PASS] $Label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $Label" -ForegroundColor Red
        Write-Host "         Missing pattern: $Pattern"
        $script:fail++
    }
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$AlertPath = Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertQuarantineReleaseRequests.ps1'
$SchedulerPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Entrypoints/Orchestrator Functions/Start-UserTasksOrchestrator.ps1'

if (-not (Test-Path $AlertPath)) {
    Write-Error "Alert source not found at: $AlertPath"
    exit 1
}

if (-not (Test-Path $SchedulerPath)) {
    Write-Error "Scheduler source not found at: $SchedulerPath"
    exit 1
}

$AlertSource = Get-Content -Raw -Path $AlertPath
$SchedulerSource = Get-Content -Raw -Path $SchedulerPath

Write-Host "`n=== Quarantine Alert Behavior ===" -ForegroundColor Cyan
Assert-SourceContains 'Quarantine alert checks only requested releases' $AlertSource "ReleaseStatus\s*=\s*'Requested'"
Assert-SourceContains 'Quarantine alert queries Get-QuarantineMessage' $AlertSource "-cmdlet\s+'Get-QuarantineMessage'"
Assert-SourceContains 'Quarantine alert defaults to a 30 day requested-release queue' $AlertSource '\$LookbackDays\s*=\s*30'
Assert-SourceContains 'Quarantine alert uses a lookback window' $AlertSource 'StartReceivedDate\s*=\s*\(Get-Date\)\.AddDays\(-\$LookbackDays\)'
Assert-SourceContains 'Quarantine alert emits an empty queue state when requests clear' $AlertSource "QueueStatus\s*=\s*'Empty'"

Write-Host "`n=== Scheduler Recovery Behavior ===" -ForegroundColor Cyan
Assert-SourceContains 'Recurring Failed tasks are included in scheduler pickup filter' $SchedulerSource "TaskState eq 'Failed' and Recurrence ne '0' and Recurrence ne ''"
Assert-SourceContains 'Scheduler setup failures preserve recurring tasks as Failed - Planned' $SchedulerSource '\$State\s*=\s+''Failed - Planned'''
Assert-SourceContains 'Scheduler setup failures advance the next scheduled time' $SchedulerSource '\$ScheduledTime\s*=\s+\[string\]\(\[int64\]\$task\.ScheduledTime \+ \[int64\]\$secondsToAdd\)'

Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "  Passed: $pass" -ForegroundColor Green
Write-Host "  Failed: $fail" -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })

if ($fail -gt 0) { exit 1 }
