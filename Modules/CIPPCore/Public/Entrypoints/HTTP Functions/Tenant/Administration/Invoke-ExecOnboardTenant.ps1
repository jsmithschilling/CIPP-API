function Invoke-ExecOnboardTenant {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Tenant.Administration.ReadWrite
    #>
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers


    # Interact with query parameters or the body of the request.
    $Id = $Request.Body.id
    if ($Id) {
        try {
            $OnboardTable = Get-CIPPTable -TableName 'TenantOnboarding'
            $SafeId = ConvertTo-CIPPODataFilterValue -Value $Id -Type String
            if ($Request.Body.Cancel -eq $true) {
                $TenantOnboarding = Get-CIPPAzDataTableEntity @OnboardTable -Filter "RowKey eq '$SafeId'"
                if ($TenantOnboarding) {
                    Remove-AzDataTableEntity -Force @OnboardTable -Entity $TenantOnboarding
                    $Results = @{'Results' = 'Onboarding job canceled' }
                    $StatusCode = [HttpStatusCode]::OK
                } else {
                    $Results = 'Onboarding job not found'
                    $StatusCode = [HttpStatusCode]::NotFound
                }
            } else {
                $TenMinutesAgo = (Get-Date).AddMinutes(-10).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $TenantOnboarding = Get-CIPPAzDataTableEntity @OnboardTable -Filter "RowKey eq '$SafeId' and Timestamp ge datetime'$TenMinutesAgo'"
                if (!$TenantOnboarding -or [bool]$Request.Body.Retry) {
                    $OnboardingSteps = [PSCustomObject]@{
                        'Step1' = @{
                            'Status'  = 'pending'
                            'Title'   = 'Step 1: GDAP Invite'
                            'Message' = 'Waiting for onboarding job to start'
                        }
                        'Step2' = @{
                            'Status'  = 'pending'
                            'Title'   = 'Step 2: GDAP Role Test'
                            'Message' = 'Waiting for Step 1'
                        }
                        'Step3' = @{
                            'Status'  = 'pending'
                            'Title'   = 'Step 3: GDAP Group Mapping'
                            'Message' = 'Waiting for Step 2'
                        }
                        'Step4' = @{
                            'Status'  = 'pending'
                            'Title'   = 'Step 4: CPV Refresh'
                            'Message' = 'Waiting for Step 3'
                        }
                        'Step5' = @{
                            'Status'  = 'pending'
                            'Title'   = 'Step 5: Graph API Test'
                            'Message' = 'Waiting for Step 4'
                        }
                    }
                    $TenantOnboarding = [PSCustomObject]@{
                        PartitionKey    = 'Onboarding'
                        RowKey          = [string]$SafeId
                        CustomerId      = ''
                        Status          = 'queued'
                        OnboardingSteps = [string](ConvertTo-Json -InputObject $OnboardingSteps -Compress)
                        Relationship    = ''
                        Logs            = ''
                        Exception       = ''
                    }
                    Add-CIPPAzDataTableEntity @OnboardTable -Entity $TenantOnboarding -Force -ErrorAction Stop

                    $Item = [pscustomobject]@{
                        FunctionName               = 'ExecOnboardTenantQueue'
                        id                         = $SafeId
                        Roles                      = $Request.Body.gdapRoles
                        AddMissingGroups           = $Request.Body.addMissingGroups
                        IgnoreMissingRoles         = $Request.Body.ignoreMissingRoles
                        AutoMapRoles               = $Request.Body.autoMapRoles
                        StandardsExcludeAllTenants = $Request.Body.standardsExcludeAllTenants
                    }

                    $InputObject = @{
                        OrchestratorName = 'OnboardingOrchestrator'
                        Batch            = @($Item)
                    }
                    $InstanceId = Start-CIPPOrchestrator -InputObject $InputObject
                    Write-LogMessage -headers $Headers -API $APIName -message "Onboarding job $Id started" -Sev 'Info' -LogData @{ 'InstanceId' = $InstanceId }
                }

                $Steps = $TenantOnboarding.OnboardingSteps | ConvertFrom-Json
                $OnboardingSteps = foreach ($Step in $Steps.PSObject.Properties.Name) { $Steps.$Step }
                $Relationship = try { $TenantOnboarding.Relationship | ConvertFrom-Json -ErrorAction Stop } catch { @{} }
                $Logs = try { $TenantOnboarding.Logs | ConvertFrom-Json -ErrorAction Stop } catch { @{} }
                $TenantOnboarding.OnboardingSteps = $OnboardingSteps
                $TenantOnboarding.Relationship = $Relationship
                $TenantOnboarding.Logs = $Logs
                $Results = $TenantOnboarding
                $StatusCode = [HttpStatusCode]::OK
            }
        } catch {
            $ErrorMsg = Get-NormalizedError -message $($_.Exception.Message)

            # If onboarding was created but queue/orchestrator startup failed, mark the job as failed
            # so the UI does not remain stuck at "Queued / Waiting for onboarding job to start".
            try {
                if ($OnboardTable -and $SafeId) {
                    $QueuedOnboarding = Get-CIPPAzDataTableEntity @OnboardTable -Filter "RowKey eq '$SafeId'"
                    if ($QueuedOnboarding -and $QueuedOnboarding.Status -eq 'queued') {
                        $QueuedSteps = try { $QueuedOnboarding.OnboardingSteps | ConvertFrom-Json -ErrorAction Stop } catch { $null }
                        if ($QueuedSteps -and $QueuedSteps.Step1) {
                            $QueuedSteps.Step1.Status = 'failed'
                            $QueuedSteps.Step1.Message = 'Failed to start onboarding job. Check queue/offloading configuration and retry.'
                            $QueuedOnboarding.OnboardingSteps = [string](ConvertTo-Json -InputObject $QueuedSteps -Compress)
                        }

                        $QueuedLogs = [System.Collections.Generic.List[object]]::new()
                        try {
                            $ExistingLogs = @($QueuedOnboarding.Logs | ConvertFrom-Json -ErrorAction Stop)
                            foreach ($LogEntry in $ExistingLogs) {
                                $QueuedLogs.Add($LogEntry)
                            }
                        } catch {
                            # No existing logs; continue with an empty log collection.
                        }
                        $QueuedLogs.Add([PSCustomObject]@{
                                Date = (Get-Date).ToUniversalTime()
                                Log  = "Onboarding startup failed: $ErrorMsg"
                            })

                        $QueuedOnboarding.Status = 'failed'
                        $QueuedOnboarding.Exception = [string]$ErrorMsg
                        $QueuedOnboarding.Logs = [string](ConvertTo-Json -InputObject @($QueuedLogs) -Compress)
                        Add-CIPPAzDataTableEntity @OnboardTable -Entity $QueuedOnboarding -Force -ErrorAction Stop
                    }
                }
            } catch {
                Write-Warning "Failed to update onboarding status after startup failure: $($_.Exception.Message)"
            }

            $Results = "Function Error: $($_.InvocationInfo.ScriptLineNumber) - $ErrorMsg"
            $StatusCode = [HttpStatusCode]::BadRequest
        }
    } else {
        $StatusCode = [HttpStatusCode]::NotFound
        $Results = 'Relationship not found'
    }
    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Results
        })

}
