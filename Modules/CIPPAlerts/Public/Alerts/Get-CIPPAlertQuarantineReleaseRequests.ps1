function Get-CIPPAlertQuarantineReleaseRequests {
    <#
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        $TenantFilter
    )

    $HasLicense = Test-CIPPStandardLicense -StandardName 'QuarantineReleaseRequests' -TenantFilter $TenantFilter -Preset Exchange

    if (-not $HasLicense) {
        return
    }

    try {
        $LookbackDays = 30
        if ($InputValue -is [hashtable] -and $InputValue.LookbackDays) {
            $LookbackDays = [int]$InputValue.LookbackDays
        } elseif ($InputValue -and $InputValue.PSObject.Properties.Name -contains 'LookbackDays' -and $InputValue.LookbackDays) {
            $LookbackDays = [int]$InputValue.LookbackDays
        }

        if ($LookbackDays -lt 1) {
            $LookbackDays = 1
        } elseif ($LookbackDays -gt 30) {
            $LookbackDays = 30
        }

        $cmdParams = @{
            PageSize          = 1000
            ReleaseStatus     = 'Requested'
            StartReceivedDate = (Get-Date).AddDays(-$LookbackDays)
            EndReceivedDate   = (Get-Date).AddHours(0)
        }
        $RequestedReleases = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-QuarantineMessage' -cmdParams $cmdParams -ErrorAction Stop | Select-Object -ExcludeProperty *data.type* | Sort-Object -Property ReceivedTime

        # Get the CIPP URL for the Quarantine link
        $CippConfigTable = Get-CippTable -tablename Config
        $CippConfig = Get-CIPPAzDataTableEntity @CippConfigTable -Filter "PartitionKey eq 'InstanceProperties' and RowKey eq 'CIPPURL'"
        $CIPPUrl = 'https://{0}' -f $CippConfig.Value

        if ($RequestedReleases) {
            $AlertData = foreach ($Message in $RequestedReleases) {
                [PSCustomObject]@{
                    Identity          = $Message.Identity
                    MessageId         = $Message.MessageId
                    Subject           = $Message.Subject
                    SenderAddress     = $Message.SenderAddress
                    RecipientAddress  = $Message.RecipientAddress -join '; '
                    Type              = $Message.Type
                    PolicyName        = $Message.PolicyName
                    ReleaseStatus     = $Message.ReleaseStatus
                    ReceivedTime      = $Message.ReceivedTime
                    QuarantineViewUrl = "$CIPPUrl/email/administration/quarantine?tenantFilter=$TenantFilter"
                    Tenant            = $TenantFilter
                }
            }

            Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data $AlertData
        } else {
            Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data ([PSCustomObject]@{
                    QueueStatus      = 'Empty'
                    RequestedCount   = 0
                    LookbackDays     = $LookbackDays
                    ReleaseStatus    = 'Requested'
                    QuarantineViewUrl = "$CIPPUrl/email/administration/quarantine?tenantFilter=$TenantFilter"
                    Tenant           = $TenantFilter
                })
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "QuarantineReleaseRequests: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
