function Invoke-ExecGraphRequest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Core.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    function Get-ExecGraphRequestValue {
        param(
            [object]$Body,
            [object]$Query,
            [string[]]$Names
        )

        foreach ($Name in $Names) {
            if ($Body -and $Body.PSObject.Properties.Name -contains $Name -and $null -ne $Body.$Name) {
                return $Body.$Name
            }

            if ($Query -and $Query.PSObject.Properties.Name -contains $Name -and $null -ne $Query.$Name) {
                return $Query.$Name
            }
        }

        return $null
    }

    function Resolve-ExecGraphEndpoint {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Endpoint,
            [string]$VersionOverride
        )

        $GraphVersion = if ($VersionOverride) { $VersionOverride.Trim().ToLowerInvariant() } else { 'beta' }
        if ($GraphVersion -notin @('v1.0', 'beta')) {
            throw "Unsupported version '$VersionOverride'. Allowed values: v1.0, beta."
        }

        $NormalizedEndpoint = $Endpoint.Trim()
        if ([string]::IsNullOrWhiteSpace($NormalizedEndpoint)) {
            throw 'Endpoint is required.'
        }

        if ($NormalizedEndpoint -match '^https?://') {
            try {
                $Uri = [System.Uri]$NormalizedEndpoint
            } catch {
                throw "Endpoint '$Endpoint' is not a valid URI."
            }

            if ($Uri.Host -ne 'graph.microsoft.com') {
                throw "Endpoint host '$($Uri.Host)' is not allowed."
            }

            $NormalizedEndpoint = $Uri.PathAndQuery
        }

        $NormalizedEndpoint = $NormalizedEndpoint -replace '^/+', ''
        if ($NormalizedEndpoint -match '^(?<GraphVersion>v1\.0|beta)/(?<GraphPath>.+)$') {
            $GraphVersion = $Matches.GraphVersion.ToLowerInvariant()
            $NormalizedEndpoint = $Matches.GraphPath
        }

        if ([string]::IsNullOrWhiteSpace($NormalizedEndpoint)) {
            throw 'Endpoint is required.'
        }

        $EndpointPath = ($NormalizedEndpoint -split '\?')[0]
        if ($EndpointPath -notmatch '^teams/[^/\?]+/schedule(?:/.*)?$') {
            throw "Endpoint '$EndpointPath' is blocked. Allowed pattern: teams/{team-ID}/schedule/*."
        }

        return @{
            Version       = $GraphVersion
            Endpoint      = $NormalizedEndpoint
            EndpointPath  = $EndpointPath
            AllowedTarget = 'teams/{team-ID}/schedule/*'
        }
    }

    function Convert-ExecGraphHeaders {
        param($RawHeaders)

        if ($null -eq $RawHeaders) {
            return @{
                Headers     = @{}
                ContentType = $null
            }
        }

        if ($RawHeaders -is [string]) {
            if (-not (Test-Json -Json $RawHeaders -ErrorAction SilentlyContinue)) {
                throw 'Headers must be valid JSON when provided as a string.'
            }

            $RawHeaders = $RawHeaders | ConvertFrom-Json
        }

        if ($RawHeaders -isnot [hashtable] -and $RawHeaders -isnot [pscustomobject]) {
            throw 'Headers must be a JSON object.'
        }

        $Headers = @{}
        $ContentType = $null

        $HeaderItems = if ($RawHeaders -is [hashtable]) {
            $RawHeaders.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{
                    Name  = $_.Key
                    Value = $_.Value
                }
            }
        } else {
            $RawHeaders.PSObject.Properties | Select-Object Name, Value
        }

        foreach ($Header in $HeaderItems) {
            $Name = [string]$Header.Name
            $Value = [string]$Header.Value

            if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Value)) {
                continue
            }

            if ($Name -notmatch '^[A-Za-z0-9-]+$') {
                throw "Invalid header name '$Name'."
            }

            if ($Name -match '^(?i:authorization|host|content-length)$') {
                throw "Header '$Name' is not allowed."
            }

            if ($Name -ieq 'Content-Type') {
                $ContentType = $Value
                continue
            }

            $Headers[$Name] = $Value
        }

        return @{
            Headers     = $Headers
            ContentType = $ContentType
        }
    }

    function Convert-ExecGraphBody {
        param(
            [string]$Method,
            $RawBody
        )

        if ($Method -eq 'GET') {
            if ($null -ne $RawBody -and -not [string]::IsNullOrWhiteSpace([string]$RawBody)) {
                throw 'Body is not supported when method is GET.'
            }

            return $null
        }

        if ($null -eq $RawBody -or [string]::IsNullOrWhiteSpace([string]$RawBody)) {
            return '{}'
        }

        if ($RawBody -is [string]) {
            if (-not (Test-Json -Json $RawBody -ErrorAction SilentlyContinue)) {
                throw 'Body must be valid JSON.'
            }

            return $RawBody
        }

        return $RawBody | ConvertTo-Json -Depth 50 -Compress
    }

    $StatusCode = [HttpStatusCode]::OK
    $ResultBody = $null

    try {
        $RequestBody = $Request.Body
        $RequestQuery = $Request.Query

        $TenantFilter = [string](Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('tenantFilter', 'TenantFilter'))
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
            throw 'TenantFilter is required.'
        }

        $EndpointValue = [string](Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('endpoint', 'Endpoint'))
        $Method = [string](Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('method', 'Method'))
        $Method = if ([string]::IsNullOrWhiteSpace($Method)) { 'GET' } else { $Method.Trim().ToUpperInvariant() }
        if ($Method -notin @('GET', 'POST', 'PATCH')) {
            throw "Method '$Method' is not allowed. Allowed methods: GET, POST, PATCH."
        }

        $AsAppValue = Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('asApp', 'AsApp')
        $AsApp = if ($null -eq $AsAppValue) { $true } else { [System.Convert]::ToBoolean($AsAppValue) }

        $VersionOverride = [string](Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('version', 'Version'))
        $ResolvedEndpoint = Resolve-ExecGraphEndpoint -Endpoint $EndpointValue -VersionOverride $VersionOverride

        $HeaderResult = Convert-ExecGraphHeaders -RawHeaders (Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('headers', 'Headers'))
        $BodyJson = Convert-ExecGraphBody -Method $Method -RawBody (Get-ExecGraphRequestValue -Body $RequestBody -Query $RequestQuery -Names @('body', 'Body'))

        if ($BodyJson) {
            $BodyByteCount = [System.Text.Encoding]::UTF8.GetByteCount($BodyJson)
            if ($BodyByteCount -gt 262144) {
                throw "Body exceeds the maximum size of 262144 bytes. Current size: $BodyByteCount bytes."
            }
        }

        $Uri = "https://graph.microsoft.com/$($ResolvedEndpoint.Version)/$($ResolvedEndpoint.Endpoint)"
        $GraphRequestParams = @{
            uri         = $Uri
            tenantid    = $TenantFilter
            type        = $Method
            AsApp       = $AsApp
            NoAuthCheck = $true
        }

        if ($HeaderResult.Headers.Count -gt 0) {
            $GraphRequestParams.AddedHeaders = $HeaderResult.Headers
        }

        if ($HeaderResult.ContentType) {
            $GraphRequestParams.contentType = $HeaderResult.ContentType
        }

        if ($BodyJson) {
            $GraphRequestParams.body = $BodyJson
        }

        $APIName = $Request.Params.CIPPEndpoint
        $LogMessage = 'Accessed this API | Endpoint: {0} | Method: {1}' -f $ResolvedEndpoint.Endpoint, $Method
        Write-LogMessage -headers $Request.Headers -API $APIName -message $LogMessage -Sev 'Debug'

        $GraphResults = New-GraphPOSTRequest @GraphRequestParams

        $ResultBody = [PSCustomObject]@{
            Results  = @($GraphResults)
            Metadata = [PSCustomObject]@{
                Endpoint      = $ResolvedEndpoint.Endpoint
                EndpointPath  = $ResolvedEndpoint.EndpointPath
                AllowedTarget = $ResolvedEndpoint.AllowedTarget
                Method        = $Method
                Version       = $ResolvedEndpoint.Version
                TenantFilter  = $TenantFilter
                AsApp         = $AsApp
            }
        }
    } catch {
        $StatusCode = [HttpStatusCode]::BadRequest
        $ResultBody = @{
            error = [PSCustomObject]@{
                message = $_.Exception.Message
            }
        }
        Write-Warning "ExecGraphRequest failed: $($_.Exception.Message)"
        Write-Information $_.InvocationInfo.PositionMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $ResultBody
        })
}
