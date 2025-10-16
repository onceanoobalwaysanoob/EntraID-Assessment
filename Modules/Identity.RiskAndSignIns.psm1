# session connection with required scopes
$script:RiskRequiredScopes   = @('Directory.Read.All','User.Read.All','IdentityRiskyUser.Read.All')
$script:RiskDetectScope      = 'IdentityRiskEvent.Read.All'
$script:AuditSignInScope     = 'AuditLog.Read.All'

[OutputType([pscustomobject])]
function Initialize-RiskSession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global',
    [switch] $IncludeDetections,   
    [switch] $NeedSignIns          
  )

  $scopes = @($script:RiskRequiredScopes)
  if ($IncludeDetections) { $scopes += $script:RiskDetectScope }
  if ($NeedSignIns)       { $scopes += $script:AuditSignInScope }

  # Feature/licensing safety (P2 for Identity Protection)
  Ensure-Feature -FeatureName IdentityProtection -Quiet | Out-Null

  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $scopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId -RequiredScopes $scopes -Environment $Environment
  }
}

## get risky users
[OutputType([pscustomobject])]
function Get-RiskyUsers {
    [CmdletBinding()]
    param(
        [int] $PageSize = 999,
        [switch] $IncludeDetections,
        [int] $Days = 30,
        [int] $ThrottleLimit = 8,
        [ValidateSet('All','atRisk','confirmedCompromised','remediated','dismissed')]
        [string] $RiskState = 'All',
        [ValidateSet('All','high','medium','low','hidden','none','unknownFutureValue')]
        [string] $RiskLevel = 'All',
        [switch] $FilterByLastUpdated,
        [string] $TenantId,
        [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
        [string] $Environment = 'Global'
    )
    Initialize-RiskSession -TenantId $TenantId -Environment $Environment -IncludeDetections:$IncludeDetections

    try {
        # Build $filter for riskyUsers if any selector chosen
        $filters = @()
        if ($RiskState -ne 'All') { $filters += "riskState eq '$RiskState'" }
        if ($RiskLevel -ne 'All') { $filters += "riskLevel eq '$RiskLevel'" }
        if ($FilterByLastUpdated) {
        $since = (Get-Date).AddDays(-1 * $Days).ToString("s") + "Z"
        $filters += "riskLastUpdatedDateTime ge $since"
        }
        $filterString = if ($filters.Count) { $filters -join ' and ' } else { $null }

        # Pull risky users
        $select = @(
        'id','userPrincipalName','displayName',
        'riskLevel','riskState','riskDetail','riskLastUpdatedDateTime','isDeleted'
        ) -join ','

        if ($filterString) {
        $risky = Get-MgIdentityProtectionRiskyUser -All -PageSize $PageSize `
                -Filter $filterString -Property $select -ErrorAction Stop
        } else {
        $risky = Get-MgIdentityProtectionRiskyUser -All -PageSize $PageSize `
                -Property $select -ErrorAction Stop
        }

        if (-not $risky) { return @() }

        # Base map to objects; detections fields default empty
        $base = $risky | ForEach-Object {
            [pscustomobject]@{
                UserId                  = $_.Id
                UserPrincipalName       = $_.UserPrincipalName
                DisplayName             = $_.DisplayName
                RiskLevel               = $_.RiskLevel
                RiskState               = $_.RiskState
                RiskDetail              = $_.RiskDetail
                RiskLastUpdatedDateTime = [datetimeoffset]$_.RiskLastUpdatedDateTime
                IsDeleted               = [bool]$_.IsDeleted
                DetectionsCount         = 0
                DetectionsTypes         = @()
                LastDetectionDateTime   = $null
                TenantId                = (Get-MgContext).TenantId
                CollectedAt             = [datetimeoffset]::UtcNow
                Source                  = 'Graph/v1.0:identityProtection/riskyUsers'
            }
        }

        if (-not $IncludeDetections) {
        return $base
        }

        # Fetch recent detections per user in parallel (limit to last -Days)
        $cutoff = ([datetimeoffset](Get-Date)).AddDays(-1 * $Days).ToString('s') + 'Z'
        $bag    = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        $base | ForEach-Object -Parallel {
        param($row, $cut, $bagRef)
        try {
            $attempt = 0; $max = 3
            do {
            try {
                $f   = "userId eq '$($row.UserId)' and createdDateTime ge $cut"
                $det = Get-MgIdentityProtectionRiskDetection -All -Filter $f -ErrorAction Stop
                $err = $null
            } catch {
                $err = $_
                if ($attempt -lt $max -and ($_.Exception.Message -match '(429|temporar|throttl|timeout|5\d{2})')) {
                Start-Sleep -Milliseconds (300 * [math]::Pow(2,$attempt) + (Get-Random -Min 50 -Max 200))
                } else { break }
            }
            $attempt++
            } while ($err)

            if ($err) {
            $row | Add-Member -NotePropertyName 'DetectionsError' -NotePropertyValue $err.Exception.Message -Force
            } elseif ($det) {
            $types = @()
            $last  = $null
            foreach ($d in $det) {
                if ($d.RiskEventType) { $types += $d.RiskEventType }
                if ($d.CreatedDateTime -and (-not $last -or $d.CreatedDateTime -gt $last)) { $last = $d.CreatedDateTime }
            }
            $row.DetectionsCount       = $det.Count
            $row.DetectionsTypes       = $types | Sort-Object -Unique
            $row.LastDetectionDateTime = $last
            }
        } finally {
            [void]$bagRef.Add($row)
        }
        } -ThrottleLimit $ThrottleLimit -ArgumentList $cutoff, $bag

        return $bag.ToArray()
    } catch {
        throw "Error retrieving risky users: $($_.Exception.Message)"
    }
}

## get users with sign in anomalies
[OutputType([pscustomobject])]
function Find-SignInAnomalies {
    [CmdletBinding()]
    param(
        [int] $Days = 14,
        [int] $PageSize = 999,
        [int] $FailureRateThresholdPercent = 30,
        [int] $TravelWindowHours = 2,
        [int] $MinEvents = 5,
        [string] $TenantId,
        [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
        [string] $Environment = 'Global'
    )
    Initialize-RiskSession -TenantId $TenantId -Environment $Environment -NeedSignIns

    try {
        $since = ([datetimeoffset](Get-Date)).AddDays(-1 * $Days).ToString('s') + 'Z'
        $select = 'id,createdDateTime,userId,userDisplayName,userPrincipalName,ipAddress,location,conditionalAccessStatus,status,clientAppUsed'
        $signIns = Get-MgAuditLogSignIn -All -PageSize $PageSize -Filter "createdDateTime ge $since" -Property $select -ErrorAction Stop
        if (-not $signIns) { return @() }

        # Group per user and compute stats
        $byUser = $signIns | Group-Object -Property userId
        $result = foreach ($g in $byUser) {
            $events = $g.Group | Sort-Object createdDateTime
            if ($events.Count -lt $MinEvents) { continue }
            $total  = $events.Count
            $fails  = ($events | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
            $failPct = if ($total -gt 0) { [math]::Round(($fails / $total) * 100, 1) } else { 0 }

            # Build time-ordered country list to detect rapid country changes
            $anoms = 0
            $hops  = @()
            for ($i = 0; $i -lt ($events.Count - 1); $i++) {
                $a = $events[$i]
                $b = $events[$i+1]
                $countryA = $a.Location.CountryOrRegion
                $countryB = $b.Location.CountryOrRegion
                if ($countryA -and $countryB -and $countryA -ne $countryB) {
                $delta = [datetime]$b.CreatedDateTime - [datetime]$a.CreatedDateTime
                if ($delta.TotalHours -le $TravelWindowHours) {
                    $anoms++
                    $hops += "$($countryA)->$($countryB) in {0:n1}h" -f $delta.TotalHours
                }
                }
            }

            [pscustomobject]@{
                UserId                  = $g.Name
                UserPrincipalName       = ($events | Select-Object -First 1 -ExpandProperty userPrincipalName)
                DisplayName             = ($events | Select-Object -First 1 -ExpandProperty userDisplayName)
                WindowStart             = $since
                WindowDays              = $Days
                TotalSignIns            = $total
                FailedSignIns           = $fails
                FailureRatePercent      = $failPct
                ImpossibleTravelCount   = $anoms
                ImpossibleTravelSamples = $hops
                HasHighFailureRate      = ($failPct -ge $FailureRateThresholdPercent)
                HasImpossibleTravel     = ($anoms -gt 0)
                TenantId                = (Get-MgContext).TenantId
                CollectedAt             = [datetimeoffset]::UtcNow
                Source                  = 'Graph/v1.0:auditLogs/signIns'
            }
        }

        # Return only users with any anomaly, but keep full object for scoring
        $result | Where-Object { $_.HasHighFailureRate -or $_.HasImpossibleTravel }
    } catch {
        throw "Error computing sign-in anomalies: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function Initialize-RiskSession, Get-RiskyUsers, Find-SignInAnomalies
