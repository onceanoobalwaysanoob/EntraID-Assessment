# session connection with required scopes
$script:BreakGlassScopes = @(
  'Directory.Read.All','User.Read.All','UserAuthenticationMethod.Read.All','Policy.Read.All','AuditLog.Read.All'
)
$script:DeviceScopes = @('Directory.Read.All','User.Read.All','Device.Read.All')

function Initialize-BreakGlassSession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global'
  )
  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $script:BreakGlassScopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId -RequiredScopes $script:BreakGlassScopes -Environment $Environment
  }
}

function Initialize-DeviceSession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global'
  )
  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $script:DeviceScopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId -RequiredScopes $script:DeviceScopes -Environment $Environment
  }
}

## get break glass accounts
[OutputType([pscustomobject])]
function Get-BreakGlassCandidates {
  [CmdletBinding()]
  param(
    [int]    $PageSize = 999,
    [int]    $ThrottleLimit = 8,
    [int]    $DaysInactive = 90,
    [switch] $IncludeGroupExclusions,
    [int]    $GroupExpansionDepth = 1,
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global'
  )

  Initialize-BreakGlassSession -TenantId $TenantId -Environment $Environment

  try {
    $threshold = [datetimeoffset](Get-Date).AddDays(-1 * $DaysInactive)

    # Users: cloud-only, enabled member accounts
    $uProps = 'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,userType,signInActivity'
    $users = Get-MgUser -All -PageSize $PageSize -Property $uProps -ErrorAction Stop |
             Where-Object { $_.UserType -eq 'Member' -and (-not $_.OnPremisesSyncEnabled) -and $_.AccountEnabled }
    if (-not $users) { return @() }

    # Auth methods (parallel) + light retry
    $authBag = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
    $users | ForEach-Object -Parallel {
      param($u,$dict)
      $attempt=0;$max=3
      do {
        try {
          $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
          $err=$null
        } catch {
          $err=$_
          if ($attempt -lt $max -and ($_.Exception.Message -match '(429|temporar|throttl|timeout|5\d{2})')) {
            Start-Sleep -Milliseconds (300 * [math]::Pow(2,$attempt) + (Get-Random -Min 50 -Max 200))
          } else { break }
        }
        $attempt++
      } while ($err)

      if ($err) {
        $dict[$u.Id] = [pscustomobject]@{ HasLocalMfa = $false; Methods = @(); Error = $err.Exception.Message }
      } else {
        $hasAny = $false
        $types  = @()
        foreach ($m in $methods) {
          $t = $m.AdditionalProperties['@odata.type']
          if ($t) { $types += $t }
          if ($t -and $t -ne '#microsoft.graph.passwordAuthenticationMethod' -and $t -ne '#microsoft.graph.emailAuthenticationMethod') {
            $hasAny = $true
          }
        }
        $dict[$u.Id] = [pscustomobject]@{ HasLocalMfa = $hasAny; Methods = $types }
      }
    } -ThrottleLimit $ThrottleLimit -ArgumentList $authBag

    # Conditional Access policies (enforcing MFA/auth strength/compliantDevice)
    $policies = Get-MgIdentityConditionalAccessPolicy -All -PageSize $PageSize -ErrorAction Stop
    if (-not $policies) { $policies = @() }

    $enforcingPolicies = $policies | Where-Object {
      $_.GrantControls -and (
        ($_.GrantControls.BuiltInControls -contains 'mfa') -or
        ($_.GrantControls.AuthenticationStrength) -or
        ($_.GrantControls.BuiltInControls -contains 'compliantDevice')
      )
    }

    # Build direct and group exclusions maps
    $excludedUserIds       = [System.Collections.Generic.HashSet[string]]::new()
    $policyExcludesUsers   = @{}
    $policyExcludesGroups  = @{}
    foreach ($p in $enforcingPolicies) {
      $policyExcludesUsers[$p.Id]  = @($p.Conditions.Users.ExcludeUsers)  | Where-Object { $_ }
      $policyExcludesGroups[$p.Id] = @($p.Conditions.Users.ExcludeGroups) | Where-Object { $_ }
      foreach ($id in $policyExcludesUsers[$p.Id]) { [void]$excludedUserIds.Add($id) }
    }

    # Optional: expand group exclusions (depth-aware)
    $expandedGroupMembers = @{}
    if ($IncludeGroupExclusions) {
      $excludedGroupIds = $policyExcludesGroups.Values | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique
      foreach ($gid in $excludedGroupIds) {
        try {
          $members = if ($GroupExpansionDepth -le 1) {
            Get-MgGroupMember -GroupId $gid -All -PageSize $PageSize -ErrorAction Stop
          } else {
            Get-MgGroupTransitiveMember -GroupId $gid -All -PageSize $PageSize -ErrorAction Stop
          }
          $members = $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
          $expandedGroupMembers[$gid] = @($members.Id)
          foreach ($m in $members) { [void]$excludedUserIds.Add($m.Id) }
        } catch {
          Write-Warning "Failed to expand group $gid exclusions: $($_.Exception.Message)"
          $expandedGroupMembers[$gid] = @()
        }
      }
    }

    # Emit candidates
    $tenantId = (Get-MgContext).TenantId
    $out = foreach ($u in $users) {
      # Safe fetch of auth
      $auth = $null
      $null = $authBag.TryGetValue($u.Id, [ref]$auth)
      if (-not $auth) { $auth = [pscustomobject]@{ HasLocalMfa = $false; Methods = @(); Error = 'AuthMethodsUnavailable' } }

      # Determine which policies exclude this user
      $excludingPolicies = @()
      foreach ($p in $enforcingPolicies) {
        $directHit = ($policyExcludesUsers[$p.Id] -contains $u.Id)
        $groupHit  = $false
        if ($IncludeGroupExclusions -and $policyExcludesGroups[$p.Id]) {
          foreach ($gid in $policyExcludesGroups[$p.Id]) {
            if ($expandedGroupMembers[$gid] -and ($expandedGroupMembers[$gid] -contains $u.Id)) { $groupHit = $true; break }
          }
        }
        if ($directHit -or $groupHit) { $excludingPolicies += $p.Id }
      }

      $isExcluded = $excludingPolicies.Count -gt 0
      $lastSignIn = $u.SignInActivity.LastSignInDateTime
      $hasRecent  = $lastSignIn -and ([datetimeoffset]$lastSignIn -gt $threshold)

      if ((-not $auth.HasLocalMfa) -and $isExcluded) {
        [pscustomobject]@{
          UserId                   = $u.Id
          UserPrincipalName        = $u.UserPrincipalName
          DisplayName              = $u.DisplayName
          AccountEnabled           = $u.AccountEnabled
          CloudOnly                = (-not $u.OnPremisesSyncEnabled)
          LastSignInDateTime       = $lastSignIn
          HasRecentSignIn          = [bool]$hasRecent
          HasLocalMfaMethods       = $auth.HasLocalMfa
          LocalMethodTypes         = $auth.Methods
          ExplicitlyExcludedFromCA = $true
          ExcludingPolicyIds       = $excludingPolicies
          ExcludingPolicyCount     = $excludingPolicies.Count
          ExcludingPolicyNames     = @($enforcingPolicies | Where-Object { $excludingPolicies -contains $_.Id } | Select-Object -ExpandProperty DisplayName)
          TenantId                 = $tenantId
          CollectedAt              = [datetimeoffset]::UtcNow
          Source                   = 'Graph/v1.0:users + conditionalAccess/policies'
        }
      }
    }

    $out
  } catch {
    throw "Error identifying break-glass candidates: $($_.Exception.Message)"
  }
}

## get user device footprint
[OutputType([pscustomobject])]
function Get-UserDeviceFootprint {
  [CmdletBinding()]
  param(
    [int] $PageSize = 999,
    [int] $ThrottleLimit = 8,
    [switch] $OnlyManaged,
    [switch] $OnlyCompliant,
    [int] $OnlyActiveSinceDays = 0,
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global'
  )

  Initialize-DeviceSession -TenantId $TenantId -Environment $Environment

  try {
    $users = Get-MgUser -All -PageSize $PageSize -Property 'id,displayName,userPrincipalName' -ErrorAction Stop
    if (-not $users) { return @() }

    $cutoff   = if ($OnlyActiveSinceDays -gt 0) { [datetimeoffset](Get-Date).AddDays(-1 * $OnlyActiveSinceDays) } else { $null }
    $tenantId = (Get-MgContext).TenantId
    $bag      = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    $users | ForEach-Object -Parallel {
      param($u,$pageSize,$bagRef,$cutoff,$onlyManaged,$onlyCompliant,$tenantId)
      try {
        # Retry on transient errors
        $attempt=0;$max=3
        do {
          try {
            $owned = Get-MgUserOwnedDevice      -UserId $u.Id -All -PageSize $pageSize -ErrorAction Stop
            $regd  = Get-MgUserRegisteredDevice -UserId $u.Id -All -PageSize $pageSize -ErrorAction Stop
            $err=$null
          } catch {
            $err=$_
            if ($attempt -lt $max -and ($_.Exception.Message -match '(429|temporar|throttl|timeout|5\d{2})')) {
              Start-Sleep -Milliseconds (300 * [math]::Pow(2,$attempt) + (Get-Random -Min 50 -Max 200))
            } else { break }
          }
          $attempt++
        } while ($err)

        if ($err) {
          [void]$bagRef.Add([pscustomobject]@{
            UserId=$u.Id; UserPrincipalName=$u.UserPrincipalName; DisplayName=$u.DisplayName; Error=$err.Exception.Message
          })
          return
        }

        # Merge & de-dupe
        $allDevs = @()
        if ($owned) { $allDevs += $owned }
        if ($regd)  { $allDevs += $regd }
        $allDevs = $allDevs | Sort-Object Id -Unique

        foreach ($d in $allDevs) {
          if ($d.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.device') { continue }
          $ap = $d.AdditionalProperties
          $last = $ap.approximateLastSignInDateTime
          if ($onlyManaged   -and -not $ap.isManaged)   { continue }
          if ($onlyCompliant -and -not $ap.isCompliant) { continue }
          if ($cutoff -and $last -and ([datetimeoffset]$last -lt $cutoff)) { continue }

          [void]$bagRef.Add([pscustomobject]@{
            UserId                        = $u.Id
            UserPrincipalName             = $u.UserPrincipalName
            DisplayName                   = $u.DisplayName
            DeviceId                      = $ap.deviceId
            DeviceObjectId                = $d.Id
            DeviceDisplayName             = $ap.displayName
            OperatingSystem               = $ap.operatingSystem
            DeviceTrustType               = if ($ap.deviceTrustType) { $ap.deviceTrustType } else { $ap.trustType }
            IsCompliant                   = $ap.isCompliant
            IsManaged                     = $ap.isManaged
            ApproximateLastSignInDateTime = $last
            AccountEnabled                = $ap.accountEnabled
            TenantId                      = $tenantId
            CollectedAt                   = [datetimeoffset]::UtcNow
            Source                        = 'Graph/v1.0:users/*/devices'
          })
        }
      } catch {
        [void]$bagRef.Add([pscustomobject]@{
          UserId=$u.Id; UserPrincipalName=$u.UserPrincipalName; DisplayName=$u.DisplayName; Error=$_.Exception.Message
        })
      }
    } -ThrottleLimit $ThrottleLimit -ArgumentList $PageSize, $bag, $cutoff, $OnlyManaged, $OnlyCompliant, $tenantId

    $bag.ToArray()
  } catch {
    throw "Error retrieving user device footprint: $($_.Exception.Message)"
  }
}

Export-ModuleMember -Function Initialize-BreakGlassSession, Get-BreakGlassCandidates, Initialize-DeviceSession, Get-UserDeviceFootprint
