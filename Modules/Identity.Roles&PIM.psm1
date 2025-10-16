# session connection with required scopes
$script:RolesRequiredScopes = @('RoleManagement.Read.Directory','Directory.Read.All','User.Read.All')
$script:SignInScope         = 'AuditLog.Read.All'
$script:ReportsScope        = 'Reports.Read.All'

[OutputType([pscustomobject])]
function Initialize-AdminAndPimSession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global',
    [switch] $UseBeta,
    [switch] $NeedSignInActivity,   # adds AuditLog.Read.All
    [switch] $NeedReports           # adds Reports.Read.All and Beta
  )

  $scopes = @($script:RolesRequiredScopes)
  if ($NeedSignInActivity) { $scopes += $script:SignInScope }
  if ($NeedReports)        { $scopes += $script:ReportsScope }

  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $scopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId -RequiredScopes $scopes -Environment $Environment -UseBeta:($UseBeta -or $NeedReports)
  } elseif ($NeedReports) {
    # Ensure beta for the reports endpoint even on reuse
    Select-MgProfile -Name Beta | Out-Null
  }
}

## get admin role membership
[OutputType([pscustomobject])]
function Get-AdminRoleMembership {
    [CmdletBinding()]
    param(
      [switch] $IncludeSignInActivity,
      [int]    $ThrottleLimit = 8,
      [int]    $PageSize      = 999
      [string] $TenantId,
      [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
      [string] $Environment = 'Global',
      [switch] $UseBeta
    )
    Initialize-AdminAndPimSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta -NeedSignInActivity:$IncludeSignInActivity

    try {
      # Get all directory roles (active only) and members
      $roles = Get-MgDirectoryRole -All -PageSize $PageSize -ErrorAction Stop

      # Build flat list of (Role, UserId) pairs
      $pairs = foreach ($role in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -PageSize $PageSize -ErrorAction Stop |
          Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
        foreach ($m in $members) {
          [pscustomobject]@{
            RoleId       = $role.Id
            RoleName     = $role.DisplayName
            UserId       = $m.Id
            UserUPN      = $m.AdditionalProperties.userPrincipalName
            UserName     = $m.AdditionalProperties.displayName
          }
        }
      }

      if (-not $pairs) { return @() }

      if (-not $IncludeSignInActivity) {
        # Return as-is; no extra calls
        return $pairs | Select-Object RoleName, RoleId, UserName, UserUPN, UserId
      }

      # Include sign-in activity: fetch per user (parallel, throttled)
      $bag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
      $pairs | ForEach-Object -Parallel {
        param($p)
        try {
          $u = Get-MgUser -UserId $p.UserId -Property 'signInActivity' -ErrorAction Stop
          $lastInteractive = $u.SignInActivity.LastSignInDateTime
          $obj = [pscustomobject]@{
            Id                = $uid
            User              = $u.UserPrincipalName
            DisplayName       = $u.DisplayName
            IsMfaRegistered   = [bool]$reg.isMfaRegistered
            IsMfaCapable      = [bool]$reg.isMfaCapable
            DefaultMfaMethod  = $reg.defaultMfaMethod
            MethodsRegistered = ($reg.methodsRegistered -join ', ')
            TenantId          = (Get-MgContext).TenantId
            CollectedAt       = [DateTimeOffset]::UtcNow
            Source            = 'Graph/beta:reports/userRegistrationDetails'
          }
          [void]$using:bag.Add($obj)
        } catch {
          $obj = [pscustomobject]@{
            Id                = $uid
            User              = $u.UserPrincipalName
            DisplayName       = $u.DisplayName
            IsMfaRegistered   = [bool]$reg.isMfaRegistered
            IsMfaCapable      = [bool]$reg.isMfaCapable
            DefaultMfaMethod  = $reg.defaultMfaMethod
            MethodsRegistered = ($reg.methodsRegistered -join ', ')
            TenantId          = (Get-MgContext).TenantId
            CollectedAt       = [DateTimeOffset]::UtcNow
            Source            = 'Graph/beta:reports/userRegistrationDetails'
          }
          [void]$using:bag.Add($obj)
        }
      } -ThrottleLimit $ThrottleLimit

      return $bag.ToArray()
    } catch {
      throw "Error retrieving admin role membership: $($_.Exception.Message)"
    }
}

## get PIM eligibility
[OutputType([pscustomobject])]
function Get-PIMEligible {
    [CmdletBinding]
    Param(
      [int] $PageSize = 999
      [string] $TenantId,
      [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
      [string] $Environment = 'Global',
      [switch] $UseBeta
    )
    Ensure-Feature -FeatureName PIM -Quiet | Out-Null
    Initialize-AdminAndPimSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta -NeedSignInActivity:$IncludeSignInActivity

    try {
        $instances = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -PageSize $PageSize -ExpandProperty "roleDefinition,principal,directoryScope" -ErrorAction Stop
        $instances | ForEach-Object {
            $pType = ($_?.Principal?.AdditionalProperties.'@odata.type')
            $isUser = $pType -eq '#microsoft.graph.user'
            $isGroup = $pType -eq '#microsoft.graph.group'

            # common fields
            $end = $_.EndDateTime
            $perm = [bool]( -not $end )

            [PSCustomObject]@{
                # principal
                PrincipalType = if ($isUser) { 'User' } elseif ($isGroup) { 'Group' } else { 'Other' }
                PrincipalId = $_.PrincipalId
                PrincipalDisplayName = $_.Principal.AdditionalProperties.displayName
                PrincipalUPN = if ($isUser) { $_.Principal.AdditionalProperties.userPrincipalName } else { $null }
                AccountEnabled = if ($isUser) { $_.Principal.AdditionalProperties.accountEnabled } else { $null }
                IsAssignedToRole = if ($isGroup) { $_.Principal.AdditionalProperties.isAssignableToRole } else { $null }
                TenantId = (Get-MgContext).TenantId
                CollectedAt = [DateTimeOffset]::UtcNow
                Source = 'Graph/v1.0:roleEligibilityScheduleInstances'

                # Role
                RoleId               = $_.RoleDefinition.Id
                RoleName             = $_.RoleDefinition.DisplayName

                # Scope
                DirectoryScopeId     = $_.DirectoryScopeId
                DirectoryScopeType   = $_.DirectoryScope?.AdditionalProperties?.'@odata.type'

                # Eligibility window
                MemberType           = $_.MemberType
                StartDateTime        = $_.StartDateTime
                EndDateTime          = if ($perm) { $null } else { $end }
                IsPermanent          = $perm
                EligibilityDuration  = if ($perm) { 'Permanent' } else { ([string]([timespan]::FromTicks(($end - $_.StartDateTime).Ticks))) }

                # Source
                ScheduleInstanceId   = $_.Id
            }
        }
    } catch {
        throw "Error retrieving PIM eligibility: $($_.Exception.Message)"
    }
}

## get admin accounts not protected with MFA
[OutputType([pscustomobject])]
function Get-AdminRoleHolders {
    [CmdletBinding()]
    param(
      [int] $PageSize = 999
      [string] $TenantId,
      [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
      [string] $Environment = 'Global',
      [switch] $UseBeta
    )
  Initialize-AdminAndPimSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta -NeedSignInActivity:$IncludeSignInActivity

    # Returns unique user IDs holding any directory role (active assignments)
    $roles = Get-MgDirectoryRole -All -PageSize $PageSize -ErrorAction Stop
    $bag   = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($r in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All -PageSize $PageSize -ErrorAction Stop |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
        foreach ($m in $members) { [void]$bag.Add($m.Id) }
    }
    # Return as array of IDs
    ,$bag.ToArray()
}

[OutputType([pscustomobject])]
function Get-UserRegistrationDetailsById {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory, ValueFromPipeline)]
      [string[]] $UserIds,
      [int] $ThrottleLimit = 8
      [string] $TenantId,
      [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
      [string] $Environment = 'Global',
      [switch] $UseBeta
    )
  Initialize-AdminAndPimSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta -NeedSignInActivity:$IncludeSignInActivity

    begin { $out = [System.Collections.Concurrent.ConcurrentBag[object]]::new() }
    process {
        $UserIds | ForEach-Object -Parallel {
        param($uid)
        $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails/$uid"
        try {
            $u   = Get-MgUser -UserId $uid -ErrorAction Stop
            $reg = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            # Normalize record
            $obj = [pscustomobject]@{
              Id                = $uid
              User              = $u.UserPrincipalName
              DisplayName       = $u.DisplayName
              IsMfaRegistered   = [bool]$reg.isMfaRegistered
              IsMfaCapable      = [bool]$reg.isMfaCapable
              DefaultMfaMethod  = $reg.defaultMfaMethod
              MethodsRegistered = ($reg.methodsRegistered -join ', ')
              TenantId          = (Get-MgContext).TenantId
              CollectedAt       = [DateTimeOffset]::UtcNow
              Source            = 'Graph/beta:reports/userRegistrationDetails'
            }

            [void]$using:out.Add($obj)
        } catch {
            $err = [pscustomobject]@{
            Id                = $uid
            User              = $u.UserPrincipalName
            DisplayName       = $u.DisplayName
            IsMfaRegistered   = [bool]$reg.isMfaRegistered
            IsMfaCapable      = [bool]$reg.isMfaCapable
            DefaultMfaMethod  = $reg.defaultMfaMethod
            MethodsRegistered = ($reg.methodsRegistered -join ', ')
            TenantId          = (Get-MgContext).TenantId
            CollectedAt       = [DateTimeOffset]::UtcNow
            Source            = 'Graph/beta:reports/userRegistrationDetails'
            Error            = $_.Exception.Message
          }
          [void]$using:out.Add($err)
        }
        } -ThrottleLimit $ThrottleLimit
    }
    end { $out.ToArray() }
}

[OutputType([pscustomobject])]
function Get-AdminAccountsWithoutMfa {
    [CmdletBinding()]
    param(
      [int] $ThrottleLimit = 8
      [string] $TenantId,
      [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
      [string] $Environment = 'Global',
      [switch] $UseBeta
    )
    Initialize-AdminAndPimSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta -NeedReports

    $adminIds = Get-AdminRoleHolders
    if (-not $adminIds -or $adminIds.Count -eq 0) { return @() }

    $details |
    Where-Object { -not $_.IsMfaRegistered } |
    Select-Object Id, User, DisplayName, DefaultMfaMethod, MethodsRegistered,
                  @{N='TenantId';E={(Get-MgContext).TenantId}},
                  @{N='CollectedAt';E={[DateTimeOffset]::UtcNow}},
                  @{N='Source';E{'Graph/beta:reports/userRegistrationDetails'}}

    # Return only admins lacking MFA registration
    $details | Where-Object { -not $_.IsMfaRegistered } |
        Select-Object Id, User, DisplayName, DefaultMfaMethod, MethodsRegistered
}

Export-ModuleMember -Function Initialize-AdminAndPimSession, Get-AdminRoleMembership, Get-PIMEligible, Get-AdminRoleHolders, Get-UserRegistrationDetailsById, Get-AdminAccountsWithoutMfa
