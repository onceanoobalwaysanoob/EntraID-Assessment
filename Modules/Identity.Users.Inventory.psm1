# session connection with required scopes
$script:InvRequiredScopes = @('Directory.Read.All','User.Read.All','AuditLog.Read.All')

[OutputType([pscustomobject])]
function Initialize-UsersInventorySession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global',
    [switch] $UseBeta
  )
  # Validate or connect using Core.Graph
  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $script:InvRequiredScopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId `
                          -RequiredScopes $script:InvRequiredScopes `
                          -Environment $Environment `
                          -UseBeta:$UseBeta
  }
}

# collection
## retrieve all users
[OutputType([pscustomobject])]
function Get-UserInventory {
    [CmdletBinding()]
    param(
        [int] $PageSize = 999,
        [string] $TenantId,
        [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
        [string] $Environment = 'Global',
        [switch] $UseBeta
    )
    Initialize-UsersInventorySession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta

    try {
        $properties = @(
            'id','displayName','userPrincipalName','accountEnabled',
            'onPremisesSyncEnabled','assignedLicenses','userType',
            'signInActivity','createdDateTime','lastPasswordChangeDateTime',
            'passwordPolicies'
        )
        $allUsers = Get-MgUser -All -PageSize $PageSize -Property ($properties -join ',') -ErrorAction Stop
        $allUsers | Select-Object Id, DisplayName, UserPrincipalName, AccountEnabled, UserType,
                    AssignedLicenses, CreatedDateTime, LastPasswordChangeDateTime, PasswordPolicies,
                    @{N='IsSynced';E={[bool]$_.OnPremisesSyncEnabled}},
                    @{N='LastSuccessfulSignInDateTime';E={$_.SignInActivity.LastSuccessfulSignInDateTime}},
                    @{N='LastSignInDateTime';E={$_.SignInActivity.LastSignInDateTime}},
                    @{N='TenantId';E={ (Get-MgContext).TenantId }},
                    @{N='CollectedAt';E={ [DateTimeOffset]::UtcNow }},
                    @{N='Source';E={ 'Graph/v1.0:users' }}
    } catch {
        throw "Error retrieving users: $($_.Exception.Message)"
    }
}

## enabled users
[OutputType([pscustomobject])]
function Get-EnabledUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.AccountEnabled } }
}

## disabled users
[OutputType([pscustomobject])]
function Get-DisabledUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { -not $_.AccountEnabled } }
}

## cloud users
[OutputType([pscustomobject])]
function Get-CloudUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { ($_.UserType -eq 'Member') -and (-not $_.IsSynced) } }
}

## on-premises synced users
[OutputType([pscustomobject])]
function Get-SyncedUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.IsSynced } }
}

## guest users
[OutputType([pscustomobject])]
function Get-GuestUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.UserType -ne 'Member' } }
}

## licensed users
[OutputType([pscustomobject])]
function Get-LicensedUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.AssignedLicenses.Count -gt 0 } }
}

## unlicensed users
[OutputType([pscustomobject])]
function Get-UnlicensedUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.AssignedLicenses.Count -eq 0  } }
}

## active users
[OutputType([pscustomobject])]
function Get-ActiveUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.LastSuccessfulSignInDateTime  } }
}

## inactive users
[OutputType([pscustomobject])]
function Get-StaleUsers {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $allUsers,
        [int] $Days = 90
    )
    begin {
        $threshold = [datetimeoffset](Get-Date).AddDays(-1 * $Days)
    }
    process { 
        $allUsers | Where-Object { -not $_.LastSuccessfulSignInDateTime -or ([datetimeoffset]$_.LastSuccessfulSignInDateTime) -lt $threshold  } 
    }
}

## get users with non expiring passwords
[OutputType([pscustomobject])]
function Get-UsersWithNonExpiringPasswords {
    [CmdletBinding()] 
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.PasswordPolicies -match 'DisablePasswordExpiration' } }
}

## get users password change dates
[OutputType([pscustomobject])]
function Get-UserPasswordChangeDates {
    [CmdletBinding()] 
    param(
        [Parameter(ValueFromPipeline)] $allUsers
    )
    process { $allUsers | Where-Object { $_.LastPasswordChangeDateTime } | Select-Object DisplayName,UserPrincipalName,LastPasswordChangeDateTime }
}

Export-ModuleMember -Function Get-UserInventory, Get-EnabledUsers, Get-DisabledUsers, Get-CloudUsers, Get-SyncedUsers, Get-GuestUsers, Get-LicensedUsers, Get-UnlicensedUsers, Get-ActiveUsers, Get-StaleUsers, Get-UsersWithNonExpiringPasswords, Get-UserPasswordChangeDates, Initialize-UsersInventorySession
