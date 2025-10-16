$script:GraphLastFailure = $null

function Test-GraphConnection {
    [CmdletBinding()]
    param(
        [string]   $TenantId,
        [string[]] $RequiredScopes = @()  # minimal set the caller needs
    )

    $context = Get-MgContext
    if (-not $context) {
        $script:GraphLastFailure = 'NoContext'
        return $false
    }

    if ($TenantId -and $context.TenantId -and $context.TenantId -ne $TenantId) {
        Write-Warning "Connected to tenant $($context.TenantId) but requested $TenantId!"
    }

    # Delegated-only: enforce scope superset (case-insensitive)
    if ($RequiredScopes -and $RequiredScopes.Count -gt 0) {
        $connScopes = @($context.Scopes | ForEach-Object { $_.ToLowerInvariant() })
        $reqNorm    = @($RequiredScopes   | ForEach-Object { $_.ToLowerInvariant() })
        $missing    = $reqNorm | Where-Object { $_ -notin $connScopes }
        if ($missing) {
            Write-Warning "Current token missing delegated scopes: $($missing -join ', ')"
            $script:GraphLastFailure = 'MissingScopes'
            return $false
        }
    }

    # Token freshness probe (delegated)
    try {
        Get-MgUser -Top 1 -ErrorAction Stop | Out-Null
    } catch {
        $script:GraphLastFailure = 'ProbeFailedDelegated'
        return $false
    }

    return $true
}

function Connect-GraphIfNeeded {
    [CmdletBinding()]
    param(
        [string]   $TenantId,
        [string[]] $RequiredScopes = @('Directory.Read.All','User.Read.All'),  # minimal default
        [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
        [string]   $Environment = 'Global',
        [switch]   $UseBeta
    )

    # Warn if currently connected to a different cloud environment
    $ctx = Get-MgContext
    if ($ctx -and $ctx.Environment -and $ctx.Environment -ne $Environment) {
        Write-Warning "Connected environment is '$($ctx.Environment)' but requested '$Environment'."
    }

    if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $RequiredScopes)) {
        Write-Host "Connecting to Microsoft Graph" -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        try {
            $profile = (Get-MgProfile) -as [string]
            if ($UseBeta -and ($profile -ne 'beta')) {
                Select-MgProfile -Name Beta | Out-Null
            }

            Connect-MgGraph -TenantId $TenantId `
                            -Scopes   $RequiredScopes `
                            -Environment $Environment `
                            -NoWelcome

            Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
        } catch {
            throw "Error connecting to Microsoft Graph: $($_.Exception.Message)"
        }
    } else {
        # Switch profile if needed on an existing connection
        $profile = (Get-MgProfile) -as [string]
        if ($UseBeta -and ($profile -ne 'beta')) {
            try { Select-MgProfile -Name Beta | Out-Null } catch { Write-Warning "Failed to switch to Beta profile: $($_.Exception.Message)" }
        }
        Write-Host "Using existing Microsoft Graph connection" -ForegroundColor Green
    }
}

function Ensure-Feature {
    <#
      Verifies a feature is allowed by config and licensed in the tenant.
      FeatureName: IdentityProtection | PIM | ConditionalAccess | Reports
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('IdentityProtection','PIM','ConditionalAccess','Reports')]
        [string] $FeatureName,

        [hashtable] $Config,
        [switch]    $Quiet
    )

    # Config gate (optional)
    if ($Config -and $Config.ContainsKey('Features')) {
        $feat = $Config.Features[$FeatureName]
        if ($feat -is [bool] -and -not $feat) {
            $msg = "Feature '$FeatureName' is disabled by configuration."
            if ($Quiet) { Write-Verbose $msg; return $false } else { throw $msg }
        }
    }

    # Licensing inference (skip for Reports)
    if ($FeatureName -ne 'Reports') {
        try {
            $skus = Get-MgSubscribedSku -ErrorAction Stop
        } catch {
            $msg = "Unable to read subscribed SKUs to verify licensing for '$FeatureName': $($_.Exception.Message)"
            if ($Quiet) { Write-Verbose $msg; return $false } else { throw $msg }
        }

        $skuParts = @($skus | ForEach-Object { $_.SkuPartNumber })  # e.g., AAD_PREMIUM, AAD_PREMIUM_P2, EMSPREMIUM, SPE_E5, M365_E5
        $hasP2 = $skuParts -match 'AAD_PREMIUM_P2' -or $skuParts -match 'E5' -or $skuParts -match 'EMSPREMIUM'
        $hasP1 = $skuParts -match 'AAD_PREMIUM(?!_P2)' -or $hasP2  # P2 implies P1

        switch ($FeatureName) {
            'IdentityProtection' {
                if (-not $hasP2) {
                    $msg = "Identity Protection requires Entra ID P2 (or an E5 bundle). Not detected in tenant SKUs: $($skuParts -join ', ')."
                    if ($Quiet) { Write-Verbose $msg; return $false } else { throw $msg }
                }
            }
            'PIM' {
                if (-not $hasP2) {
                    $msg = "PIM requires Entra ID P2 (or an E5 bundle). Not detected in tenant SKUs: $($skuParts -join ', ')."
                    if ($Quiet) { Write-Verbose $msg; return $false } else { throw $msg }
                }
            }
            'ConditionalAccess' {
                if (-not $hasP1) {
                    $msg = "Conditional Access requires Entra ID P1 or higher. Not detected in tenant SKUs: $($skuParts -join ', ')."
                    if ($Quiet) { Write-Verbose $msg; return $false } else { throw $msg }
                }
            }
        }
    }

    return $true
}

Export-ModuleMember -Function Test-GraphConnection, Connect-GraphIfNeeded, Ensure-Feature
