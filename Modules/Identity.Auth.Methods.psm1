# session connection with required scopes
$script:AuthRequiredScopes = @('UserAuthenticationMethod.Read.All','User.Read.All','Directory.Read.All')

function Initialize-AuthMethodsSession {
  [CmdletBinding()]
  param(
    [string] $TenantId,
    [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
    [string] $Environment = 'Global',
    [switch] $UseBeta
  )
  if (-not (Test-GraphConnection -TenantId $TenantId -RequiredScopes $script:AuthRequiredScopes)) {
    Connect-GraphIfNeeded -TenantId $TenantId `
                          -RequiredScopes $script:AuthRequiredScopes `
                          -Environment $Environment `
                          -UseBeta:$UseBeta
  }
}

## authentication methods
[OutputType([pscustomobject])]
function Get-UserAuthenticationMethods {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $allUsers,
        [int] $ThrottleLimit = 8
        [string] $TenantId,
        [ValidateSet('Global','USGov','USGovHigh','USGovDoD','China')]
        [string] $Environment = 'Global',
        [switch] $UseBeta
    )   
    Initialize-AuthMethodsSession -TenantId $TenantId -Environment $Environment -UseBeta:$UseBeta

    begin { 
      $bag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
      $tenantId = (Get-MgContext).TenantId
    }
    process {
        $allUsers | ForEach-Object -Parallel {
        param($u, $tid)
        $obj = [pscustomobject]@{
            DisplayName           = $u.DisplayName
            UserPrincipalName     = $u.UserPrincipalName
            ObjectId              = $u.Id
            UserType              = $u.UserType
            MFARegisteredCount    = 0
            MFAStatus             = 'No MFA Registered'
            AuthenticatorApp      = $false
            FIDO2                 = $false
            WindowsHello          = $false
            SoftwareOATH          = $false
            Phone                 = $false
            HasSmsOrVoice         = $false
            Email                 = $false      # not MFA, informational
            Certificate           = $false
            TemporaryAccessPass   = $false      # bootstrap
            HasPhishingResistant  = $false
            AuthStrength          = 'None'
            MethodODataTypes      = @()
            CollectedAt           = [DateTimeOffset]::UtcNow
            Source                = 'Graph/v1.0:users/{id}/authentication/methods'
            TenantId              = $tid
        }
        try {
          # Get-MgUserAuthenticationMethod is a hot path and often hits 429/5xx
          #iny backoff to reduce random gaps
          $attempt = 0; $max = 3
          do {
              try {
                  $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
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
            $obj | Add-Member -NotePropertyName 'Error' -NotePropertyValue $err.Exception.Message -Force 
          }
            
          if ($methods) {
          $obj.MFARegisteredCount = $methods.Count
          foreach ($m in $methods) {
              $t = $m.AdditionalProperties['@odata.type']
              if ($t) { $obj.MethodODataTypes += $t }
              switch ($t) {
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { $obj.AuthenticatorApp = $true }
                '#microsoft.graph.fido2AuthenticationMethod'                  { $obj.FIDO2 = $true }
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'{ $obj.WindowsHello = $true }
                '#microsoft.graph.softwareOathAuthenticationMethod'           { $obj.SoftwareOATH = $true }
                '#microsoft.graph.phoneAuthenticationMethod'                  { $obj.Phone = $true; $obj.HasSmsOrVoice = $true }
                '#microsoft.graph.emailAuthenticationMethod'                  { $obj.Email = $true } # not MFA
                '#microsoft.graph.temporaryAccessPassAuthenticationMethod'    { $obj.TemporaryAccessPass = $true }
                '#microsoft.graph.x509CertificateAuthenticationMethod'        { $obj.Certificate = $true }
              }
          }

          $hasPhishRes = $obj.FIDO2 -or $obj.WindowsHello -or $obj.Certificate
          if ($hasPhishRes) {
            $obj.AuthStrength = 'Phishing-Resistant'
            $obj.HasPhishingResistant = $true
            $obj.MFAStatus = 'Enabled'
          } elseif ($obj.AuthenticatorApp -or $obj.SoftwareOATH) {
            $obj.AuthStrength = 'Strong'
            $obj.MFAStatus = 'Enabled'
          } elseif ($obj.Phone) {
            $obj.AuthStrength = 'Weak'
            $obj.MFAStatus = 'Enabled'
          } else {
            $obj.AuthStrength = 'None'
            if ($obj.Email -or $obj.TemporaryAccessPass) { 
              $obj.MFAStatus = 'No MFA Registered' 
            }
          }
        }
      } catch {
          $obj | Add-Member -NotePropertyName 'Error' -NotePropertyValue $_.Exception.Message -Force
        }
      [void]$using:bag.Add($obj)
    } -ThrottleLimit $ThrottleLimit -ArgumentList $tenantId
  }
  end { $bag.ToArray() }
}

## get guests without known MFA
[OutputType([pscustomobject])]
function Get-GuestsWithoutKnownMFA {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $UsersAuth
  )
  $UsersAuth |
    Where-Object { $_.UserType -ne 'Member' -and $_.AuthStrength -eq 'None' } |
    Select-Object ObjectId, DisplayName, UserPrincipalName, UserType,
      @{N='MFAObservation';E={'No local MFA methods; guest may be MFA-enforced at external IdP. Verify CA excludes and cross-tenant access settings.'}}
}

Export-ModuleMember -Function Initialize-AuthMethodsSession, Get-UserAuthenticationMethods, Get-GuestsWithoutKnownMFA
