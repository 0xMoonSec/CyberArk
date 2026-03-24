#Requires -Version 5.1
###############################################################################
#
# NAME   : CyberArk-ChangePlatform.ps1
#
# DESCRIPTION:
#   Reads a CSV list of CyberArk account IDs and changes their Platform ID
#   on the same PVWA using the REST API.
#
# CSV FORMAT (accounts.csv):
#   AccountId,TargetPlatformId
#   12345abc-...,WinDomainAccounts
#   67890def-...,WinDomainAccounts
#
# OUTPUT:
#   - Color-coded console output
#   - Migration report : PlatformMigration_<timestamp>.csv
#   - Log file         : PlatformMigration_<timestamp>.log
#
# EXAMPLES:
#   # Normal run
#   .\CyberArk-ChangePlatform.ps1 `
#       -PvwaUrl "https://pvwa.company.com" `
#       -CsvPath ".\accounts.csv" `
#       -AuthType CyberArk
#
#   # Dry run — no changes made
#   .\CyberArk-ChangePlatform.ps1 `
#       -PvwaUrl "https://pvwa.company.com" `
#       -CsvPath ".\accounts.csv" `
#       -AuthType CyberArk `
#       -WhatIf
#
#   # Skip SSL validation (dev/test only)
#   .\CyberArk-ChangePlatform.ps1 ... -SkipCertCheck
#
###############################################################################

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $PvwaUrl,    # e.g. https://pvwa.company.com
    [Parameter(Mandatory)] [string] $CsvPath,    # Path to input CSV file
    [Parameter(Mandatory)]
    [ValidateSet("CyberArk","LDAP","RADIUS","Windows")]
    [string] $AuthType,
    [switch] $WhatIf,                            # Dry run — no changes made
    [switch] $SkipCertCheck                      # Disable SSL validation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

###############################################################################
# OUTPUT FILES
###############################################################################
$ts         = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile    = "PlatformMigration_$ts.log"
$ReportFile = "PlatformMigration_$ts.csv"
$Report     = [System.Collections.Generic.List[PSObject]]::new()

###############################################################################
# LOGGING HELPER
###############################################################################
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $time  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green"  }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        "HEADER"  { "Cyan"   }
        default   { "White"  }
    }
    $line = "[$time] [$Level] $Msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

###############################################################################
# REPORT HELPER
###############################################################################
function Add-Report {
    param(
        [string]$AccountId,
        [string]$AccountName,
        [string]$Safe,
        [string]$OldPlatform,
        [string]$NewPlatform,
        [string]$Status,
        [string]$Detail
    )
    $Report.Add([PSCustomObject]@{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        AccountId   = $AccountId
        AccountName = $AccountName
        Safe        = $Safe
        OldPlatform = $OldPlatform
        NewPlatform = $NewPlatform
        Status      = $Status
        Detail      = $Detail
    })
}

###############################################################################
# TLS
###############################################################################
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($SkipCertCheck) {
    Write-Log "SSL certificate validation is DISABLED — use only in dev/test environments." "WARN"
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
}

###############################################################################
# API WRAPPER
###############################################################################
function Invoke-PvwaApi {
    param(
        [string] $Method,
        [string] $Endpoint,
        [string] $Token,
        [object] $Body = $null
    )
    $uri     = "$PvwaUrl/PasswordVault/API/$Endpoint"
    $headers = @{ "Content-Type" = "application/json" }
    if ($Token) { $headers["Authorization"] = $Token }

    $params = @{ Uri = $uri; Method = $Method; Headers = $headers }
    if ($Body) { $params["Body"] = ($Body | ConvertTo-Json -Depth 10) }

    try {
        return Invoke-RestMethod @params
    } catch {
        $detail = $_.ErrorDetails.Message ?? $_.Exception.Message
        throw "API [$Method $Endpoint] failed: $detail"
    }
}

###############################################################################
# AUTHENTICATION
###############################################################################
function Get-AuthToken {
    $cred  = Get-Credential -Message "Enter CyberArk credentials for $PvwaUrl"
    $plain = $cred.GetNetworkCredential().Password

    $body = switch ($AuthType) {
        "Windows" { $null }
        default   { @{ username = $cred.UserName; password = $plain } }
    }

    $ep     = "auth/$AuthType/Logon"
    $params = @{ Method = "POST"; Endpoint = $ep }
    if ($body) { $params["Body"] = $body }
    if ($AuthType -eq "Windows") {
        # Windows auth uses default credentials — bypass Invoke-PvwaApi
        $uri = "$PvwaUrl/PasswordVault/API/$ep"
        return (Invoke-RestMethod -Uri $uri -Method POST -UseDefaultCredentials).Trim('"')
    }

    $token = Invoke-PvwaApi @params
    Write-Log "Authenticated to $PvwaUrl as [$($cred.UserName)]" "SUCCESS"
    return $token.Trim('"')
}

function Invoke-Logoff {
    param([string]$Token)
    try {
        Invoke-PvwaApi -Method POST -Endpoint "auth/Logoff" -Token $Token | Out-Null
        Write-Log "Logged off from $PvwaUrl"
    } catch {
        Write-Log "Logoff warning: $_" "WARN"
    }
}

###############################################################################
# VALIDATE CSV
###############################################################################
function Import-AccountCsv {
    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    $rows = Import-Csv -Path $CsvPath

    # Validate required columns
    $cols = $rows | Select-Object -First 1 | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    if ("AccountId" -notin $cols) {
        throw "CSV is missing required column: 'AccountId'"
    }
    if ("TargetPlatformId" -notin $cols) {
        throw "CSV is missing required column: 'TargetPlatformId'"
    }

    # Filter out blank rows
    $valid = $rows | Where-Object { $_.AccountId -and $_.TargetPlatformId }
    Write-Log "CSV loaded: $($valid.Count) valid rows from '$CsvPath'"
    return $valid
}

###############################################################################
# GET ACCOUNT DETAILS
###############################################################################
function Get-Account {
    param([string]$AccountId, [string]$Token)
    return Invoke-PvwaApi -Method GET -Endpoint "Accounts/$AccountId" -Token $Token
}

###############################################################################
# CHANGE PLATFORM (PATCH)
###############################################################################
function Set-AccountPlatform {
    param([string]$AccountId, [string]$NewPlatformId, [string]$Token)

    # Uses JSON Patch (RFC 6902) — PATCH /Accounts/{id}
    $patchBody = @(
        @{
            op    = "replace"
            path  = "/platformId"
            value = $NewPlatformId
        }
    )
    Invoke-PvwaApi -Method PATCH -Endpoint "Accounts/$AccountId" -Token $Token -Body $patchBody | Out-Null
}

###############################################################################
# BANNER
###############################################################################
Write-Log "═══════════════════════════════════════════════════" "HEADER"
Write-Log "  CyberArk Platform Migration — Change Platform ID"  "HEADER"
Write-Log "  PVWA   : $PvwaUrl"                                  "HEADER"
Write-Log "  CSV    : $CsvPath"                                   "HEADER"
Write-Log "  WhatIf : $($WhatIf.IsPresent)"                      "HEADER"
Write-Log "═══════════════════════════════════════════════════" "HEADER"

###############################################################################
# MAIN
###############################################################################

# Step 1 — Load CSV
$rows = Import-AccountCsv

# Step 2 — Authenticate
Write-Log "Authenticating..."
$token = Get-AuthToken

# Step 3 — Process each row
$total   = $rows.Count
$success = 0
$skipped = 0
$failed  = 0
$i       = 0

foreach ($row in $rows) {
    $i++
    $accountId       = $row.AccountId.Trim()
    $targetPlatform  = $row.TargetPlatformId.Trim()

    Write-Log "($i/$total) AccountId: $accountId → Platform: $targetPlatform"

    # Fetch current account details
    $acct = $null
    try {
        $acct = Get-Account -AccountId $accountId -Token $token
    } catch {
        Write-Log "  Could not retrieve account '$accountId': $_" "ERROR"
        Add-Report $accountId "N/A" "N/A" "N/A" $targetPlatform "FAILED" "Could not retrieve account: $_"
        $failed++
        continue
    }

    $currentPlatform = $acct.platformId
    $accountName     = $acct.name       ?? "$($acct.userName)@$($acct.address)"
    $safeName        = $acct.safeName

    Write-Log "  Name     : $accountName"
    Write-Log "  Safe     : $safeName"
    Write-Log "  Platform : $currentPlatform → $targetPlatform"

    # Skip if already on the target platform
    if ($currentPlatform -eq $targetPlatform) {
        Write-Log "  Already on platform '$targetPlatform' — skipping." "WARN"
        Add-Report $accountId $accountName $safeName $currentPlatform $targetPlatform "SKIPPED" "Already on target platform"
        $skipped++
        continue
    }

    # WhatIf — no changes
    if ($WhatIf) {
        Write-Log "  [WHATIF] Would change platform: '$currentPlatform' → '$targetPlatform'" "WARN"
        Add-Report $accountId $accountName $safeName $currentPlatform $targetPlatform "WHATIF" "Would change platform (dry run)"
        $skipped++
        continue
    }

    # Apply the platform change
    try {
        Set-AccountPlatform -AccountId $accountId -NewPlatformId $targetPlatform -Token $token
        Write-Log "  Platform changed successfully." "SUCCESS"
        Add-Report $accountId $accountName $safeName $currentPlatform $targetPlatform "SUCCESS" "Platform updated"
        $success++
    } catch {
        Write-Log "  FAILED to change platform: $_" "ERROR"
        Add-Report $accountId $accountName $safeName $currentPlatform $targetPlatform "FAILED" $_
        $failed++
    }
}

###############################################################################
# LOGOFF
###############################################################################
Invoke-Logoff -Token $token

###############################################################################
# EXPORT REPORT
###############################################################################
$Report | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8
Write-Log "Report saved to: $ReportFile"

###############################################################################
# SUMMARY
###############################################################################
Write-Log "═══════════════════════════════════════════════════" "HEADER"
Write-Log "  SUMMARY"                                           "HEADER"
Write-Log "  Total in CSV : $total"                             "HEADER"
Write-Log "  Succeeded    : $success"                           "HEADER"
Write-Log "  Skipped      : $skipped"                           "HEADER"
Write-Log "  Failed       : $failed"                            "HEADER"
Write-Log "  Report       : $ReportFile"                        "HEADER"
Write-Log "  Log          : $LogFile"                           "HEADER"
Write-Log "═══════════════════════════════════════════════════" "HEADER"

if ($failed -gt 0) { exit 1 } else { exit 0 }