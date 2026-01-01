<#
.SYNOPSIS
  Runs local cryptographic inventory collectors and writes JSON + CSV outputs.

.DESCRIPTION
  Orchestrates read-only collection:
    - Windows certificate stores
    - SCHANNEL TLS posture
    - IIS HTTPS bindings (optional)
    - WinRM listeners (optional)
    - OpenSSH posture (optional)

  Produces:
    - crypto_inventory.json (structured inventory)
    - findings.csv (prioritized certificate hygiene + PQC relevance backlog)

.NOTES
  Read-only by default. No credential storage. Designed for local execution.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TargetsConfig,

    [Parameter(Mandatory)]
    [string]$ScoringConfig,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [switch]$IncludeIIS,
    [switch]$IncludeWinRM,
    [switch]$IncludeOpenSSH
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Folder {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Read-Yaml {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw

    if (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
        return ($raw | ConvertFrom-Yaml)
    }

    throw "ConvertFrom-Yaml not available. Install the 'powershell-yaml' module or use a PowerShell build that provides YAML support."
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Path
    )

    $Object | ConvertTo-Json -Depth 12 | Out-File -FilePath $Path -Encoding UTF8
}

# Ensure output folder exists
New-Folder -Path $OutputPath

# Load configuration
$targets = Read-Yaml -Path $TargetsConfig
$scoring = Read-Yaml -Path $ScoringConfig

# Load collectors
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptRoot 'Collect-WindowsCerts.ps1')
. (Join-Path $scriptRoot 'Collect-TlsConfig.ps1')
. (Join-Path $scriptRoot 'Collect-IISBindings.ps1')
. (Join-Path $scriptRoot 'Collect-WinRMListeners.ps1')
. (Join-Path $scriptRoot 'Collect-OpenSSHConfig.ps1')

# Host metadata
$os = Get-CimInstance Win32_OperatingSystem
$hostInfo = @{
    computerName = $env:COMPUTERNAME
    osCaption    = $os.Caption
    osVersion    = $os.Version
}

# Inventory object
$inventory = [ordered]@{
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    org            = @{
        name                     = $targets.org.name
        owner                    = $targets.org.owner
        dataConfidentialityYears = [double]$targets.org.data_confidentiality_years
    }
    host           = $hostInfo
    artifacts      = @{
        certificates = @()
        tlsConfig     = @()
        iisBindings   = @()
        winrm         = @()
        openssh       = @()
    }
}

# Collect artifacts
$inventory.artifacts.certificates = Collect-WindowsCerts
$inventory.artifacts.tlsConfig    = Collect-TlsConfig

if ($IncludeIIS)     { $inventory.artifacts.iisBindings = Collect-IISBindings }
if ($IncludeWinRM)   { $inventory.artifacts.winrm       = Collect-WinRMListeners }
if ($IncludeOpenSSH) { $inventory.artifacts.openssh     = Collect-OpenSSHConfig }

# Build findings from certificates (v1 backlog)
$findings = New-Object System.Collections.Generic.List[object]

$rsaMinBits      = [int]$scoring.thresholds.rsa_min_bits
$expiresSoonDays = [int]$scoring.thresholds.expires_soon_days

foreach ($c in $inventory.artifacts.certificates) {
    $score = 0
    $notes = New-Object System.Collections.Generic.List[string]

    # PQC relevance (public-key types)
    if ($c.PublicKeyAlgorithm -match 'RSA') {
        $score += [int]$scoring.weights.pqc_relevance.rsa
    } elseif ($c.PublicKeyAlgorithm -match 'ECDSA|ECC') {
        $score += [int]$scoring.weights.pqc_relevance.ecc
    } elseif ($c.PublicKeyAlgorithm -match 'DH') {
        $score += [int]$scoring.weights.pqc_relevance.dh
    } else {
        $score += [int]$scoring.weights.pqc_relevance.unknown_public_key
    }

    # Hygiene: SHA-1 signatures
    if ($c.SignatureHashAlgorithm -match 'sha1') {
        $score += [int]$scoring.weights.hygiene.sha1_signature
        $notes.Add('SHA-1 signature algorithm')
    }

    # Hygiene: weak RSA key size
    if (($c.PublicKeyAlgorithm -match 'RSA') -and ($c.PublicKeyBits -lt $rsaMinBits)) {
        $score += [int]$scoring.weights.hygiene.weak_rsa_key
        $notes.Add("RSA key < $rsaMinBits bits")
    }

    # Hygiene: expiry
    $now = Get-Date
    if ($c.NotAfter -lt $now) {
        $score += [int]$scoring.weights.hygiene.expired_cert
        $notes.Add('Certificate expired')
    } else {
        $daysLeft = (New-TimeSpan -Start $now -End $c.NotAfter).Days
        if ($daysLeft -le $expiresSoonDays) {
            $score += [int]$scoring.weights.hygiene.expires_soon_score
            $notes.Add("Certificate expires within $expiresSoonDays days")
        }
    }

    # Longevity bump (if configured)
    if ($scoring.weights.longevity.enabled -eq $true) {
        $thresholdYears = [double]$scoring.weights.longevity.years_threshold
        $dataYears      = [double]$inventory.org.dataConfidentialityYears

        if ($dataYears -ge $thresholdYears -and ($c.PublicKeyAlgorithm -match 'RSA|ECDSA|ECC|DH')) {
            $score += [int]$scoring.weights.longevity.add_score
            $notes.Add("Long-lived confidentiality >= $thresholdYears years")
        }
    }

    # Severity band
    $severity = 'low'
    if ($score -ge [int]$scoring.severity_bands.critical) { $severity = 'critical' }
    elseif ($score -ge [int]$scoring.severity_bands.high) { $severity = 'high' }
    elseif ($score -ge [int]$scoring.severity_bands.medium) { $severity = 'medium' }

    $findings.Add([pscustomobject]@{
        Host               = $env:COMPUTERNAME
        ArtifactType       = 'Certificate'
        Store              = $c.Store
        Subject            = $c.Subject
        Issuer             = $c.Issuer
        Thumbprint         = $c.Thumbprint
        PublicKeyAlgorithm = $c.PublicKeyAlgorithm
        PublicKeyBits      = $c.PublicKeyBits
        SignatureHash      = $c.SignatureHashAlgorithm
        NotAfter           = $c.NotAfter
        Severity           = $severity
        Score              = $score
        Notes              = ($notes -join '; ')
    })
}

# Write outputs
$outInventory = Join-Path $OutputPath 'crypto_inventory.json'
$outFindings  = Join-Path $OutputPath 'findings.csv'

Write-JsonFile -Object $inventory -Path $outInventory
$findings | Sort-Object Score -Descending | Export-Csv -NoTypeInformation -Path $outFindings

Write-Host "Wrote: $outInventory"
Write-Host "Wrote: $outFindings"
