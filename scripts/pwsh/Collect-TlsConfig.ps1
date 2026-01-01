function Collect-TlsConfig {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $results = New-Object System.Collections.Generic.List[object]

    $protocolsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

    if (-not (Test-Path -LiteralPath $protocolsPath)) {
        $results.Add([pscustomobject]@{
            Source = 'SCHANNEL'
            Note   = 'SCHANNEL Protocols registry path not found.'
        })
        return $results
    }

    # Enumerate protocol enable/disable posture (coarse, registry-driven)
    Get-ChildItem -Path $protocolsPath -ErrorAction SilentlyContinue | ForEach-Object {
        $protocolName = $_.PSChildName

        foreach ($role in @('Client', 'Server')) {
            $rolePath = Join-Path $_.PSPath $role

            if (-not (Test-Path -LiteralPath $rolePath)) {
                continue
            }

            $props = Get-ItemProperty -Path $rolePath -ErrorAction SilentlyContinue

            # In StrictMode, accessing a missing property throws. Use safe reads.
            $enabled = $null
            $disabledByDefault = $null

            if ($props -and ($props.PSObject.Properties.Name -contains 'Enabled')) {
                $enabled = $props.Enabled
            }
            if ($props -and ($props.PSObject.Properties.Name -contains 'DisabledByDefault')) {
                $disabledByDefault = $props.DisabledByDefault
            }

            $results.Add([pscustomobject]@{
                Source            = 'SCHANNEL'
                Protocol          = $protocolName
                Role              = $role
                Enabled           = $enabled
                DisabledByDefault = $disabledByDefault
                RegistryPath      = $rolePath
            })
        }
    }

    # Cipher suite policy (best-effort)
    $cipherSuitePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    if (Test-Path -LiteralPath $cipherSuitePolicyPath) {
        $policyProps = Get-ItemProperty -Path $cipherSuitePolicyPath -ErrorAction SilentlyContinue

        $functions = $null
        if ($policyProps -and ($policyProps.PSObject.Properties.Name -contains 'Functions')) {
            $functions = $policyProps.Functions
        }

        $results.Add([pscustomobject]@{
            Source       = 'CipherSuitesPolicy'
            CipherSuites = if ($functions) { ($functions -join ', ') } else { $null }
            RegistryPath = $cipherSuitePolicyPath
        })
    }

    return $results
}
