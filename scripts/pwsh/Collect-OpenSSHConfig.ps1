function Collect-OpenSSHConfig {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $results = New-Object System.Collections.Generic.List[object]

    $sshdConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'

    if (-not (Test-Path -LiteralPath $sshdConfigPath)) {
        $results.Add([pscustomobject]@{
            Source = 'OpenSSH'
            Note   = 'sshd_config not found. OpenSSH Server may not be installed.'
        })
        return $results
    }

    $lines = Get-Content -LiteralPath $sshdConfigPath -ErrorAction Stop

    # Best-effort posture checks: host keys and any explicit algorithm directives if present.
    $hostKeyLines = $lines | Where-Object { $_ -match '^\s*HostKey\s+' }
    $kexLines     = $lines | Where-Object { $_ -match '^\s*KexAlgorithms\s+' }
    $cipherLines  = $lines | Where-Object { $_ -match '^\s*Ciphers\s+' }
    $macLines     = $lines | Where-Object { $_ -match '^\s*MACs\s+' }
    $hostKeyAlgo  = $lines | Where-Object { $_ -match '^\s*HostKeyAlgorithms\s+' }
    $pubKeyAlgo   = $lines | Where-Object { $_ -match '^\s*PubkeyAcceptedAlgorithms\s+' }

    $results.Add([pscustomobject]@{
        Source                    = 'OpenSSH'
        ConfigPath                = $sshdConfigPath
        HostKeyLines              = if ($hostKeyLines) { ($hostKeyLines -join '; ') } else { $null }
        HostKeyAlgorithms         = if ($hostKeyAlgo)  { ($hostKeyAlgo -join '; ') }  else { $null }
        PubkeyAcceptedAlgorithms  = if ($pubKeyAlgo)   { ($pubKeyAlgo -join '; ') }   else { $null }
        KexAlgorithms             = if ($kexLines)     { ($kexLines -join '; ') }     else { $null }
        Ciphers                   = if ($cipherLines)  { ($cipherLines -join '; ') }  else { $null }
        MACs                      = if ($macLines)     { ($macLines -join '; ') }     else { $null }
    })

    return $results
}
