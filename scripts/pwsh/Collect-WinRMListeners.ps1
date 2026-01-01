function Collect-WinRMListeners {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $results = New-Object System.Collections.Generic.List[object]

    try {
        # Returns text blocks; we keep this best-effort and read-only.
        $raw = & winrm enumerate winrm/config/Listener 2>$null

        if (-not $raw) {
            $results.Add([pscustomobject]@{
                Source = 'WinRM'
                Note   = 'No listeners returned. WinRM may be disabled, not configured, or access was denied.'
            })
            return $results
        }

        # Parse into blocks separated by blank lines.
        $current = New-Object System.Collections.Generic.List[string]

        foreach ($line in $raw) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                if ($current.Count -gt 0) {
                    $results.Add([pscustomobject]@{
                        Source = 'WinRM'
                        Raw    = ($current -join "`n")
                    })
                    $current.Clear()
                }
                continue
            }

            $current.Add($line)
        }

        if ($current.Count -gt 0) {
            $results.Add([pscustomobject]@{
                Source = 'WinRM'
                Raw    = ($current -join "`n")
            })
        }

    } catch {
        $results.Add([pscustomobject]@{
            Source = 'WinRM'
            Note   = $_.Exception.Message
        })
    }

    return $results
}
