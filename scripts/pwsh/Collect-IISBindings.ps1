function Collect-IISBindings {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $results = New-Object System.Collections.Generic.List[object]

    # IIS inventory requires WebAdministration (present when IIS management tools/features are installed)
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        $results.Add([pscustomobject]@{
            Source = 'IIS'
            Note   = 'WebAdministration module not available. IIS may not be installed, or management tools are missing.'
        })
        return $results
    }

    Import-Module WebAdministration -ErrorAction Stop

    $sitesPath = 'IIS:\Sites'
    if (-not (Test-Path -LiteralPath $sitesPath)) {
        $results.Add([pscustomobject]@{
            Source = 'IIS'
            Note   = 'IIS:\Sites provider path not found. IIS may not be installed.'
        })
        return $results
    }

    Get-ChildItem -Path $sitesPath | ForEach-Object {
        $siteName = $_.Name

        Get-WebBinding -Name $siteName | ForEach-Object {
            $binding = $_

            $certThumbprint = $null
            $sslFlags = $null

            if ($binding.protocol -eq 'https') {
                # Attempt to resolve the SSL binding for this IP:port:host tuple
                try {
                    $bindingInfo = $binding.bindingInformation
                    $sslItemPath = "IIS:\SslBindings\$bindingInfo"

                    if (Test-Path -LiteralPath $sslItemPath) {
                        $sslItem = Get-Item -Path $sslItemPath -ErrorAction SilentlyContinue
                        if ($sslItem) {
                            $certThumbprint = $sslItem.Thumbprint
                            $sslFlags = $sslItem.SslFlags
                        }
                    }
                } catch {
                    # Best-effort only; do not fail the collector if an SSL binding cannot be resolved
                }
            }

            $results.Add([pscustomobject]@{
                Source                = 'IIS'
                Site                  = $siteName
                Protocol              = $binding.protocol
                BindingInformation    = $binding.bindingInformation
                CertificateThumbprint = $certThumbprint
                SslFlags              = $sslFlags
            })
        }
    }

    return $results
}
