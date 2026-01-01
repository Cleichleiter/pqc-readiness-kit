function Collect-WindowsCerts {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Get-PublicKeyBits {
        param([Parameter(Mandatory)]$Cert)

        # Best-effort key size resolution across providers (PS 5.1 compatible)
        try {
            if ($Cert.PublicKey -and $Cert.PublicKey.Key -and $Cert.PublicKey.Key.KeySize) {
                return [int]$Cert.PublicKey.Key.KeySize
            }
        } catch { }

        try {
            if ($Cert.PublicKey -and $Cert.PublicKey.Key -and $Cert.PublicKey.Key.Size) {
                return [int]$Cert.PublicKey.Key.Size
            }
        } catch { }

        try {
            if ($Cert.PublicKey -and $Cert.PublicKey.EncodedKeyValue -and $Cert.PublicKey.EncodedKeyValue.RawData) {
                # RawData is key material; length in bits is an approximation but better than failing
                return [int]($Cert.PublicKey.EncodedKeyValue.RawData.Length * 8)
            }
        } catch { }

        return $null
    }

    $results = New-Object System.Collections.Generic.List[object]

    $stores = @(
        @{ Path = 'Cert:\LocalMachine\My';   Store = 'LocalMachine\My' }
        @{ Path = 'Cert:\LocalMachine\Root'; Store = 'LocalMachine\Root' }
        @{ Path = 'Cert:\LocalMachine\CA';   Store = 'LocalMachine\CA' }
        @{ Path = 'Cert:\CurrentUser\My';    Store = 'CurrentUser\My' }
    )

    foreach ($store in $stores) {
        if (-not (Test-Path -LiteralPath $store.Path)) {
            continue
        }

        Get-ChildItem -Path $store.Path | ForEach-Object {

            $publicKey = $_.PublicKey

            $publicKeyAlgo = $null
            try { $publicKeyAlgo = $publicKey.Oid.FriendlyName } catch { }
            if (-not $publicKeyAlgo) {
                try { $publicKeyAlgo = $publicKey.Oid.Value } catch { }
            }

            $ekuList = @()
            try {
                $ekuList = $_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }
            } catch {
                $ekuList = @()
            }

            $sigAlg = $null
            try { $sigAlg = $_.SignatureAlgorithm.FriendlyName } catch { }

            $results.Add([pscustomobject]@{
                Store                  = $store.Store
                Subject                = $_.Subject
                Issuer                 = $_.Issuer
                Thumbprint             = $_.Thumbprint
                SerialNumber           = $_.SerialNumber
                NotBefore              = $_.NotBefore
                NotAfter               = $_.NotAfter
                PublicKeyAlgorithm     = $publicKeyAlgo
                PublicKeyBits          = (Get-PublicKeyBits -Cert $_)
                SignatureHashAlgorithm = $sigAlg
                HasPrivateKey          = [bool]$_.HasPrivateKey
                EnhancedKeyUsages      = ($ekuList -join ', ')
            })
        }
    }

    return $results
}
