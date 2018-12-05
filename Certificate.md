
## Certificate stuff

### [ Create selfsigned certificates ]
```diff
- This is just an example how you can quickly create certificates for a testing environment.
- Never do this in production and always us an official certificate from a trusted publisher.
- If you still decide to go the selfsigned way, store the private key of your root and signing certificates in a safe (offline) store.
```
Self-signed root certificate
```powershell
$RootCert = New-SelfSignedCertificate -Type Custom `
-KeySpec Signature `
-Subject "CN=FOOL-ROOT-CA" `
-KeyExportPolicy Exportable `
-HashAlgorithm sha256 `
-KeyLength 4096 `
-CertStoreLocation "Cert:\LocalMachine\My" `
-KeyUsageProperty Sign `
-KeyUsage CertSign `
-NotAfter (Get-Date).AddYears(5)
```

### Generate certificates from root
In this case i will create a computer certificate for my host dc001.fool.local<br>
```powershell
New-SelfSignedCertificate -Type Custom `
-KeySpec Signature `
-Subject "CN=dc001.fool.local" `
-KeyExportPolicy Exportable `
-HashAlgorithm sha256 `
-KeyLength 2048 `
-NotAfter (Get-Date).AddMonths(24) `
-CertStoreLocation "Cert:\LocalMachine\My" `
-Signer $RootCert `
-TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
```

I can also add some other attribute to make it a SAN certificate or give it other extensions so it can be used for other purposes<br>
In this case i included an second DNS name and the TextExtension represents "Server and Client Authentication"
```powershell
-DnsName dc001.fool.local,ldaps.fool.local
-TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")
```

<br><br>
### [ Read and download certificate from remote endpoint ]

I assembled this function based on several other scripts that had a similar purpose.<br>
I used this script to verify that a group of servers have the expected certificate mapped to the service.   

```powershell
function Read-SSLCertificate {

    param (
    [parameter(Mandatory = $true)]
    [string]$RemoteEndpoint,

    [parameter(Mandatory = $true)]
    [int]$TcpPort,

    [parameter(Mandatory = $false)]
    [switch]$DownloadCertificate
    )

    # Clear Variables
    Clear-Variable strSSLStatus,strSSLPolicyError -Scope Global -ErrorAction SilentlyContinue

    # Create a TCP Socket to the remote endpoint
    $objTcpSocket = New-Object Net.Sockets.TcpClient($RemoteEndpoint, $TcpPort)

    if($objTcpSocket) {
        #Socket Got connected get the tcp stream ready to read the certificate
        write-Verbose "Successfully Connected to $RemoteEndpoint on $TcpPort"
        $objTcpStream = $objTcpSocket.GetStream()

        # Getting detailed information about validation
        $global:RemoteCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param (
                [object]$objSender,
                [System.Security.Cryptography.X509Certificates.X509Certificate]$objCertificate,
                [System.Security.Cryptography.X509Certificates.X509Chain]$objChain,
                [System.Net.Security.SslPolicyErrors]$objSslPolicyErrors
            )

            # Download certificate to temp directory        
            if($DownloadCertificate) {

                $objCerts = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
                $objChain.ChainElements | ForEach-Object {
                    [void]$objCerts.Add($_.Certificate)
                }
     
                $strSslCertPath = $env:TEMP + "\SslCertsDownload"
                if (!(Test-Path $strSslCertPath)) {
                    New-Item -Type Directory -Path $strSslCertPath -Force
                }
                $strCertFilename = $strSslCertPath + "\" + $RemoteEndpoint + ".p7b"
                Write-Verbose "Certificate saved to $strCertFilename"
                Set-Content -Path $strCertFilename -Value $objCerts.Export("pkcs7") -Encoding Byte
            }
 
            # Check Certificate
            if ($objSslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
                $global:strSSLStatus = "OK"
            }
            else {
                $global:strSSLStatus = "Errors"
            }
    
            if ($objSslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors)) {
                $global:strSSLPolicyError = "Remote Certificate Chain Errors"
                Write-Verbose "- Remote Certificate Chain Errors"
                ForEach ($objStatus in $objChain.ChainStatus) {
                    Write-Verbose "- $($objStatus.StatusInformation)"
                }
            }
 
            if ($objSslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)) {
                $global:strSSLPolicyError = "Remote Certificate Name Mismatch"
                Write-Verbose "- Remote Certificate Name Mismatch"
            }
 
            if ($objSslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable)) {
                $global:strSSLPolicyError = "Remote Certificate Not Available"
                Write-Verbose "- Remote Certificate Not Available"
            }
 
            # Ignore invalid certificates
            return $true     
        }

        Write-Verbose "Reading SSL Certificate...."
        #Create an SSL Connection 
        $objSslStream = New-Object System.Net.Security.SslStream($objTcpStream,$false,$global:RemoteCertificateValidationCallback)
        #Force the SSL Connection to send us the certificate
        $objSslStream.AuthenticateAsClient($RemoteEndpoint)

        #Read the certificate
        $objCertInfo = New-Object system.security.cryptography.x509certificates.x509certificate2($objSslStream.RemoteCertificate)
    }
    else {
        Write-Verbose "Error Opening Connection: $TcpPort on $RemoteEndpoint Unreachable"
        $global:strSSLStatus = "Error"
        $global:strSSLPolicyError = "Could not connect to TCP endpoint"
    }

    # Build return object
    $objReturn = [PSCustomObject]@{
        "RemoteEndpoint"=$RemoteEndpoint
        "Issuer" = $objCertInfo.Issuer
        "Subject" = $objCertInfo.Subject
        "DnsNameList" = $objCertInfo.DnsNameList
        "FriendlyName" = $objCertInfo.FriendlyName
        "SSLStatus" = "$global:strSSLStatus"
        "SSLPolicyErrors" = "$global:strSSLPolicyError"
        "NotBefore" = $objCertInfo.NotBefore
        "NotAfter" = $objCertInfo.NotAfter
        "HasPrivateKey" = $objCertInfo.HasPrivateKey
        "EnhancedKeyUsageList" = $objCertInfo.EnhancedKeyUsageList
        "SerialNumber" = $objCertInfo.SerialNumber
        "Thumbprint" = $objCertInfo.Thumbprint
    }
    
    return $objReturn
}

$VerbosePreference = "Continue"
Read-SSLCertificate -RemoteEndpoint www.google.com -TcpPort 443 -DownloadCertificate

```
