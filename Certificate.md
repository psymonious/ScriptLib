
## Certificate stuff

### [ Create selfsigned certificates ]

Self-signed root certificate
```powershell
$RootCert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
-Subject "CN=FOOL-ROOT-CA" `
-KeyExportPolicy Exportable `
-HashAlgorithm sha256 -KeyLength 4096 `
-CertStoreLocation "Cert:\LocalMachine\My" `
-KeyUsageProperty Sign `
-KeyUsage CertSign `
-NotAfter (Get-Date).AddYears(5)
```

Generate certificates from root (For Server Authentication only) (Not for web server)
- SAN > -DnsNname -DnsName domain.example.com,anothersubdomain.example.com
- Other purposes > Adjust the 'TextExtension' Parameter like '2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2' (Server and Client authentication)
```powershell
New-SelfSignedCertificate -Type Custom -KeySpec Signature `
-Subject "CN=dc001.fool.local" -KeyExportPolicy Exportable `
-HashAlgorithm sha256 -KeyLength 2048 `
-NotAfter (Get-Date).AddMonths(24) `
-CertStoreLocation "Cert:\LocalMachine\My" `
-Signer $RootCert `
-TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
```
<br><br>
### [ Read and download certificate from remote endpoint ]

I assembled this functino based on several other scripts that had a similar purpose.<br>
I mainly needed to check what certificate the LDAPS service on a Windows Domain Controller presents.

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
