# PowerShell JWT

JWT (JSON Web Tokens) implementation in PowerShell

Many modern APIs require crytographically signed JWT tokens. This module is to enable utilising those from PowerShell. After the initial implementation using Windows PowerShell 5.1, version 1.1.0 has been successfully tested on Ubuntu and on Windows 10 with PowerShell Core 6.0.

## Getting Started

The script module is published on PowerShell Gallery. If you're using PowerShell 5 or later, install with 
```powershell
Install-Module JWT
``` 
Alternatively, download the source and import the script module directly:
```powershell
Import-Module \\Path\to\JWT.psm1
``` 

## Usage

The module provides three functions: New-Jwt, Test-Jwt (also aliased to Verify-JwtSignature), and Get-JwtPayload.

New-Jwt creates a JWT given a claim and a signing key. Only "RS256" (RSA with SHA256) is supported in v. 1.1.0, so the optional header should not be changed:

```powershell
# Windows example - using cert: drive
$jwt = New-Jwt -Cert (Get-ChildItem cert:\CurrentUser\My)[1] -PayloadJson '{"token1":"value1","token2":"value2"}'
```

Test-Jwt verifies a JWT provided certificate of the signing key:

```powershell
$certx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("c:\ps\jwt\jwt.cer")
Test-Jwt -Jwt $jwt -Cert $certx
```

Get-JwtPayload decodes the payload part of the input JWT (usually JSON):
```powershell
$jwt | Get-JwtPayload | ConvertFrom-JSON
token1 token2
------ ------
value1 value2
```

More advanced examples (taken directly from the code that started this effort) are found in the functions' help.

## Compatibility Notes

In Windows, CSP is the legacy mechanism for providing cryptographic services. Not all CSPs provide the necessary functions - some don't support signing with SHA-256. To list available CSPs and their capabilities, run ```certutil.exe -csplist -v``` and check for entry for SHA-256. One CSP that supports it is Microsoft Enhanced RSA and AES Cryptographic Provider. To find the CSP used for a particular key, run
```powershell
$cert.PrivateKey.CspKeyContainerInfo.ProviderName
```

Version 1.1.0 modifies the code to be compatible with RSA as well as CNG in WIndows and OpenSSL provider on Linux/Macintosh.
