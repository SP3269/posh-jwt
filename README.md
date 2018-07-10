# Powershell JWT
JWT (JSON Web Tokens) implementation in Powershell

Many modern APIs require crytographically signed JWT tokens. This module is to enable utilising those from Powershell. AFter the initial implementation using Windows Powershell 5.1, version 1.1.0 has been successfully tested on Ubuntu and on Windows 10 with Powershell Core 6.0.

The script module is published on Powershell Gallery (install with ```Install-Module JWT```). 

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

<sub><b>v. 1.0.0 note: in Windows, if you load signing certificate from certificate store</b>, signing might fail, depending on CSP (the Cryptographic Service Provider) used by the key. That is specified during certificate enrollment. Run "certutil.exe -csplist -v" to check CSP capabilities; you're after "SHA-256". The Microsoft Enhanced RSA and AES Cryptographic Provider works. Version 1.1.0 modifies the code to be compatible with RSA as well as CNG and OpenSSL</sub>
