# PowerShell JWT

JWT (JSON Web Tokens) implementation in PowerShell per [RFC7519](https://tools.ietf.org/html/rfc7519)

Many modern APIs require crytographically signed JWT tokens. This module is to enable creating and verifying those from PowerShell and the underlying .NET Framework, without using external libraries. 

## Getting started

The script module is published on PowerShell Gallery. Install with 
```powershell
Install-Module JWT
``` 
Alternatively, download the source and import the script module directly:
```powershell
Import-Module /Path/to/JWT.psm1
``` 

## Usage

The module provides two main functions: `New-Jwt`, `Test-Jwt` (also aliased to `Verify-JwtSignature`), as well as service functions - `ConvertFrom-Base64UrlString`, `ConvertFrom-Base64UrlString`, `Get-JwtHeader`, and `Get-JwtPayload`. Descriptions and help for each are available by running `Get-Help`.

### Using **RS256** algorithm

`New-Jwt` creates a JWT given a JSON payload containing a set of claims and a signing key, and `Test-Jwt` verifies the JWT using public key corresponding to the signing key. In this implementation, both keys are passed to the cmdlets as `-Cert` parameter of type [System.Security.Cryptography.X509Certificates.X509Certificate2](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2). 

There are several ways to create an instance of `X509Certificate2`. You can import PKCS #12/PFX file:
```powershell
$Cert = Get-PfxCertificate /ps/jwt/jwt.pfx
```
Alternatively, you can instantiate this way, specifying the file and password:
```powershell
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/ps/jwt/jwt.pfx","jwt")
```
Yet another option is using [Cert: drive](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Security/About/about_Certificate_Provider), which can contain certificates with or without private keys, and is available in Windows by default:
```powershell
$Cert = (Get-ChildItem Cert:\CurrentUser\My)[1]
```
Once  you have loaded the signing key as the private key in an instance of `X509Certificate2`, you can sign JWT using `New-Jwt`:

```
PS /ps/jwt> $jwt = New-Jwt -Cert $Cert -PayloadJson '{"token1":"value1","token2":"value2"}' -Verbose
VERBOSE: Payload to sign: {"token1":"value1","token2":"value2"}
VERBOSE: Signing certificate: CN=jwt_signing_test
```

The private signing keys can be provided in formats other than the PKCS #12/PFX. For example, Google Cloud Platform [can issue service account credentials in both PKCS #12/PFX format and Google Credentials JSON format](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys). `OpenSSL` can be used to convert between different key material formats and encodings. An example of conversion from Google Credentials format to the standard PFX can be found [here](https://gist.github.com/SP3269/a766709e7aeadc92a953dd253bb53b6a)

`Test-Jwt` verifies a JWT provided certificate of the signing key:

```powershell
$certx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("c:\ps\jwt\jwt.cer")
Test-Jwt -Jwt $jwt -Cert $certx
```

Note that the RSA signature verification requires only **public** key, which can be supplied as Base64-encoded PEM file, PFX package that doesn't contain private keys, or oher formats. Do not ever distribute your private keys!

### Using **HS256** algorithm

If "alg" in the header is set to "HS256", the JWT is MACed using the HMAC SHA-256. The JWT signature is created and verified using a shared secret. To process HS256, both `New-Jwt` and `Test-Jwt` require `-Secret` parameter, which can be a byte array (to avoid any ambiguity), or a string. The string will be converted to bytes using UTF-8 decoder:
```
PS /ps/jwt> New-Jwt -Header '{"typ":"JWT", "alg":"HS256"}' -PayloadJson '{"a": "b"}' -Secret 'I❤️#@(₴?$0'
eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ.eyJhIjogImIifQ.iFV0DXLqK_84NyEVqBClSIVRvWufv-9v0RIi9p10cdM
PS /ps/jwt> 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ.eyJhIjogImIifQ.iFV0DXLqK_84NyEVqBClSIVRvWufv-9v0RIi9p10cdM' | Test-Jwt -Secret 'I❤️#)(₴?$0'
False
```

### Using unsecured JWTs

An unsecured JWT has "alg" header parameter set to "none", and no signature part. It must be supported for RFC7519 compliance. Just header and payload are required to create unsecured JWT:
```powershell
New-Jwt -Header '{"typ":"JWT", "alg":"none"}' -PayloadJson '{"a": "b"}'
```
`Test-Jwt` just verifies that the signature part is not present, as required by the RFC:
```
PS /ps/jwt> 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoibm9uZSJ9.eyJhIjogImIifQ.' | Test-Jwt
True
```
`Test-Jwt` will return **$false** if the signature part is non-empty string. Be aware that the "none" attack is a way of testing security of systems utilising JWT - refer to ["A Look at The Draft for JWT Best Current Practices"](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/) for details.

## Using the service functions

`Get-JwtHeader` decodes the JWT header:
```
PS /ps/jwt> $jwt | Get-JwtHeader | ConvertFrom-Json -AsHashtable
Name                           Value
----                           -----
alg                            RS256
typ                            JWT
```

`Get-JwtPayload` decodes the payload part of the input JWT (usually JSON):
```
PS /ps/jwt>  $jwt | Get-JwtPayload | ConvertFrom-JSON
token1 token2
------ ------
value1 value2
```

`ConvertFrom-Base64UrlString` is [RFC4648](https://tools.ietf.org/html/rfc4648) base64url decoder. Outputs string, or a byte array is `-AsByteArray` specified.
```
PS /ps/jwt> 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | ConvertFrom-Base64UrlString
{"alg":"RS256","typ":"JWT"}
```

`ConvertTo-Base64UrlString` is the reverse - it's base64url encoder. Takes string or byte array input and outputs the base64url string.
```
PS /ps/jwt>  '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
```

## Compatibility notes

Version 1.9 was tested with Windows PowerShell 5.1 on Windows 10, as well as PowerShell 7 on Windows, Lunux (Ubuntu), and MacOS X.

In Windows, CSP is the legacy mechanism for providing cryptographic services. Not all CSPs provide the necessary functions - some don't support signing with SHA-256. To list available CSPs and their capabilities, run `certutil.exe -csplist -v` and check for entry for SHA-256. One CSP that supports it is Microsoft Enhanced RSA and AES Cryptographic Provider. To find the CSP used for a particular key, run
```powershell
$cert.PrivateKey.CspKeyContainerInfo.ProviderName
```

## Change log

- Version 1.9 - adds support for HS256 and NONE for RFC7519 compliance; additional service functions and error handling. 
- Version 1.1.0 - modifies the code to be compatible with RSA as well as CNG in Windows and OpenSSL provider on Linux/Macintosh.
- Version 1.0.0 - initial release.

## Contributing and getting support

🐞 If the code doesn't perform as expected, raise a GitHub issue. Specify the expected behaviour and the actual output/error message. Make sure you're using the latest published version of the module.

🛠️ Pull requests are welcome if you want to add functionality.

