# Powershell JWT
JWT (JSON Web Tokens) implementation in Powershell

Many modern APIs require crytographically signed JWT token. This is to enable utilising those from Powershell. The initial testing is done using Powershell 5.1 on Windows 10. Since the .NET classes used - System.Security.Cryptography.X509Certificates.X509Certificate2, System.Text.Encoding - are in .NET Core, the code should also work in all versions of Powershell Core on Linux and Macintosh; it has been successfully tested on Ubuntu with pwsh 6.0

The function New-Jwt creates a JWT given a claim and a signing key (and an optional header). Using New-Jwt is easy:

```$jwt = New-Jwt -Cert (Get-ChildItem cert:\CurrentUser\My)[1] -PayloadJson '{"token1":"value1","token2":"value2"}'```

More advanced example (taken directly from the code that started this effort) is found in the function help.

<sub><b>Please note that in Windows, if you load signing certificate from certificate store</b>, signing might fail, depending on CSP (the Cryptographic Service Provider) used by the key. That is specified during certificate enrollment. Run "certutil.exe -csplist -v" to check CSP capabilities; you're after "SHA-256". The Microsoft Enhanced RSA and AES Cryptographic Provider works. If you use key from PKCS12 package (PFX file), or not using Windows, that does not matter.</sub>
