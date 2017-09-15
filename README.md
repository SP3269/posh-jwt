
# posh-jwt
JWT (JSON Web Tokens) implementation in Powershell

Many modern APIs require crytographically signed JWT token. This is to enable utilising those from Powershell. The initial testing is done using Powershell 5.1 on Windows 10. However, the .NET classes used - System.Security.Cryptography.X509Certificates.X509Certificate2, System.Text.Encoding - are in .NET Core, so should also work in Powershell Core on Linux and Macintosh.

Using New-Jwt is easy:

$jwt = New-Jwt -Cert (Get-ChildItem cert:\CurrentUser\My)[1] -PayloadJson '{"token1":"value1","token2":"value2"}'

Please note that in Windows, if you load signing certificate from certificate store, signing might fail, depending on CSP (the Cryptographic Service Provider) used by the key. That is specified during certificate enrollment. Run "certutil.exe -csplist -v" to check CSP capabilities; you're after "SHA-256". The Microsoft Enhanced RSA and AES Cryptographic Provider works. If you use key from PKCS12 package (PFX file), or not using Windows, that does not matter.

More advanced example, real life example is found in the PS1 file.
