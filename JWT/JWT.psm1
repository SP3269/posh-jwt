function ConvertFrom-Base64UrlString {
<#
.SYNOPSIS
Base64url decoder.

.DESCRIPTION
Decodes base64url-encoded string to the original string or byte array.

.PARAMETER Base64UrlString
Specifies the encoded input. Mandatory string.

.PARAMETER AsByteArray
Optional switch. If specified, outputs byte array instead of string.

.INPUTS
You can pipe the string input to ConvertFrom-Base64UrlString.

.OUTPUTS
ConvertFrom-Base64UrlString returns decoded string by default, or the bytes if -AsByteArray is used.

.EXAMPLE

PS Variable:> 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' | ConvertFrom-Base64UrlString
{"alg":"RS256","typ":"JWT"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$Base64UrlString,
        [Parameter(Mandatory=$false)][switch]$AsByteArray
    )
    $s = $Base64UrlString.replace('-','+').replace('_','/')
    switch ($s.Length % 4) {
        0 { $s = $s }
        1 { $s = $s.Substring(0,$s.Length-1) }
        2 { $s = $s + "==" }
        3 { $s = $s + "=" }
    }
    if ($AsByteArray) {
        return [Convert]::FromBase64String($s) # Returning byte array - convert to string by using [System.Text.Encoding]::{{UTF8|Unicode|ASCII}}.GetString($s)
    }
    else {
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
    }
}


function ConvertTo-Base64UrlString {
<#
.SYNOPSIS
Base64url encoder.

.DESCRIPTION
Encodes a string or byte array to base64url-encoded string.

.PARAMETER in
Specifies the input. Must be string, or byte array.

.INPUTS
You can pipe the string input to ConvertTo-Base64UrlString.

.OUTPUTS
ConvertTo-Base64UrlString returns the encoded string by default.

.EXAMPLE

PS Variable:> '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$in
    )
    if ($in -is [string]) {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($in)) -replace '\+','-' -replace '/','_' -replace '='
    }
    elseif ($in -is [byte[]]) {
        return [Convert]::ToBase64String($in) -replace '\+','-' -replace '/','_' -replace '='
    }
    else {
        throw "ConvertTo-Base64UrlString requires string or byte array input, received $($in.GetType())"
    }
}


function Get-JwtHeader {
<#
.SYNOPSIS
Gets JSON payload from a JWT (JSON Web Token).

.DESCRIPTION
Decodes and extracts JSON header from JWT. Ignores payload and signature.

.PARAMETER jwt
Specifies the JWT. Mandatory string.

.INPUTS
You can pipe JWT as a string object to Get-JwtHeader.

.OUTPUTS
String. Get-JwtHeader returns decoded header part of the JWT.

.EXAMPLE

PS Variable:> Get-JwtHeader 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJqb2UiLCJyb2xlIjoiYWRtaW4ifQ.'
{"alg":"none","typ":"JWT"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$jwt
    )

    Write-Verbose "Processing JWT: $jwt"
    $parts = $jwt.Split('.')
    $header = ConvertFrom-Base64UrlString $parts[0]
    return $header
}


function Get-JwtPayload {
<#
.SYNOPSIS
Gets JSON payload from a JWT (JSON Web Token).

.DESCRIPTION
Decodes and extracts JSON payload from JWT. Ignores headers and signature.

.PARAMETER jwt
Specifies the JWT. Mandatory string.

.INPUTS
You can pipe JWT as a string object to Get-JwtPayload.

.OUTPUTS
String. Get-JwtPayload returns decoded payload part of the JWT.

.EXAMPLE

PS Variable:> $jwt | Get-JwtPayload -Verbose
VERBOSE: Processing JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
{"token1":"value1","token2":"value2"}

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$jwt
    )

    Write-Verbose "Processing JWT: $jwt"
    $parts = $jwt.Split('.')
    $payload = ConvertFrom-Base64UrlString $parts[1]
    return $payload
}


function New-Jwt {
<#
.SYNOPSIS
Creates a JWT (JSON Web Token).

.DESCRIPTION
Creates signed JWT given a signing certificate and claims in JSON.

.PARAMETER Payload
Specifies the claim to sign in JSON. Mandatory string.

.PARAMETER Header
Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.

.PARAMETER Cert
Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2. Must be specified and contain the private key if the algorithm in the header is RS256.

.PARAMETER Secret
Specifies the HMAC secret. Can be byte array, or a string, which will be converted to bytes. Must be specified if the algorithm in the header is HS256.

.INPUTS
You can pipe a string object (the JSON payload) to New-Jwt.

.OUTPUTS
System.String. New-Jwt returns a string with the signed JWT.

.EXAMPLE
PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]

PS Variable:\> New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg

.EXAMPLE
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/mnt/c/PS/JWT/jwt.pfx","jwt")

$now = (Get-Date).ToUniversalTime()
$createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
$expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(1)) -UFormat "%s"))
$rawclaims = [Ordered]@{
    iss = "examplecom:apikey:uaqCinPt2Enb"
    iat = $createDate
    exp = $expiryDate
} | ConvertTo-Json

$jwt = New-Jwt -PayloadJson $rawclaims -Cert $cert

$apiendpoint = "https://api.example.com/api/1.0/systems"

$splat = @{
    Method="GET"
    Uri=$apiendpoint
    ContentType="application/json"
    Headers = @{authorization="bearer $jwt"}
}

Invoke-WebRequest @splat

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$PayloadJson,
        [Parameter(Mandatory=$false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory=$false)]$Secret # Can be string or byte[] - checks in the code
    )

    Write-Verbose "Payload to sign: $PayloadJson"

    try { $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT header is not JSON: $Header" }
    Write-Verbose "Algorithm: $Alg"

    try { ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT payload is not JSON: $PayloadJson" }

    $encodedHeader = ConvertTo-Base64UrlString $Header
    $encodedPayload = ConvertTo-Base64UrlString $PayloadJson

    $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT

    $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

    switch($Alg) {
    
        "RS256" {
            if (-not $PSBoundParameters.ContainsKey("Cert")) {
                throw "RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2"
            }
            Write-Verbose "Signing certificate: $($Cert.Subject)"
            $rsa = $Cert.PrivateKey
            if ($null -eq $rsa) { # Requiring the private key to be present; else cannot sign!
                throw "There's no private key in the supplied certificate - cannot sign" 
            }
            else {
                # Overloads tested with RSACryptoServiceProvider, RSACng, RSAOpenSsl
                try { $sig = ConvertTo-Base64UrlString $rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) }
                catch { throw New-Object System.Exception -ArgumentList ("Signing with SHA256 and Pkcs1 padding failed using private key $($rsa): $_", $_.Exception) }
            }
        }
        "HS256" {
            if (-not ($PSBoundParameters.ContainsKey("Secret"))) {
                throw "HS256 requires -Secret parameter"
            }
            try { 
                $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
                if ($Secret -is [byte[]]) {
                    $hmacsha256.Key = $Secret
                }
                elseif ($Secret -is [string]) {
                    $hmacsha256.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
                }
                else {
                    throw "Expected Secret parameter as byte array or string, instead got $($Secret.gettype())"
                }                
                $sig = ConvertTo-Base64UrlString $hmacsha256.ComputeHash($toSign)
            }
            catch { throw New-Object System.Exception -ArgumentList ("Signing with HMACSHA256 failed: $_", $_.Exception) }
        }
        "none" {
            $sig = $null
        }
        default {
            throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
        }

    }
    
    $jwt = $jwt + '.' + $sig
    return $jwt
}


function Test-Jwt {
<#
.SYNOPSIS
Tests cryptographic integrity of a JWT (JSON Web Token).

.DESCRIPTION
Verifies a digital signature of a JWT given the signing certificate (for RS256) or the secret (for HS256).

.PARAMETER Cert
Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2. 
Must be specified if the algorithm in the header is RS256. Doesn't have to, and generally shouldn't, contain the private key.

.PARAMETER Secret
Specifies the HMAC secret. Can be byte array, or a string, which will be converted to bytes. 
Must be specified if the algorithm in the header is HS256.

.INPUTS
You can pipe JWT as a string object to Test-Jwt.

.OUTPUTS
Boolean. Test-Jwt returns $true if the signature successfully verifies.

.EXAMPLE

PS Variable:> $jwt | Test-Jwt -cert $cert -Verbose
VERBOSE: Verifying JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXP
Ch15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2p
RIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
VERBOSE: Using certificate with subject: CN=jwt_signing_test
True

.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/

#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$jwt,
        [Parameter(Mandatory=$false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory=$false)]$Secret
    )
    
    Write-Verbose "Verifying JWT: $jwt"

    $parts = $jwt.Split('.')
    $Header = ConvertFrom-Base64UrlString $Parts[0]
    try { $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT header is not JSON: $Header" }
    Write-Verbose "Algorithm: $Alg"

    switch($Alg) {

        "RS256" {
            if (-not $PSBoundParameters.ContainsKey("Cert")) {
                throw "RS256 requires -Cert parameter of type System.Security.Cryptography.X509Certificates.X509Certificate2"
            }
            $bytes = ConvertFrom-Base64URLString $parts[2] -AsByteArray
            Write-Verbose "Using certificate with subject: $($Cert.Subject)"
            $SHA256 = New-Object Security.Cryptography.SHA256Managed
            $computed = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0]+"."+$parts[1])) # Computing SHA-256 hash of the JWT parts 1 and 2 - header and payload
            return $cert.PublicKey.Key.VerifyHash($computed,$bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) # Returns True if the hash verifies successfully        
        }
        "HS256" {
            if (-not ($PSBoundParameters.ContainsKey("Secret"))) {
                throw "HS256 requires -Secret parameter"
            }
            $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
            if ($Secret -is [byte[]]) {
                $hmacsha256.Key = $Secret
            }
            elseif ($Secret -is [string]) {
                $hmacsha256.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
            }
            else {
                throw "Expected Secret parameter as byte array or string, instead got $($Secret.gettype())"
            }
            $signature = $hmacsha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0]+"."+$parts[1]))
            $encoded = ConvertTo-Base64UrlString $signature
            return $encoded -eq $parts[2]
        }
        "none" {
            return -not $parts[2] # Must not have the signature part
        }
        default {
            throw 'The algorithm is not one of the supported: "RS256", "HS256", "none"'
        }

    }

}


Set-Alias -Name "Verify-JwtSignature" -Value "Test-Jwt" -Description "An alias, using non-standard verb"
