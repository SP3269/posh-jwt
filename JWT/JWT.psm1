function ConvertFrom-Base64UrlString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$Base64UrlString
    )
    $s = $Base64UrlString.replace('-','+').replace('_','/')
    switch ($s.Length % 4) {
        0 { $s = $s }
        1 { $s = $s.Substring(0,$s.Length-1) }
        2 { $s = $s + "==" }
        3 { $s = $s + "=" }
    }
    return [Convert]::FromBase64String($s) # Returning byte array - convert to string by using [System.Text.Encoding]::{{UTF8|Unicode|ASCII}}.GetString($s)
}

function ConvertTo-Base64UrlString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$String
    )
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String)) -replace '\+','-' -replace '/','_' -replace '='
}

function New-Jwt {
<#
.SYNOPSIS
Creates a JWT (JSON Web Token).

.DESCRIPTION
Creates signed JWT given a signing certificate and claims in JSON.

.PARAMETER Payload
Specifies the claim to sign in JSON. Mandatory.

.PARAMETER Cert
Specifies the signing certificate. Mandatory.

.PARAMETER Header
Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.

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


    [CmdletBinding(DefaultParameterSetName="RS256Params")]
    param (
        [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$PayloadJson,
        [Parameter(Mandatory=$true,ParameterSetName="RS256Params")][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory=$true,ParameterSetName="HS256Params")][byte[]]$Secret
    )

    Write-Verbose "Payload to sign: $PayloadJson"

    try { $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT header is not JSON: $Header" }
    try { ConvertFrom-Json -InputObject $PayloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT payload is not JSON: $PayloadJson" }

    $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Header)) -replace '\+','-' -replace '/','_' -replace '='
    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PayloadJson)) -replace '\+','-' -replace '/','_' -replace '='

    $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT

    $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

    switch($Alg.ToUpper()) {
    
        "RS256" {
            Write-Verbose "Signing certificate: $($Cert.Subject)"
            $rsa = $Cert.PrivateKey
            if ($null -eq $rsa) { # Requiring the private key to be present; else cannot sign!
                throw "There's no private key in the supplied certificate - cannot sign" 
            }
            else {
                # Overloads tested with RSACryptoServiceProvider, RSACng, RSAOpenSsl
                try { $sig = [Convert]::ToBase64String($rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) -replace '\+','-' -replace '/','_' -replace '=' }
                catch { throw "Signing with SHA256 and Pkcs1 padding failed using private key $rsa" }
            }
        }
        "HS256" { 
            try { 
                $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
                $hmacsha256.Key = $Secret
                $sig = [Convert]::ToBase64String($hmacsha256.ComputeHash($toSign)) -replace '\+','-' -replace '/','_' -replace '='
            }
            catch { throw "Signing with HMACSHA256 failed" }
        }
        "NONE" {
            $sig = $null
        }
        default {
            throw "The algorithm is not one of the: RS256, HS256, none"
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
Verifies a digital signature of a JWT given a signing certificate. Assumes SHA-256 hashing algorithm. Optionally produces the original signed JSON payload.

.PARAMETER Payload
Specifies the JWT. Mandatory string.

.PARAMETER Cert
Specifies the signing certificate. Mandatory X509Certificate2.

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
        [Parameter(Mandatory=$true)][string]$jwt,
        [Parameter(Mandatory=$false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [Parameter(Mandatory=$false)][byte[]]$Secret
    )

    Write-Verbose "Verifying JWT: $jwt"

    $parts = $jwt.Split('.')
    $Header = [System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64UrlString $Parts[0]))
    try { $Alg = (ConvertFrom-Json -InputObject $Header -ErrorAction Stop).alg } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT header is not JSON: $Header" }
    Write-Verbose "Algorithm: $Alg"

    switch($Alg.ToUpper()) {

        "RS256" {
            $bytes = Convert-FromBase64URLString $parts[2]
            Write-Verbose "Using certificate with subject: $($Cert.Subject)"
            $SHA256 = New-Object Security.Cryptography.SHA256Managed
            $computed = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0]+"."+$parts[1])) # Computing SHA-256 hash of the JWT parts 1 and 2 - header and payload
            return $cert.PublicKey.Key.VerifyHash($computed,$bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) # Returns True if the hash verifies successfully        
        }
        "HS256" {
            $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
            $hmacsha256.Key = $Secret
            $signature = $hmacsha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0]+"."+$parts[1]))
            $encoded = [Convert]::ToBase64String($signature) -replace '\+','-' -replace '/','_' -replace '=' 
            return $encoded -eq $parts[2]
        }
        "NONE" {
            return -not $parts[2] # Must not have the signature part
        }
        default {
            throw "The algorithm is not one of the: RS256, HS256, none"
        }

    }

}

New-Alias -Name "Verify-JwtSignature" -Value "Test-Jwt" -Description "An alias, using non-standard verb"

function Get-JwtPayload {
    <#
    .SYNOPSIS
    Gets JSON payload from a JWT (JSON Web Token).
    
    .DESCRIPTION
    Decodes and extracts JSON payload from JWT. Ignores headers and signature.
    
    .PARAMETER Payload
    Specifies the JWT. Mandatory string.
    
    .INPUTS
    You can pipe JWT as a string object to Get-JwtPayload.
    
    .OUTPUTS
    String. Get-JwtPayload returns $true if the signature successfully verifies.
    
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

    $payload = $parts[1].replace('-','+').replace('_','/') # Decoding Base64url to the original byte array
    $mod = $payload.Length % 4
    switch ($mod) {
        # 0 { $payload = $payload } - do nothing
        1 { $payload = $payload.Substring(0,$payload.Length-1) }
        2 { $payload = $payload + "==" }
        3 { $payload = $payload + "=" }
    }
    $bytes = [Convert]::FromBase64String($payload) # Conversion completed

    return [System.Text.Encoding]::UTF8.GetString($bytes)

}
    