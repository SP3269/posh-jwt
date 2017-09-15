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
Specifies a JWT header. Optional. Should be {"alg":"RS256","typ":"JWT"}' as HS256 is not implemented

.INPUTS
None. You cannot pipe objects to New-Jwt.

.OUTPUTS
System.String. New-Jwt returns a string with the signed JWT.

.EXAMPLE
PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]

PS Variable:\> New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg

.EXAMPLE
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.import("c:\ps\jwt.pfx","jwt","Exportable,PersistKeySet")

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
https://jwt.io/

#>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
        [Parameter(Mandatory=$true)][string]$PayloadJson,
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    try { ConvertFrom-Json -InputObject $payloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
    catch { throw "The supplied JWT payload is not JSON: $payloadJson" }

    $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Header)) -replace '\+','-' -replace '/','_' -replace '='
    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PayloadJson)) -replace '\+','-' -replace '/','_' -replace '='

    $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT

    $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)
    $rsa = $Cert.PrivateKey
    $sig = [Convert]::ToBase64String($rsa.SignData($toSign,"SHA256")) -replace '\+','-' -replace '/','_' -replace '='

    $jwt = $jwt + '.' + $sig

    return $jwt

}