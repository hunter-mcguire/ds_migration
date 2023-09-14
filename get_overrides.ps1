<#
This script iterates through Deep Security computer objects and captures
the hostnames of all objects with firewall overrides.

Requires a valid Deep Security API Key and DSM URL. If using port other than 443
add port to DSM_URL.

Can optionally skip checking self signed certificates with SkipCertCheck parameter

Writes output to a file in same directory named 'override_list.txt'

Usage Example:
pwsh get_overrides.ps1 -ApiKey '<api_key>' -DsmUrl '<dsm_url>:4119' -SkipCertCheck

#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$DsmUrl,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipCertCheck
)

$headers = @{
    'api-version' = 'v1'
    'api-secret-key' = $ApiKey
}

if ($SkipCertCheck) {
    $response = Invoke-RestMethod -SkipCertificateCheck -Uri "${DsmUrl}/api/computers?overrides=true" -Method Get -Headers $headers
} else {
    $response = Invoke-RestMethod -Uri "${DsmUrl}/api/computers?overrides=true" -Method Get -Headers $headers
}

$overrides_list = @()

foreach($computer in $response.computers) {
    if ($computer.firewall.state -eq 'on') {
        $overrides_list += $computer.hostName
    }
}

$overrides_list > override_list.txt
