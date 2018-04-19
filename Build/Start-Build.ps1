param(
    [string]$Task = 'Default',
    [string]$CertFileForSignature,
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
)

$ProjectRoot = $(Resolve-Path "$PSScriptRoot\..").Path
$ModuleRoot = Split-Path $(Resolve-Path "$ProjectRoot\*\*.psm1")
$ModuleName = $ModuleRoot | Split-Path -Leaf

if ($CertFileForSignature -and !$Cert) {
    if (!$(Test-Path $CertFileForSignature)) {
        Write-Error "Unable to find the Certificate specified to be used for Code Signing! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $Cert = Get-PfxCertificate $CertFileForSignature
}
if ($Cert) {
    # We don't want to include the Module's .psm1 or .psd1 yet because the psake.ps1 Compile Task hasn't finalized them yet...
    $FilesToSign = Get-ChildItem $ProjectRoot -Recurse -File | Where-Object {
        $_.Extension -match "\.ps1|\.psd1|\.psm1" -and $_.Name -notmatch "^$ModuleName\.ps[d|m]1$"
    }

    # Since the Set-AuthenticodeSignature cmdlet eats the line above '# SIG...' in a file everytime it is used,
    # we need to check the line befor '# SIG' to make sure it is empty before signing
    [System.Collections.ArrayList]$FilesThatSetAuthentcodeWillBreak = @()
    foreach ($FilePath in $FilesToSign.FullName) {
        $FileContent = Get-Content $FilePath
        $PrecedingLineIsBlank = [String]::IsNullOrWhiteSpace($($($FileContent | Select-String -Pattern "^# SIG # Begin signature block" -Context 1,0).Context.PreContext[0]))
        if (!$PrecedingLineIsBlank) {
            $null = $FilesThatSetAuthentcodeWillBreak.Add($FilePath)
        }
    }

    if ($FilesThatSetAuthentcodeWillBreak.Count -gt 0) {
        Write-Warning "The following files need additional New Lines so that the 'Set-Authenticode' cmdlet doesn't break functionality:`n$($FilesThatSetAuthentcodeWillBreak -join "`n")"
        Write-Error "Need to add some New Lines in files to be signed by 'Set-Authenticode'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        [System.Collections.ArrayList]$FilesFailedToSign = @()
        foreach ($FilePath in $FilesToSign.FullName) {
            try {
                $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $FilePath -cert $Cert
                if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -eq "HasMisMatch") {throw}
            }
            catch {
                $null - $FilesFailedToSign.Add($FilePath)
            }
        }

        if ($FilesFailedToSign.Count -gt 0) {
            Write-Error "Halting because we failed to digitally sign the following files:`n$($FilesFailedToSign -join "`n")"
            $global:FunctionResult = "1"
            return
        }
    }
}

# dependencies
Get-PackageProvider -Name NuGet -ForceBootstrap | Out-Null
if(-not (Get-Module -ListAvailable PSDepend))
{
    & (Resolve-Path "$PSScriptRoot\helpers\Install-PSDepend.ps1")
}
Import-Module PSDepend
$null = Invoke-PSDepend -Path "$PSScriptRoot\build.requirements.psd1" -Install -Import -Force

Set-BuildEnvironment -Force -Path $PSScriptRoot\..

$InvokePSakeParamsSplatParams = @{}
if ($CertFileForSignature) {
    $InvokePSakeParamsSplatParams.Add("CertFileForSignature",$CertFileForSignature)
}
if ($Cert) {
    $InvokePSakeParamsSplatParams.Add("Cert",$Cert)
}

if ($InvokePSakeParamsSplatParams.Count -gt 0) {
    Invoke-psake $PSScriptRoot\psake.ps1 -taskList $Task -nologo -parameters $InvokePSakeParamsSplatParams
}
else {
    Invoke-psake $PSScriptRoot\psake.ps1 -taskList $Task -nologo
}

exit ( [int]( -not $psake.build_success ) )


















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyc/0eNP8paI3/XfgFe3MZYe0
# ZTCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFODfzYfMlyIPIUB
# x+pjUSWmjVgQMA0GCSqGSIb3DQEBAQUABIIBAAZe0EGUPrfW+MqTFOoadGrebuXs
# 4cR5w+mmHRxOUHozTOUpWtxnN7NuROSQe7JDFjvEMkWpaSK0nNefu9QQMwcSN1XA
# ViBX9G6kK8a4cH/jF8JBh9nBf76ooKxLtwXjFu9QCK6skM8CmZ/rMKdH7nRg2NqW
# YG7ISmF+ifxqmtcGLDBVclFcn6tGrLnxI7i3k+XBwqHxesHkaSinqKny8YOPhipW
# BN5hN0FMAmNIWsMx1fuiVuQQIT8OT4KdmVAWv4s5yuVute9s8yaoIIQVSYWvdvpA
# CKQ+PCaz2Y9D3tLdpi0v3TOHsuQZNFLVjvFJgkrT0RCQT/PPB89XGaKe2HA=
# SIG # End signature block
