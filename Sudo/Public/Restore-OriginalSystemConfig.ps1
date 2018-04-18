# Just in case the PowerShell Session in which you originally created the SudoSession is killed/interrupted,
# you can use this function to revert WSMAN/Registry changes that were made with the New-SudoSession function.
# Example:
#   Restore-OriginalSystemConfig -SudoSessionChangesLogFilePath "$HOME\SudoSession_04182018\SudoSession_Config_Changes_04182018_082747.xml"
function Restore-OriginalSystemConfig {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SudoSessionChangesLogFilePath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [securestring]$Password,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply Credentials'
        )]
        [System.Management.Automation.PSCredential]$Credentials
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # First, ingest SudoSessionChangesLogFilePath
    if (!$(Test-Path $SudoSessionChangesLogFilePath)) {
        Write-Error "The path $SudoSessionChangesLogFilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $OriginalConfigInfo = Import-CliXML $SudoSessionChangesLogFilePath
    }

    $CurrentUser = $($(whoami) -split "\\")[-1]
    $SudoSessionFolder = "$HOME\SudoSession_$CurrentUser_$(Get-Date -Format MMddyyy)"
    if (!$(Test-Path $SudoSessionFolder)) {
        $SudoSessionFolder = $(New-Item -ItemType Directory -Path $SudoSessionFolder).FullName
    }
    $SudoSessionRevertChangesPSObject = "$SudoSessionFolder\SudoSession_Config_Revert_Changes__$CurrentUser_$(Get-Date -Format MMddyyy_hhmmss).xml"

    if (!$(Get-Elevation)) {
        if ($global:SudoCredentials) {
            if (!$Credentials) {
                if ($Username -match "\\") {
                    $UserName = $($UserName -split "\\")[-1]
                }
                if ($global:SudoCredentials.UserName -match "\\") {
                    $SudoUserName = $($global:SudoCredentials.UserName -split "\\")[-1]
                }
                else {
                    $SudoUserName = $global:SudoCredentials.UserName
                }
                if ($SudoUserName -match $UserName) {
                    $Credentials = $global:SudoCredentials
                }
            }
            else {
                if ($global:SudoCredentials.UserName -ne $Credentials.UserName) {
                    $global:SudoCredentials = $Credentials
                }
            }
        }
    
        if (!$Credentials) {
            if (!$Password) {
                $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            }
            $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
        }
    
        if ($Credentials.UserName -match "\\") {
            $UserName = $($Credentials.UserName -split "\\")[-1]
        }
        if ($Username -match "\\") {
            $UserName = $($UserName -split "\\")[-1]
        }
    
        $global:SudoCredentials = $Credentials
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    if (Get-Elevation) {
        # Collect $Output as we go...
        $Output = [ordered]@{}

        if ($OriginalConfigInfo.WSMANServerCredSSPStateChange) {
            Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value false
            $Output.Add("CredSSPServer","Off")
        }
        if ($OriginalConfigInfo.WSMANClientCredSSPStateChange) {
            Set-Item -Path "WSMan:\localhost\Client\Auth\CredSSP" -Value false
            $Output.Add("CredSSPClient","Off")
        }
        if ($OriginalConfigInfo.WinRMStateChange) {
            if ([bool]$(Test-WSMan -ErrorAction SilentlyContinue)) {
                try {
                    Disable-PSRemoting -Force -ErrorAction Stop -WarningAction SilentlyContinue
                    $Output.Add("PSRemoting","Disabled")
                    Stop-Service winrm -ErrorAction Stop
                    $Output.Add("WinRMService","Stopped")
                    Set-Item "WSMan:\localhost\Service\AllowRemoteAccess" -Value false -ErrorAction Stop
                    $Output.Add("WSMANServerAllowRemoteAccess",$False)
                }
                catch {
                    Write-Error $_
                    if ($Output.Count -gt 0) {[pscustomobject]$Output}
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if ($OriginalConfigInfo.RegistryKeyPropertiesCreated.Count -gt 0) {
            [System.Collections.ArrayList]$RegistryKeyPropertiesRemoved = @()

            foreach ($Property in $OriginalConfigInfo.RegistryKeyPropertiesCreated) {
                $PropertyName = $($Property | Get-Member -Type NoteProperty | Where-Object {$_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider"}).Name
                $PropertyPath = $Property.PSPath

                if (Test-Path $PropertyPath) {
                    Remove-ItemProperty -Path $PropertyPath -Name $PropertyName
                    $null = $RegistryKeyPropertiesRemoved.Add($Property)
                }
            }

            $Output.Add("RegistryKeyPropertiesRemoved",$RegistryKeyPropertiesRemoved)
        }

        if ($OriginalConfigInfo.RegistryKeysCreated.Count -gt 0) {
            [System.Collections.ArrayList]$RegistryKeysRemoved = @()

            foreach ($RegKey in $OriginalConfigInfo.RegistryKeysCreated) {
                $RegPath = $RegKey.PSPath

                if (Test-Path $RegPath) {
                    Remove-Item $RegPath -Recurse -Force
                    $null = $RegistryKeysRemoved.Add($RegKey)
                }
            }

            $Output.Add("RegistryKeysRemoved",$RegistryKeysRemoved)
        }

        if ($Output.Count -gt 0) {
            $Output.Add("RevertConfigChangesFilePath",$SudoSessionRevertChangesPSObject)

            [pscustomobject]$Output
            [pscustomobject]$Output | Export-CliXml $SudoSessionRevertChangesPSObject
        }
    }
    else {
        [System.Collections.ArrayList]$SystemConfigScript = @()

        $Line = '$Output = [ordered]@{}'
        $null = $SystemConfigScript.Add($Line)

        if ($OriginalConfigInfo.WSMANServerCredSSPStateChange) {
            $Line = 'Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value false'
            $null = $SystemConfigScript.Add($Line)
            $Line = '$Output.Add("CredSSPServer","Off")'
            $null = $SystemConfigScript.Add($Line)
        }
        if ($OriginalConfigInfo.WSMANClientCredSSPStateChange) {
            $Line = 'Set-Item -Path "WSMan:\localhost\Client\Auth\CredSSP" -Value false'
            $null = $SystemConfigScript.Add($Line)
            $Line = '$Output.Add("CredSSPClient","Off")'
            $null = $SystemConfigScript.Add($Line)
        }
        if ($OriginalConfigInfo.WinRMStateChange) {
            if ([bool]$(Test-WSMan -ErrorAction SilentlyContinue)) {
                $AdditionalLines = @(
                    'try {'
                    '    Disable-PSRemoting -Force -ErrorAction Stop -WarningAction SilentlyContinue'
                    '    $Output.Add("PSRemoting","Disabled")'
                    '    Stop-Service winrm -ErrorAction Stop'
                    '    $Output.Add("WinRMService","Stopped")'
                    '    Set-Item "WSMan:\localhost\Service\AllowRemoteAccess" -Value false -ErrorAction Stop'
                    '    $Output.Add("WSMANServerAllowRemoteAccess",$False)'
                    '}'
                    'catch {'
                    '    Write-Error $_'
                    '    if ($Output.Count -gt 0) {[pscustomobject]$Output}'
                    '    $global:FunctionResult = "1"'
                    '    return'
                    '}'
                )
                foreach ($AdditionalLine in $AdditionalLines) {
                    $null = $SystemConfigScript.Add($AdditionalLine)
                }
            }
        }

        if ($OriginalConfigInfo.RegistryKeyPropertiesCreated.Count -gt 0) {
            $Line = '[System.Collections.ArrayList]$RegistryKeyPropertiesRemoved = @()'
            $null = $SystemConfigScript.Add($Line)

            foreach ($Property in $OriginalConfigInfo.RegistryKeyPropertiesCreated) {
                $PropertyName = $($Property | Get-Member -Type NoteProperty | Where-Object {$_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider"}).Name
                $PropertyPath = $Property.PSPath

                if (Test-Path $PropertyPath) {
                    $Line = "if ([bool](Get-ItemProperty -Path '$PropertyPath' -Name '$PropertyName' -EA SilentlyContinue)) {`$null = `$RegistryKeyPropertiesRemoved.Add((Get-ItemProperty -Path '$PropertyPath' -Name '$PropertyName'))}"
                    $null = $SystemConfigScript.Add($Line)
                    $Line = "Remove-ItemProperty -Path '$PropertyPath' -Name '$PropertyName'"
                    $null = $SystemConfigScript.Add($Line)
                }
            }

            $Line = '$Output.Add("RegistryKeyPropertiesRemoved",$RegistryKeyPropertiesRemoved)'
            $null = $SystemConfigScript.Add($Line)
        }

        if ($OriginalConfigInfo.RegistryKeysCreated.Count -gt 0) {
            $Line = '[System.Collections.ArrayList]$RegistryKeysRemoved = @()'
            $null = $SystemConfigScript.Add($Line)

            foreach ($RegKey in $OriginalConfigInfo.RegistryKeysCreated) {
                $RegPath = $RegKey.PSPath

                if (Test-Path $RegPath) {
                    $Line = "if ([bool](Get-Item '$RegPath' -EA SilentlyContinue)) {`$null = `$RegistryKeysRemoved.Add((Get-Item '$RegPath'))}"
                    $null = $SystemConfigScript.Add($Line)
                    $Line = "Remove-Item '$RegPath' -Recurse -Force"
                    $null = $SystemConfigScript.Add($Line)
                }
            }

            $Line = '$Output.Add("RegistryKeysRemoved",$RegistryKeysRemoved)'
            $null = $SystemConfigScript.Add($Line)
        }

        $AdditionalLines = @(
            'if ($Output.Count -gt 0) {'
            "    `$Output.Add('RevertConfigChangesFilePath','$SudoSessionRevertChangesPSObject')"
            "    [pscustomobject]`$Output | Export-CliXml '$SudoSessionRevertChangesPSObject'"
            '}'
        )
        foreach ($AdditionalLine in $AdditionalLines) {
            $null = $SystemConfigScript.Add($AdditionalLine)
        }

        $SystemConfigScriptFilePath = "$SudoSessionFolder\SystemConfigScript.ps1"
        $SystemConfigScript | Set-Content $SystemConfigScriptFilePath

        # IMPORTANT NOTE: You CANNOT use the RunAs Verb if UseShellExecute is $false, and you CANNOT use
        # RedirectStandardError or RedirectStandardOutput if UseShellExecute is $true, so we have to write
        # output to a file temporarily
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "powershell.exe"
        $ProcessInfo.RedirectStandardError = $false
        $ProcessInfo.RedirectStandardOutput = $false
        $ProcessInfo.UseShellExecute = $true
        $ProcessInfo.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"& $SystemConfigScriptFilePath`""
        $ProcessInfo.Verb = "RunAs"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        
        $RevertChangesResult = Import-CliXML $SudoSessionRevertChangesPSObject
        $RevertChangesResult
    }

    ##### END Main Body #####
        
}
























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURt7467NCC6gDLeFfhiPdwqGd
# b7agggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPjajkNNWr1j/5oA
# xtsA/sZDuQxRMA0GCSqGSIb3DQEBAQUABIIBAHOBMjHZQNf5PQR4VYoZioVShByP
# NlendZs5p16aKuMEbdB3PkU/lfBGULz29afagzpf2QDqKicxTHqO3KsPu1/Gzke3
# 5YA/u7ZBkqBQDqsj2tga748i5nMGt6iOZIN9WVEeU971R2IPON6tblKpYQGAOcF9
# y4boYmGD16Xkwhw4ZjPBXkacFWilqumo2VrmnRqOxK3fDbNUhoFysUCzzZt+PXLJ
# 5215JEG59KnryXsK0yWWfrTriTvCKNclb5mQdd/ccb5DkO6UjLYG/BY4e56tMvH7
# 0xutKh7W5vu8qSKP9wnALgtxl3hcFbZOvlVzLqwyqTuY+H4iDJtFhinouKI=
# SIG # End signature block
