<#
    .SYNOPSIS
        Sudo for PowerShell! This function allows you to run a command, expression, or scriptblock as if you were
        in an elevated (i.e. "Run as Administrator") context. If you supply credentials for a different user
        that has Admin privileges, you can run the commands as that other user.

        This Start-SudoSession's alias is 'sudo' so that you can run commands via:
            sudo {Install-Module ...}

    .DESCRIPTION
        When used in a Non-Elevated PowerShell session, this function:

        1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
        configuration changes are made)

        2) Checks the Local Group Policy Object...
            Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
        ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

        3) Creates an Elevated PSSession using the New-PSSession cmdlet

        4) Runs the command/expression/scriptblock in the Elevated PSSession

        5) Removes the Elevated PSSession and reverts all changes made (if any) to Local Group Policy and WSMAN/CredSSP config.

    .PARAMETER UserName
        This parameter takes a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This parameter takes a SecureString that represents the password for -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This parameter takes a System.Management.Automation.PSCredential object.

        This parameter is mandatory if you do NOT use the -Password parameter.

    .PARAMETER ScriptBlock
        This parameter is mandatory if you do NOT use the -StringExpression paramter.

        This parameter takes a scriptblock that you would like to run in an elevated context.

    .PARAMETER StringExpression
        This parameter is mandatory is you do NOT use the -ScriptBlock parameter.

        This parameter takes a string that represents a PowerShell expression that will be run in an elevated context.
        Usage is similar to the -Command parameter of the Invoke-Expession cmdlet. See:
        https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/invoke-expression

    .PARAMETER ExistingSudoSession
        This parameter is OPTIONAL, but is used by default if there is an existing Sudo Session available.

        This parameter defaults to using the global variable $global:NewSessionAndOriginalStatus created by the
        New-SudoSession function - specifically its 'ElevatedPSSession' property.

        Command(s)/Expression/ScriptBlock will, by default, be run in this existing Sudo Session, UNLESS
        new Credenitals are provided, in which case a new Sudo Session will be created and the Command(s)/Expression/ScriptBlock
        will be run in that context.

    .EXAMPLE
        PS C:\Users\zeroadmin> sudo {Install-Module -Name Assert}
        Please enter the passworf for 'zero\zeroadmin': ***************

#>
function Start-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    [Alias('sudo')]
    Param(
        [Parameter(
            Mandatory=$False,
            Position=0
        )]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [string]$StringExpression,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [string]$UserName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [securestring]$Password,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply Credentials'
        )]
        [pscredential]$Credentials,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$ExistingSudoSession = $global:NewSessionAndOriginalStatus.ElevatedPSSession
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
    if (GetElevation) {
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$UserName) {
        $UserName = GetCurrentUser
    }
    $SimpleUserName = $($UserName -split "\\")[-1]

    if ($global:SudoCredentials) {
        if (!$Credentials) {
            if ($global:SudoCredentials.UserName -match "\\") {
                $SudoUserName = $($global:SudoCredentials.UserName -split "\\")[-1]
            }
            else {
                $SudoUserName = $global:SudoCredentials.UserName
            }

            if ($SudoUserName -eq $SimpleUserName) {
                $Credentials = $global:SudoCredentials
            }
            elseif ($PSBoundParameters['UserName']) {
                Remove-Variable -Name SudoCredentials -Force -ErrorAction SilentlyContinue
            }
            elseif (!$PSBoundParameters['UserName']) {
                $ErrMsg = "The -UserName parameter was not used, so default current user (i.e. $(whoami)) " +
                "was used. The Sudo Credentials available in the `$global:SudoCredentials object reference UserName " +
                "$($global:SudoCredentials.UserName), which does not match $(whoami)! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
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

    if ($Credentials.UserName -notmatch "\\") {
        Write-Error "The UserName provided to the `$Credentials object is not in the correct format! Please use a UserName with format <Domain>\<User> or <HostName>\<User>! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $global:SudoCredentials = $Credentials

    if ($StringExpression) {
        # Find the variables in the $StringExpression string
        $InitialRegexMatches = $($StringExpression | Select-String -Pattern "\$[\w]+:[\w]+([\W]|[^\s]|[\s]|$)|\$[\w]+([\W]|[^\s]|[\s]|$)" -AllMatches).Matches.Value
        if ($InitialRegexMatches.Count -gt 0) {
            $TrimmedRegexMatches = $InitialRegexMatches | % {$_.Substring(0,$_.Length-1)}
            [array]$VariableNames = $TrimmedRegexmatches -replace "\$",""
            # Redefine variables within this function's scope
            foreach ($varname in $VariableNames) {
                if ($varname -like "*script:*") {
                    New-Variable -Name $varname -Value $(Get-Variable -Name $varname -Scope 2 -ValueOnly)
                }
                if ($varname -like "*local:*" -or $varname -notmatch "script:|global:") {
                    New-Variable -Name $varname -Value $(Get-Variable -Name $varname -Scope 1 -ValueOnly)
                }
            }

            $UpdatedVariableArray = @()
            foreach ($varname in $VariableNames) {
                $SuperVar = [pscustomobject]@{
                    Name    = $varname
                    Value   = Get-Variable -Name $varname -ValueOnly
                }
                
                $UpdatedVariableArray +=, $SuperVar
            }
            # Update the string references to variables in the $StringExpression string if any of them are scope-special
            for ($i=0; $i -lt $VariableNames.Count; $i++) {
                $StringExpression = $StringExpression -replace "$($VariableNames[$i])","args[$i]"
            }
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    if ($ExistingSudoSession.State -eq "Opened") {
        $ElevatedPSSession = $ExistingSudoSession
    }
    else {
        try {
            $SudoSessionInfo = New-SudoSession -Credentials $Credentials -SuppressTimeWarning -ErrorAction Stop
            if (!$SudoSessionInfo) {throw "There was a problem with the New-SudoSession function! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        
        $ElevatedPSSession = $SudoSessionInfo.ElevatedPSSession
    }

    if ($StringExpression) {
        if ($InitialRegexMatches.Count -gt 0) {
            $UpdatedVariableArrayNames = foreach ($varname in $UpdatedVariableArray.Name) {
                "`$"+"$varname"
            }
            [string]$FinalArgumentList = $UpdatedVariableArrayNames -join ","

            # If there is only one argument to pass to the scriptblock, the special $args variable within the scriptblock BECOMES
            # that argument, as opposed to being an array of psobjects that contains one element, i.e. the single argument object
            # So we need to fake it out
            if ($UpdatedVariableArray.Count -eq 1) {
                $FinalArgumentList = "$FinalArgumentList"+","+"`"`""
            }

            # Time for the magic...
            Invoke-Expression "Invoke-Command -Session `$ElevatedPSSession -ArgumentList $FinalArgumentList -Scriptblock {$StringExpression}"
        }
        else {
            Invoke-Expression "Invoke-Command -Session `$ElevatedPSSession -Scriptblock {$StringExpression}"
        }
    }

    if ($ScriptBlock) {
        Invoke-Command -Session $ElevatedPSSession -Scriptblock $ScriptBlock
    }


    if (!$ExistingSudoSession) {
        # Remove the SudoSession
        $null = Remove-SudoSession -SessionToRemove $ElevatedPSSession
    }

    ##### END Main Body #####
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWHxa1Q4gqlLZlE+/O6mWwYwU
# lGegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLfqkCF3NPuO4jlC
# ZEEYWljMvSg+MA0GCSqGSIb3DQEBAQUABIIBAGt5SUBPkVrZ0yrtqPnArYSaf24M
# 1dp1iOJmYjup7TyKBP2o7OAeb386kT9gxs8RLYmkkN53W1TSALKNmclx19EUknot
# eazYVoGOGneQEgRh8Pp9V4frkiPYmvWKVO2dVKyDkP64oT3j06Yi2+NC3mWghMyN
# wZXqNIL1ggZqzHaw2AyBdK5bn7SzCm+2aHXs7w1cRpyrXQe+wg+m0kcdgGwnmUiM
# LVfKvjxEhcIAjT44esw1XXxDRycujE88nRdhmoZQWOqkSnVWl2vahMjq2o3yFMx/
# LT7iITeZjEuhi0BqBqakRcaAamPD7lwfW7xdDp93ujSj73CLeK988rNgvkc=
# SIG # End signature block
