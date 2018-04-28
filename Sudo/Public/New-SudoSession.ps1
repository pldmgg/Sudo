<#
    .SYNOPSIS
        Creates an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session.

    .DESCRIPTION
        Using WSMan's CredSSP Authentication mechanism, this function creates a New PSSession via the New-PSSession
        cmdlet named "Sudo<UserName>". You can then run elevated commands in the Elevated PSSession by
        either entering the Elevated PSSession via the Enter-PSSession cmdlet or by using the Invoke-Command cmdlet with
        its -Session and -ScriptBlock parameters.

        This function will NOT run in a PowerShell Session that is already elevated (i.e. launched using "Run As Administrator").

        When used in a Non-Elevated PowerShell session, this function:

        1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
        configuration changes are made)

        2) Checks the Local Group Policy Object...
            Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
        ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

        3) Creates an Elevated PSSession using the New-PSSession cmdlet

        4) Outputs a PSCustomObject that contains four Properties:
        - ElevatedPSSession - Contains the object [PSSession]ElevatedPSSessionFor<UserName>
        - WSManAndRegistryChanges - Contains another PSCustomObject with the following Properties -
            [bool]WinRMStateChange
            [bool]WSMANServerCredSSPStateChange
            [bool]WSMANClientCredSSPStateChange
            [System.Collections.ArrayList]RegistryKeyCreated
            [System.Collections.ArrayList]RegistryKeyPropertiesCreated
        - ConfigChangesFilePath - Path to the .xml file that logs exactly what changes (if any) were made to WSMAN/CredSSP
        - RevertedChangesFilePath - Path to the .xml file that logs exactly what changes (if any) were made to WSMAN/CredSSP when
        reverting configuration back to what it was prior to using the New-SudoSession function

        IMPORTANT NOTE: By default, all changes made to WSMAN/CredSSP are immediately reverted after the Sudo PSSession has
        been Opened. The Sudo Session will stay open for approximately 3 minutes in this state. If you would like to keep
        the Sudo Session open indefinitely and delay reverting WSMAN/CredSSP configuration changes, use the -KeepOpen
        switch. If the -KeepOpen switch is used the aforementioned 'RevertedChangesFilePath' will be $null (because nothing
        gets reverted until you use the Remove-SudoSession function).

    .NOTES
        Recommend assigning this function to a variable when it is used so that it can be referenced in the companion
        function Remove-SudoSession. If you do NOT assign a variable to this function when it is used, you can always
        reference this function's PSCustomObject output by calling $global:NewSessionAndOriginalStatus, which is a
        Global Scope variable created when this function is run. $global:NewSessionAndOriginalStatus.WSManAndRegistryChanges
        can be used for Remove-SudoSession's -OriginalConfigInfo parameter, and $global:NewSessionAndOriginalStatus.ElevatedPSSesion
        can be used for Remove-SudoSession's -SessionToRemove parameter.

    .PARAMETER UserName
        This parameter takes a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This parameter takes a SecureString that represents the Password for the user specified by -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This parameter takes a System.Management.Automation.PSCredential object with Administrator privileges.

        This parameter is mandatory if you do NOT use the -Password parameter.

    .PARAMETER KeepOpen
        This parameter is a switch.

        If used, the configuration changes made to WSMan/CredSSP will remain until you specifically use the Remove-SudoSession
        function. This allows the Sudo Session to stay open for longer than 3 minutes.

    .PARAMETER SuppressTimeWarning
        This parameter is a switch.

        If used, it will suppress the warning regarding the new Sudo Session only staying open for approximately 3 minutes.

    .EXAMPLE
        PS C:\Users\zeroadmin> New-SudoSession
        Please enter the password for zero\zeroadmin: ************

        ElevatedPSSession                      WSManAndRegistryChanges
        -----------------                      ------------------------------
        [PSSession]Sudozeroadmin 

        PS C:\Users\zeroadmin> Get-PSSession

        Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
        -- ----            ------------    ------------    -----         -----------------     ------------
        1 Sudozeroadmin    localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

        PS C:\Users\zeroadmin> Enter-PSSession -Name Sudozeroadmin
        [localhost]: PS C:\Users\zeroadmin\Documents> 

    .EXAMPLE
        PS C:\Users\zeroadmin> $SudoSessionInfo = New-SudoSession -Credentials $TestAdminCreds
        PS C:\Users\zeroadmin> Get-PSSession

        Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
        -- ----            ------------    ------------    -----         -----------------     ------------
        1 Sudotestadmin    localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

        PS C:\Users\zeroadmin> Invoke-Command -Session $SudoSessionInfo.ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}

    .OUTPUTS
        See DESCRIPTION and NOTES sections

#>
function New-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [ValidatePattern("[\w]+\\[\w]+")]
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
        [System.Management.Automation.PSCredential]$Credentials,

        # If this switch is not used, then the New SudoSession will only stay open for ~3 minutes.
        # IMPORTANT NOTE: If it IS used, then either the 'Remove-SudoSession' or 'Restore-OriginalSystemConfig' functions
        # MUST be used to revert WSMAN and/or CredSSP configurations to what ther were prior to using the 'New-SudoSession' function 
        [Parameter(Mandatory=$False)]
        [switch]$KeepOpen,

        # Meant for use within Start-SudoSession code. Suppresses warning message about the Elevated PSSession only
        # being open for 3 minutes since that doesn't apply to the Start-SudoSession function (where it's only open
        # for the duration of the scriptblock you run)
        [Parameter(Mandatory=$False)]
        [switch]$SuppressTimeWarning
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

    $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
    $LocalHostFQDN = "$env:ComputerName.$Domain"

    ##### END Variable/Parameter Transforms and PreRunPrep #####

    ##### BEGIN Main Body #####

    $CurrentUser = $($(whoami) -split "\\")[-1]
    $SudoSessionFolder = "$HOME\SudoSession_$CurrentUser`_$(Get-Date -Format MMddyyy)"
    if (!$(Test-Path $SudoSessionFolder)) {
        $SudoSessionFolder = $(New-Item -ItemType Directory -Path $SudoSessionFolder).FullName
    }
    $SudoSessionChangesPSObject = "$SudoSessionFolder\SudoSession_Config_Changes_$CurrentUser`_$(Get-Date -Format MMddyyy_hhmmss).xml"
    $TranscriptPath = "$SudoSessionFolder\SudoSession_Transcript_$CurrentUser`_$(Get-Date -Format MMddyyy_hhmmss).txt"
    $SystemConfigScriptFilePath = "$SudoSessionFolder\SystemConfigScript.ps1"
    $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
    $CredSSPServicePath = "WSMan:\localhost\Service\Auth\CredSSP"
    $CredSSPClientPath = "WSMan:\localhost\Client\Auth\CredSSP"
    $AllowFreshValue = "WSMAN/$LocalHostFQDN"

    $SystemConfigScript = @"
    `$CredDelRegLocation = '$CredDelRegLocation'
    `$CredSSPServicePath = '$CredSSPServicePath'
    `$CredSSPClientPath = '$CredSSPClientPath'
    `$AllowFreshValue = '$AllowFreshValue'
    `$SudoSessionChangesPSObject = '$SudoSessionChangesPSObject'
    `$CurrentUser = '$CurrentUser'
    `$TranscriptPath = '$TranscriptPath'

"@ + @'
    Start-Transcript -Path $TranscriptPath -Append

    # Gather output as we go...
    $Output = [ordered]@{}
    [System.Collections.ArrayList]$RegistryKeysCreated = @()
    [System.Collections.ArrayList]$RegistryKeyPropertiesCreated = @()
    $WinRMStateChange = $False


    if (!$(Test-WSMan)) {
        try {
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        $Output.Add("WinRMStateChange",$True)
    }

    ##### BEGIN Registry Tweaks under HKLM:\ #####

    # Create the $CredDelRegLocation Key if it doesn't already exist
    if (!$(Test-Path $CredDelRegLocation)) {
        $CredentialsDelegationKey = New-Item -Path $CredDelRegLocation
        $null = $RegistryKeysCreated.Add($CredentialsDelegationKey)
    }

    # Determine if the $CredDelRegLocation Key itself has a property (DWORD) called 'AllowFreshCredentials'
    # and also if it has a SubKey of the same name (i.e.'AllowFreshCredentials'). Also check if it has a property
    # (DWORD) called 'ConcatenateDefaults_AllowFresh'
    $CredDelRegLocationProperties = Get-ItemProperty -Path $CredDelRegLocation
    $AllowFreshCredsDWORDExists = $($CredDelRegLocationProperties | Get-Member -Type NoteProperty).Name -contains "AllowFreshCredentials"
    $ConcatDefAllowFreshDWORDExists = $($CredDelRegLocationProperties | Get-Member -Type NoteProperty).Name -contains "ConcatenateDefaults_AllowFresh"
    $AllowFreshCredentialsWhenNTLMOnlyDWORDExists = $($CredDelRegLocationProperties | Get-Member -Type NoteProperty).Name -contains "AllowFreshCredentialsWhenNTLMOnly"
    $ConcatenateDefaults_AllowFreshNTLMOnlyDWORDExists = $($CredDelRegLocationProperties | Get-Member -Type NoteProperty).Name -contains "ConcatenateDefaults_AllowFreshNTLMOnly"
    
    # The below should be an array of integers
    [array]$AllowFreshCredsSubKeyCheck = Get-ChildItem -Path $CredDelRegLocation | Where-Object {$_.PSChildName -match "AllowFreshCredentials"}

    # If the two $CredDelRegLocation DWORDs don't exist, create them
    if (!$AllowFreshCredsDWORDExists) {
        $NewAllowFreshCredsProperty = Set-ItemProperty -Path $CredDelRegLocation -Name AllowFreshCredentials -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewAllowFreshCredsProperty)
    }
    if (!$ConcatDefAllowFreshDWORDExists) {
        $NewConcatenateDefaultsProperty = Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFresh -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewConcatenateDefaultsProperty)
    }
    if (!$AllowFreshCredentialsWhenNTLMOnlyDWORDExists) {
        $NewAllowFreshCredsWhenNTLMProperty = Set-ItemProperty -Path $CredDelRegLocation -Name AllowFreshCredentialsWhenNTLMOnly -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewAllowFreshCredsWhenNTLMProperty)
    }
    if (!$ConcatenateDefaults_AllowFreshNTLMOnlyDWORDExists) {
        $NewConcatenateDefaults_AllowFreshNTLMProperty = Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFreshNTLMOnly -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewConcatenateDefaults_AllowFreshNTLMProperty)
    }

    if (!$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {
        $AllowCredentialsKey = New-Item -Path $CredDelRegLocation\AllowFreshCredentials
        $null = $RegistryKeysCreated.Add($AllowCredentialsKey)
    }
    if (!$(Test-Path $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly)) {
        $AllowCredentialsWhenNTLMKey = New-Item -Path $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly
        $null = $RegistryKeysCreated.Add($AllowCredentialsWhenNTLMKey)
    }

    # Should be an array of integers
    [array]$AllowFreshCredsSubKeyPropertyKeys = $(Get-Item $CredDelRegLocation\AllowFreshCredentials).Property
    [array]$AllowFreshCredsWhenNTLMSubKeyPropertyKeys = $(Get-Item $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly).Property

    if ($AllowFreshCredsSubKeyPropertyKeys.Count -eq 0) {
        $AllowFreshCredsSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name 1 -Value $AllowFreshValue -Type String -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsSubKeyNewProperty)
    }
    else {
        [array]$AllowFreshCredsSubKeyPropertyValues = foreach ($key in $AllowFreshCredsSubKeyPropertyKeys) {
            $(Get-ItemProperty $CredDelRegLocation\AllowFreshCredentials).$key
        }

        if ($AllowFreshCredsSubKeyPropertyValues -notmatch [regex]::Escape($AllowFreshValue)) {
            $AllowFreshCredsSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name $($AllowFreshCredsSubKeyPropertyKeys.Count+1) -Value $AllowFreshValue -Type String -Passthru
            $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsSubKeyNewProperty)
        }
    }

    if ($AllowFreshCredsWhenNTLMSubKeyPropertyKeys.Count -eq 0) {
        $AllowFreshCredsWhenNTLMSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value $AllowFreshValue -Type String -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsWhenNTLMSubKeyNewProperty)
    }
    else {
        [array]$AllowFreshCredsWhenNTLMSubKeyPropertyValues = foreach ($key in $AllowFreshCredsWhenNTLMSubKeyPropertyKeys) {
            $(Get-ItemProperty $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly).$key
        }

        if ($AllowFreshCredsWhenNTLMSubKeyPropertyValues -notmatch [regex]::Escape($AllowFreshValue)) {
            $AllowFreshCredsWhenNTLMSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentialsWhenNTLMOnly -Name $($AllowFreshCredsWhenNTLMSubKeyPropertyKeys.Count+1) -Value $AllowFreshValue -Type String -Passthru
            $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsWhenNTLMSubKeyNewProperty)
        }
    }


    $Output.Add("RegistryKeysCreated",$RegistryKeysCreated)
    $Output.Add("RegistryKeyPropertiesCreated",$RegistryKeyPropertiesCreated)

    ##### END Registry Tweaks under HKLM:\ #####

    ##### BEGIN WSMAN Tweaks under WSMAN:\ #####

    try {
        $CredSSPServiceSetting = $(Get-Item $CredSSPServicePath).Value
        if (!$CredSSPServiceSetting) {throw "Unable to get the value of WSMAN:\ path '$CredSSPServicePath'! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    try {
        $CredSSPClientSetting = $(Get-Item $CredSSPClientPath).Value
        if ($CredSSPServiceSetting.Count -eq 0) {throw "Unable to get the value of WSMAN:\ path '$CredSSPClientPath'! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($CredSSPServiceSetting -eq 'false') {
        Enable-WSManCredSSP -Role Server -Force
        $WSMANServerCredSSPStateChange = $True
    }
    $Ouput.Add("WSMANServerCredSSPStateChange",$WSMANServerCredSSPStateChange)
    
    if ($CredSSPClientSetting -eq 'false') {
        Enable-WSManCredSSP -DelegateComputer localhost -Role Client -Force
        $WSMANClientCredSSPStateChange = $True
    }
    $Output.Add("WSMANClientCredSSPStateChange",$WSMANClientCredSSPStateChange)

    ##### END WSMAN Tweaks under WSMAN:\ #####

    [pscustomobject]$Output

    # Create a backup of what we did to the system, just in case the current PowerShell Session is interrupted for some reason
    [pscustomobject]$Output | Export-CliXml $SudoSessionChangesPSObject
'@ | Set-Content $SystemConfigScriptFilePath
    
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
    try {
        $Process.Start() | Out-Null
    }
    catch {
        Write-Error $_
        Write-Error "User did not accept the UAC Prompt! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $Process.WaitForExit()
    $SystemConfigScriptResult = Import-CliXML $SudoSessionChangesPSObject

    $ElevatedPSSession = New-PSSession -Name "Sudo$SimpleUserName" -Authentication CredSSP -Credential $Credentials

    if (!$KeepOpen) {
        try {
            $RestoreOriginalSystemConfig = Restore-OriginalSystemConfig -OriginalConfigInfo $SystemConfigScriptResult -ExistingSudoSession $ElevatedPSSession -Credentials $Credentials
            if (!$RestoreOriginalSystemConfig) {throw "Problem restoring original WSMAN and CredSSP system config! See '$SudoSessionChangesPSObject' for information about what was changed."}
            
            $SudoSessionRevertChangesPSObject = $($(Resolve-Path "$SudoSessionFolder\SudoSession_Config_Revert_Changes_*.xml").Path | foreach {
                Get-Item $_
            } | Sort-Object -Property CreationTime)[-1].FullName
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    else {
        $WrnMsg = "Please be sure to run `Remove-SudoSession -SessionToRemove '`$(Get-PSSession -Id $($ElevatedPSSession.Id))' before you " +
        "close PowerShell in order to remove the SudoSession and revert WSMAN and CredSSP configuration changes."

        Write-Warning $WrnMsg
    }

    New-Variable -Name "NewSessionAndOriginalStatus" -Scope Global -Value $(
        [pscustomobject][ordered]@{
            ElevatedPSSession               = $ElevatedPSSession
            WSManAndRegistryChanges         = $SystemConfigScriptResult
            ConfigChangesFilePath           = $SudoSessionChangesPSObject
            RevertedChangesFilePath         = $SudoSessionRevertChangesPSObject
        }
    ) -Force
    
    $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly)

    # Cleanup 
    Remove-Item $SystemConfigScriptFilePath
    
    if (!$($SuppressTimeWarning -or $KeepOpen)) {
        Write-Warning "The New SudoSession named '$($ElevatedPSSession.Name)' with Id '$($ElevatedPSSession.Id)' will stay open for approximately 3 minutes!"
    }

    ##### END Main Body #####

}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxmKwyplsJCm1U8o+rc0YiahM
# +bagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEPg5GuNc5HmBhtZ
# ir9ipz/K9YnSMA0GCSqGSIb3DQEBAQUABIIBABWZB9J1AdUjKAtQKyepo2sWfQdH
# tbWwSVfIr24ZMImwIOIg0kuZM3Dm1HzH7BgDdMHLzWDk8AxAZgWsP0WE6bsUI1Tm
# Zgo5EFc0yc1nVphd8ZFZqoz3RhWwq7RzfClK1V0WqKmBH2n2vrFpdwVkTJGiqYNw
# C7VTmpNgdThPO2XLvrSFXViZv4eYFCZ3IwEiN0lPGR3Bn6s4tanxcHuLsnEtG50X
# UsfIOm9gWdInBfvi4YpxVLwTar7XJO1Vg0ubECzEMId1u275YSveZcSq0PibutrM
# W3SI/NpYFejDY5hx1NZCVw2icr/DI+3t2qXsgSLxN3oXSGkI+yTbLo/lZ/k=
# SIG # End signature block
