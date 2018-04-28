[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

# Public Functions


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


<#
    .SYNOPSIS
        Removes a Sudo Session (i.e. elevated PSSession) for the current user in the current PowerShell Session and
        and reverts any changes to WSMAN/CredSSP made by the New-SudoSession function.

        IMPORTANT NOTE: This function should only be necessary if the New-SudoSession function was used with the -KeepOpen switch!
        It is meant to be used in the same PowerShell Session that the New-SudoSession function was used in.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER SessionToRemove
        This parameter is MANDATORY.
        
        This parameter takes a System.Management.Automation.Runspaces.PSSession object that you would like to remove.
        
        NOTE: The Name property of the PSSession object provided to this paramter should be "Sudo<UserName>". This
        function is not meant to be used to close any other kind of PSSession.

    .PARAMETER OriginalConfigInfo
        This parameter is MANDATORY.

        This parameter defaults to the 'WSManAndRegistryChanges' property of the global variable created via the New-SudoSession
        function called $global:NewSessionAndOriginalStatus, which is a PSCustomObject with the following properties:
            [bool]WinRMStateChange
            [bool]WSMANServerCredSSPStateChange
            [bool]WSMANClientCredSSPStateChange
            [System.Collections.ArrayList]RegistryKeyCreated
            [System.Collections.ArrayList]RegistryKeyPropertiesCreated

    .PARAMETER UserName
        This is a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This can be either a plaintext string or a secure string that represents the password for the -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

    .EXAMPLE
        PS C:\Users\zeroadmin> $SudoSessionInfo = New-SudoSession -Credentials $MyCreds
        PS C:\Users\zeroadmin> Remove-SudoSession -Credentials $MyCreds -OriginalConfigInfo $SudoSessionInfo.WSManAndRegistryChanges -SessionToRemove $SudoSessionInfo.ElevatedPSSession

#>
function Remove-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True,
            Position=0
        )]
        [System.Management.Automation.Runspaces.PSSession]$SessionToRemove,

        [Parameter(Mandatory=$False)]
        $OriginalConfigInfo = $global:NewSessionAndOriginalStatus.WSManAndRegistryChanges,

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

    if (GetElevation) {
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($OriginalConfigInfo -eq $null) {
        Write-Warning "Unable to determine the original configuration of WinRM/WSMan and AllowFreshCredentials Registry prior to using New-SudoSession. No configuration changes will be made/reverted."
        Write-Warning "The only action will be removing the Elevated PSSession specified by the -SessionToRemove parameter."
    }

    ##### END Variable/Parameter Transforms and PreRunPrep #####

    ##### BEGIN Main Body #####

    if ($OriginalConfigInfo -ne $null) {
        $RestoreOriginalSystemConfigSplatParams = @{
            ExistingSudoSession     = $SessionToRemove
            OriginalConfigInfo      = $OriginalConfigInfo
            ErrorAction             = "Stop"
        }

        if ($SessionToRemove.State -ne "Opened") {
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
        
            $global:SudoCredentials = $null
        }

        if ($Credentials) {
            $RestoreOriginalSystemConfigSplatParams.Add("Credentials",$Credentials)
        }

        try {
            Restore-OriginalSystemConfig @RestoreOriginalSystemConfigSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    try {
        Remove-PSSession $SessionToRemove -ErrorAction Stop
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        Restores WSMan and CredSSP settings to what they were prior to running the 'New-SudoSession' or 'Start-SudoSession'
        functions.

        IMPORTANT NOTE: You would use this function as opposed to the 'Remove-SudoSession' function under the following circumstance:
            - You use the New-SudoSession with the -KeepOpen switch in a PowerShell Process we'll call 'A'
            - PowerShell Process 'A' is killed/closed unexpectedly prior to the user running the Remove-SudoSession function
            - PowerShell Process 'B' is started, the Sudo Module is imported, and this Restore-OriginalSystemConfig function
            is used to revert WSMAN/CredSSP config changes made by the New-SudoSession function in PowerShell Process 'A'

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER ExistingSudoSession
        Unless you are using the -ForceCredSSPReset switch, this parameter is MANDATORY.

        This parameter takes a System.Management.Automation.Runspaces.PSSession object.

    .PARAMETER SudoSessionChangesLogFilePath
        Unless you are using the -ForceCredSSPReset switch, this parameter is MANDATORY.

        This parameter taks a path to the .xml file generated by the New-SudoSession or Start-SudoSession functins
        that logs exactly what changes to WSMan and CredSSP were made. The file name for this file defaults to the
        format 'SudoSession_Config_Changes_<User>_<MMddyyyy>_<hhmmss>.xml'

    .PARAMETER OriginalConfigInfo
        This parameter is OPTIONAL.

        This parameter takes a PSCustomObject that can be found in the "WSManAndRegistryChanges" property of the
        PSCustomObject generated by the New-SudoSession function. The "WSManAndRegistryChanges" property is itself a
        PSCustomObject with the following properties:
            [bool]WinRMStateChange
            [bool]WSMANServerCredSSPStateChange
            [bool]WSMANClientCredSSPStateChange
            [System.Collections.ArrayList]RegistryKeyCreated
            [System.Collections.ArrayList]RegistryKeyPropertiesCreated

    .PARAMETER UserName
        This parameter is OPTIONAL.

        This parameter takes a string and defaults to the Current User.

        If you are running the Restore-OriginalSystemConfig function from a non-elevated PowerShell session, then credentials
        with Adminstrator privileges must be provided in order to revert the WSMan and CredSSP changes that were made by the
        New-SudoSession and/or the Start-SudoSession functions.

    .PARAMETER Password
        This parameter is OPTIONAL.

        This parameter takes a SecureString. It should only be used if this function is being run from a non-elevated PowerShell
        Session and if the -Credentials parameter is NOT used.

        If you are running the Restore-OriginalSystemConfig function from a non-elevated PowerShell session, then credentials
        with Adminstrator privileges must be provided in order to revert the WSMan and CredSSP changes that were made by the
        New-SudoSession and/or the Start-SudoSession functions.

    .PARAMETER Credentials
        This parameter is OPTIONAL.

        This parameter takes a System.Management.Automation.PSCredential. It should only be used if this function is being run from
        a non-elevated PowerShell Session and if the -Password parameter is NOT used.

        If you are running the Restore-OriginalSystemConfig function from a non-elevated PowerShell session, then credentials
        with Adminstrator privileges must be provided in order to revert the WSMan and CredSSP changes that were made by the
        New-SudoSession and/or the Start-SudoSession functions.

    .PARAMETER ForceCredSSPReset
        This parameter is OPTIONAL.

        This parameter is a switch.

        If used, all CredSSP settings will be set to disallow CredSSP authentication regardless of current system configuration state.

    .EXAMPLE
        PS C:\Users\zeroadmin> $SudoSessionInfo = New-SudoSession -Credentials $MyCreds
        PS C:\Users\zeroadmin> Remove-SudoSession -Credentials $MyCreds -OriginalConfigInfo $SudoSessionInfo.WSManAndRegistryChanges -SessionToRemove $SudoSessionInfo.ElevatedPSSession

#>
# Just in case the PowerShell Session in which you originally created the SudoSession is killed/interrupted,
# you can use this function to revert WSMAN/Registry changes that were made with the New-SudoSession function.
# Example:
#   Restore-OriginalSystemConfig -SudoSessionChangesLogFilePath "$HOME\SudoSession_04182018\SudoSession_Config_Changes_04182018_082747.xml"
function Restore-OriginalSystemConfig {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$ExistingSudoSession,

        [Parameter(Mandatory=$False)]
        [string]$SudoSessionChangesLogFilePath,

        [Parameter(Mandatory=$False)]
        $OriginalConfigInfo,

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
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$False)]
        [switch]$ForceCredSSPReset
    )

    # CredSSP Reset In Case of Emergency
    if ($ForceCredSSPReset) {
        $CredSSPRegistryKey = Get-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ErrorAction SilentlyContinue

        if ($CredSSPRegistryKey) {
            Remove-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Recurse -Force

            [pscustomobject]@{
                RegistryKeysRemoved = @($CredSSPRegistryKey)
            }
        }
        else {
            Write-Warning "CredSSP is not enabled. No action taken."
        }
        
        return
    }

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($(!$SudoSessionChangesLogFilePath -and !$OriginalConfigInfo) -or $($SudoSessionChangesLogFilePath -and $OriginalConfigInfo)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -SudoSessionChangesLogFilePath parameter or the -OriginalConfigInfoParameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($SudoSessionChangesLogFilePath) {
        # First, ingest SudoSessionChangesLogFilePath
        if (!$(Test-Path $SudoSessionChangesLogFilePath)) {
            Write-Error "The path $SudoSessionChangesLogFilePath was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            $OriginalConfigInfo = Import-CliXML $SudoSessionChangesLogFilePath
        }
    }

    # Validate $OriginalConfigInfo
    if ($OriginalConfigInfo) {
        $ValidNoteProperties = @("RegistryKeyPropertiesCreated","RegistryKeysCreated","WinRMStateChange","WSMANServerCredSSPStateChange","WSMANClientCredSSPStateChange")
        $ParamObjNoteProperties = $($OriginalConfigInfo | Get-Member -Type NoteProperty).Name
        foreach ($Prop in $ParamObjNoteProperties) {
            if ($ValidNoteProperties -notcontains $Prop) {
                if ($PSBoundParameters['SudoSessionChangesLogFilePath']) {
                    $ErrMsg = "The `$OriginalConfigInfo Object derived from the '$SudoSessionChangesLogFilePath' file is not valid! Halting!"
                }
                if ($PSBoundParameters['OriginalConfigInfo']) {
                    $ErrMsg = "The `$OriginalConfigInfo Object passed to the -OriginalConfigInfo parameter is not valid! Halting!"
                }
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }

    $CurrentUser = $($(GetCurrentUser) -split "\\")[-1]
    $SudoSessionFolder = "$HOME\SudoSession_$CurrentUser`_$(Get-Date -Format MMddyyy)"
    if (!$(Test-Path $SudoSessionFolder)) {
        $SudoSessionFolder = $(New-Item -ItemType Directory -Path $SudoSessionFolder).FullName
    }
    $SudoSessionRevertChangesPSObject = "$SudoSessionFolder\SudoSession_Config_Revert_Changes_$CurrentUser`_$(Get-Date -Format MMddyyy_hhmmss).xml"

    if (!$UserName) {
        $UserName = GetCurrentUser
    }

    if (!$(GetElevation)) {
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

    if (GetElevation) {
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
                    if ([bool]$(Get-ItemProperty -Path $PropertyPath -Name $PropertyName -ErrorAction SilentlyContinue)) {
                        Remove-ItemProperty -Path $PropertyPath -Name $PropertyName
                        $null = $RegistryKeyPropertiesRemoved.Add($Property)
                    }
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

            $FinalOutput = [pscustomobject]$Output
            $FinalOutput | Export-CliXml $SudoSessionRevertChangesPSObject
        }
    }
    
    if (!$(GetElevation) -and $ExistingSudoSession) {
        if ($ExistingSudoSession.State -eq "Opened") {
            $SystemConfigSB = {
                $OriginalConfigInfo = $using:OriginalConfigInfo

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
                            if ([bool]$(Get-ItemProperty -Path $PropertyPath -Name $PropertyName -ErrorAction SilentlyContinue)) {
                                Remove-ItemProperty -Path $PropertyPath -Name $PropertyName
                                $null = $RegistryKeyPropertiesRemoved.Add($Property)
                            }
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
                    [pscustomobject]$Output
                }
            }

            $FinalOutput = Invoke-Command -Session $ExistingSudoSession -Scriptblock $SystemConfigSB
            $FinalOutput | Export-CliXml $SudoSessionRevertChangesPSObject
        }
        else {
            $useAltMethod = $True
        }
    }

    if ($(!$(GetElevation) -and !$ExistingSudoSession) -or $UseAltMethod) {
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
                    $MoreLinesToAdd = @(
                        "if ([bool](Get-ItemProperty -Path '$PropertyPath' -Name '$PropertyName' -EA SilentlyContinue)) {"
                        "    `$null = `$RegistryKeyPropertiesRemoved.Add((Get-ItemProperty -Path '$PropertyPath' -Name '$PropertyName'))"
                        "    Remove-ItemProperty -Path '$PropertyPath' -Name '$PropertyName'"
                        "}"
                    )

                    foreach ($Line in $MoreLinesToAdd) {
                        $null = $SystemConfigScript.Add($Line)
                    }
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
        
        $FinalOutput = Import-CliXML $SudoSessionRevertChangesPSObject
    }

    $FinalOutput

    ##### END Main Body #####
        
}


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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUok0+TGemozDVB4mza5HwMTBr
# Wcygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNRSHBLGyU3rR22u
# 7q2k1o2lfZGaMA0GCSqGSIb3DQEBAQUABIIBALK/cXDuq5FVm02uLXrmTcYwD3m7
# xYaOJAL+61B5FPhbiqB4EE4esaT+5umVXz+RONL4u3rCR23jjToEzrttmoftx/jc
# GrhN+1Fqe6FqxtOWGaIjIMqCLJ2Oce6UEorN7btxAvgtnxkrbercDFxed+nPNzD3
# 08QAoESaHIeBqsVzh6Pqoa20Jm0QdFLfvqciAMXfH4Fe+GBS9Kx96eAWLnEeOa/i
# t+qcGHmdc4EQgpA0hW3zI8kWn2Su+dDkpcYrJ4uEkUuX52lkg+m8Lpj54rWAU83r
# PdO5CgqUmS/kgAVkH/7f996liBDZXE1TR82lleDzVukzKkGmto/MXk1l0VM=
# SIG # End signature block
