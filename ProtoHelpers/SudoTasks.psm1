function GetElevation {
    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

        if($currentPrincipal.IsInRole($administratorsRole)) {
            return $true
        }
        else {
            return $false
        }
    }
    
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -eq "root") {
            return $true
        }
        else {
            return $false
        }
    }
}


<#
    .SYNOPSIS
        Creates an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session.

    .DESCRIPTION
        Using WSMan's CredSSP Authentication mechanism, this function creates a New PSSession via the New-PSSession
        cmdlet named "ElevatedPSSessionFor<UserName>". You can then run elevated commands in the Elevated PSSession by
        either entering the Elevated PSSession via Enter-PSSession cmdlet or by using the Invoke-Command cmdlet with
        its -Session parameter.

        This function will NOT run in a PowerShell Session that was launched using "Run As Administrator".

        When used in a Non-Elevated PowerShell session, this function:

        1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
        configuration changes are made)

        2) Checks the Local Group Policy Object...
            Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
        ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

        3) Creates an Elevated PSSession using the New-PSSession cmdlet

        4) Outputs a PSCustomObject that contains two Properties:
        - ElevatedPSSession - Contains the object [PSSession]ElevatedPSSessionFor<UserName>
        - WSManAndRegistryChanges - Contains another PSCustomObject with the following Properties -
            [bool]WinRMStateChange
            [bool]WSMANServerCredSSPStateChange
            [bool]WSMANClientCredSSPStateChange
            [System.Collections.ArrayList]RegistryKeyCreated
            [System.Collections.ArrayList]RegistryKeyPropertiesCreated

    .NOTES
        Recommend assigning this function to a variable when it is used so that it can be referenced in the companion
        function Remove-SudoSessionTask. If you do NOT assign a variable to this function when it is used, you can always
        reference this function's PSCustomObject output by calling $global:NewSessionAndOriginalStatus, which is a
        Global Scope variable created when this function is run. $global:NewSessionAndOriginalStatus.WSManAndRegistryChanges
        can be used for Remove-SudoSessionTask's -OriginalConfigInfo parameter, and $global:NewSessionAndOriginalStatus.ElevatedPSSesion
        can be used for Remove-SudoSessionTask's -SessionToRemove parameter.

    .PARAMETER UserName
        This is a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This can be either a plaintext string or a secure string that represents the password for the -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

    .EXAMPLE
        PS C:\Users\zeroadmin> New-SudoSessionTask -UserName zeroadmin -Credentials $MyCreds

        ElevatedPSSession                      WSManAndRegistryChanges
        -----------------                      ------------------------------
        [PSSession]ElevatedSessionForzeroadmin 

        PS C:\Users\zeroadmin> Get-PSSession

        Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
        -- ----            ------------    ------------    -----         -----------------     ------------
        1 ElevatedSess... localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

        PS C:\Users\zeroadmin> Enter-PSSession -Name ElevatedSessionForzeroadmin
        [localhost]: PS C:\Users\zeroadmin\Documents> 

    .EXAMPLE
        PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSessionTask -UserName zeroadmin -Credentials $MyCreds
        PS C:\Users\zeroadmin> Get-PSSession

        Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
        -- ----            ------------    ------------    -----         -----------------     ------------
        1 ElevatedSess... localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

        PS C:\Users\zeroadmin> Invoke-Command -Session $MyElevatedSession.ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}

    .OUTPUTS
        See DESCRIPTION and NOTES sections

#>
function New-SudoSessionTask {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
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
        [System.Management.Automation.PSCredential]$Credentials,

        # If this switch is not used, then the New SudoSession will only stay open for ~3 minutes.
        # IMPORTANT NOTE: If it IS used, then either the 'Remove-SudoSessionTask' or 'Restore-OriginalSystemConfigTask' functions
        # MUST be used to revert WSMAN and/or CredSSP configurations to what ther were prior to using the 'New-SudoSessionTask' function 
        [Parameter(Mandatory=$False)]
        [switch]$KeepOpen,

        # Meant for use within Start-SudoSessionTask code. Suppresses warning message about the Elevated PSSession only
        # being open for 3 minutes since that doesn't apply to the Start-SudoSessionTask function (where it's only open
        # for the duration of the scriptblock you run)
        [Parameter(Mandatory=$False)]
        [switch]$StartSudo
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (GetElevation) {
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSessionTask function. Halting!"
        $global:FunctionResult = "1"
        return
    }

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
    else {
        $Output.Add("WinRMStateChange",$False)
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
    $ConcatDefAllowFreshDWORDExsits = $($CredDelRegLocationProperties | Get-Member -Type NoteProperty).Name -contains "ConcatenateDefaults_AllowFresh"
    # The below should be an array of integers
    [array]$AllowFreshCredsSubKeyCheck = $AllowFreshCredsSubKeyPropertyKeys = Get-ChildItem -Path $CredDelRegLocation | Where-Object {$_.PSChildName -eq "AllowFreshCredentials"}

    # If the two $CredDelRegLocation DWORDs don't exist, create them
    if (!$AllowFreshCredsDWORDExists) {
        $NewAllowFreshCredsProperty = Set-ItemProperty -Path $CredDelRegLocation -Name AllowFreshCredentials -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewAllowFreshCredsProperty)
    }
    if (!$ConcatDefAllowFreshDWORDExsits) {
        $NewConcatenateDefaultsProperty = Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFresh -Value 1 -Type DWord -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($NewConcatenateDefaultsProperty)
    }
    if ($AllowFreshCredsSubKeyCheck.Count -eq 0) {
        $AllowCredentialsKey = New-Item -Path $CredDelRegLocation\AllowFreshCredentials
        $null = $RegistryKeysCreated.Add($AllowCredentialsKey)

        # Should be an array of integers
        [array]$AllowFreshCredsSubKeyPropertyKeys = $(Get-Item $CredDelRegLocation\AllowFreshCredentials).Property
    }

    if ($AllowFreshCredsSubKeyPropertyKeys.Count -eq 0) {
        $AllowFreshCredsSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name 1 -Value $AllowFreshValue -Type String -Passthru
        $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsSubKeyNewProperty)
    }
    else {
        [array]$AllowFreshCredsSubKeyPropertyValues = foreach ($key in $AllowFreshCredsSubKeyPropertyKeys) {
            $(Get-ItemProperty $CredDelRegLocation\AllowFreshCredentials).$key
        }

        if ($AllowFreshCredsSubKeyPropertyValues -notcontains $AllowFreshValue) {
            $AllowFreshCredsSubKeyNewProperty = Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name $($AllowFreshCredsSubKeyPropertyKeys.Count+1) -Value $AllowFreshValue -Type String -Passthru
            $null = $RegistryKeyPropertiesCreated.Add($AllowFreshCredsSubKeyNewProperty)
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
        $Output.Add("WSMANServerCredSSPStateChange",$True)
    }
    
    if ($CredSSPClientSetting -eq 'false') {
        Enable-WSManCredSSP -DelegateComputer localhost -Role Client -Force
        $Output.Add("WSMANClientCredSSPStateChange",$True)
    }

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
        Write-Error "User did not accept the UAC Prompt! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $Process.WaitForExit()
    $SystemConfigScriptResult = Import-CliXML $SudoSessionChangesPSObject

    $ElevatedPSSession = New-PSSession -Name "Sudo$UserName" -Authentication CredSSP -Credential $Credentials

    if (!$KeepOpen) {
        try {
            $RestoreOriginalSystemConfig = Restore-OriginalSystemConfigTask -OriginalConfigInfo $SystemConfigScriptResult -ExistingSudoSession $ElevatedPSSession
            if (!$RestoreOriginalSystemConfig) {throw "Problem restoring original WSMAN and CredSSP system config! See '$SudoSessionChangesPSObject' for information about what was changed."}
            
            $SudoSessionRevertChangesPSObject = $($(Resolve-Path "$SudoSessionFolder\SudoSession_Config_Revert_Changes_*.xml").Path | foreach {
                Get-Item $_
            } | Sort-Object -Property CreationTime)[-1]
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    else {
        $WrnMsg = "Please be sure to run `Remove-SudoSessionTask -SessionToRemove '`$(Get-PSSession -Id $($ElevatedPSSession.Id))' before you " +
        "close PowerShell in order to remove the SudoSession and revert WSMAN and CredSSP configuration changes."
    }

    New-Variable -Name "NewSessionAndOriginalStatus" -Scope Global -Value $(
        [pscustomobject]@{
            ElevatedPSSession               = $ElevatedPSSession
            WSManAndRegistryChanges         = $SystemConfigScriptResult
            ConfigChangesFilePath           = $SudoSessionChangesPSObject
            RevertedChangesFilePath         = $SudoSessionRevertChangesPSObject
        }
    ) -Force
    
    $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly)

    # Cleanup 
    Remove-Item $SystemConfigScriptFilePath
    
    if (!$($StartSudo -or $KeepOpen)) {
        Write-Warning "The New SudoSession named '$($ElevatedPSSession.Name)' with Id '$($ElevatedPSSession.Id)' will stay open for approximately 3 minutes!"
    }

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        Removes an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session and
        and reverts any changes in WSMAN/WinRM and GPO configuration made by the companion New-SudoSessionTask function.

        This is a companion function with New-SudoSessionTask. If you DO NOT want to ensure that WinRM/WSMan and GPO configuration
        is as it was prior to running New-SudoSessionTask, there is no reason to use this function. You can simply use...
            Get-PSSession | Remove-PSession
        ...like any other normal PSSession.

        If you DO want to ensure that WinRM/WSMan and GPO configuration is as it was prior to running New-SudoSessionTask, then
        use this function with its -RevertConfig switch and -OriginalConfigInfo parameter.

    .DESCRIPTION
        Removes an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session and
        and reverts any changes in WSMAN/WinRM and GPO configuration made by the companion New-SudoSessionTask function.
        
        This is a companion function with New-SudoSessionTask. If you DO NOT want to ensure that WinRM/WSMan and GPO configuration
        is as it was prior to running New-SudoSessionTask, there is no reason to use this function. You can simply use...
            Get-PSSession | Remove-PSession
        ...like any other normal PSSession.

        If you DO want to ensure that WinRM/WSMan and GPO configuration is as it was prior to running New-SudoSessionTask, then
        use this function with its -RevertConfig switch and -OriginalConfigInfo parameter.

    .PARAMETER UserName
        This is a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This can be either a plaintext string or a secure string that represents the password for the -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

    .PARAMETER OriginalConfigInfo
        A PSCustomObject that can be found in the "WSManAndRegistryChanges" property of the PSCustomObject generated
        by the New-SudoSessionTask function. The "WSManAndRegistryChanges" property is itself a PSCustomObject with the
        following properties:
            [bool]WinRMStateChange
            [bool]WSMANServerCredSSPStateChange
            [bool]WSMANClientCredSSPStateChange
            [System.Collections.ArrayList]RegistryKeyCreated
            [System.Collections.ArrayList]RegistryKeyPropertiesCreated

    .PARAMETER SessionToRemove
        A System.Management.Automation.Runspaces.PSSession object that you would like to remove. You can use the 
        "ElevatedPSSession" property of the PSCustomObject generated by the New-SudoSessionTask function, or, you can simply
        get whichever PSSession you would like to remove by doing the typical...
            Get-PSSession -Name <Name>
        
        This parameter accepts value from the pipeline.

    .EXAMPLE
        Get-PSSession -Name <Name>
        $ModuleToInstall = "PackageManagement"
        $LatestVersion = $(Find-Module PackageManagement).Version
        # PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
        $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'

        $SudoSession = New-SudoSessionTask -Credentials $MyCreds -Expression $InstallModuleExpression

        Remove-SudoSessionTask -Credentials $MyCreds -OriginalConfigInfo $SudoSession.WSManAndRegistryChanges -SessionToRemove $SudoSession.ElevatedPSSession

#>
function Remove-SudoSessionTask {
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
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSessionTask function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($OriginalConfigInfo -eq $null) {
        Write-Warning "Unable to determine the original configuration of WinRM/WSMan and AllowFreshCredentials Registry prior to using New-SudoSessionTask. No configuration changes will be made/reverted."
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
            Restore-OriginalSystemConfigTask @RestoreOriginalSystemConfigSplatParams
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


# Just in case the PowerShell Session in which you originally created the SudoSession is killed/interrupted,
# you can use this function to revert WSMAN/Registry changes that were made with the New-SudoSessionTask function.
# Example:
#   Restore-OriginalSystemConfigTask -SudoSessionChangesLogFilePath "$HOME\SudoSession_04182018\SudoSession_Config_Changes_04182018_082747.xml"
function Restore-OriginalSystemConfigTask {
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

    $CurrentUser = $($(whoami) -split "\\")[-1]
    $SudoSessionFolder = "$HOME\SudoSession_$CurrentUser`_$(Get-Date -Format MMddyyy)"
    if (!$(Test-Path $SudoSessionFolder)) {
        $SudoSessionFolder = $(New-Item -ItemType Directory -Path $SudoSessionFolder).FullName
    }
    $SudoSessionRevertChangesPSObject = "$SudoSessionFolder\SudoSession_Config_Revert_Changes_$CurrentUser`_$(Get-Date -Format MMddyyy_hhmmss).xml"

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
        Sudo for PowerShell! This function allows you to run an expression as if you were in "Run as Administrator" mode.

    .DESCRIPTION
        Using WSMan's CredSSP Authentication mechanism, this function allows you to run expressions in "Run as Administrator"
        mode. This function is perfect for scripts/functions/modules that have one or two lines that absolutely need to be
        Run As Administrator, but otherwise do not need elevated permissions.

        When used in a Non-Elevated PowerShell session, this function:

        1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
        configuration changes are made)

        2) Checks the Local Group Policy Object...
            Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
        ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

        3) Creates an Elevated PSSession using the New-PSSession cmdlet

        4) Runs the expression passed to the -Expression parameter in the Elevated PSSession

        5) Removes the Elevated PSSession and reverts all changes made (if any) to Local Group Policy and WSMAN/WinRM config.

    .PARAMETER UserName
        This is a string that represents a UserName with Administrator privileges. Defaults to current user.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Password
        This can be either a plaintext string or a secure string that represents the password for the -UserName.

        This parameter is mandatory if you do NOT use the -Credentials parameter.

    .PARAMETER Credentials
        This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

    .PARAMETER Expression
        This a *string* that represents a PowerShell expression that will be Run as Administrator. Usage is similar
        to the -Command parameter of the Invoke-Expession cmdlet. See:
        https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/invoke-expression

    .EXAMPLE
        $ModuleToInstall = "PackageManagement"
        $LatestVersion = $(Find-Module PackageManagement).Version
        # PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
        $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'

        Start-SudoSessionTask -Credentials $MyCreds -Expression $InstallModuleExpression

    .OUTPUTS

#>
function Start-SudoSessionTask {
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
        [pscredential]$Credentials,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$ExistingSudoSession = $global:NewSessionAndOriginalStatus.ElevatedPSSession
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
    if (GetElevation) {
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSessionTask function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($ScriptBlock -and $StringExpression) {
        Write-Error "The function $(MyInvocation.MyCommand.Name) takes EITHER the -ScriptBlock parameter (position 0) OR the -StringExpression parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

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
            $SudoSessionInfo = New-SudoSessionTask -Credentials $Credentials -StartSudo -ErrorAction Stop
            if (!$SudoSessionInfo) {throw "There was a problem with the New-SudoSessionTask function! Halting!"}
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
        $null = Remove-SudoSessionTask -SessionToRemove $ElevatedPSSession
    }

    ##### END Main Body #####
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUf/CZa1QujtMD5t6HtSh9mmHI
# tV2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFG/y2IV0DlDAKkYj
# NOql8EUG6cv3MA0GCSqGSIb3DQEBAQUABIIBADQwd28gi0UuiBf7XSyA1EG2EeUr
# Y8HZh7l8OmMHFdNSBz0MJIThUOduXNMzuA5NEeoczbffL9myj2hUef0jFYotFjwr
# Kkz0JJ/UIHgAM3DZrL++NywaNLQKlTftGvOGf9TGkIoP4GfVBKZuFi4w0VPg3DO6
# krD3DiLp/cJsyEEVftoNy2Qzo6MILSek/O+M6ADfWs1g/1hPl2u7KrhqXiKMaxUA
# DyaCsTWX1x8PFF6f+ux68bn7zKN3sN+EfOOa7vigqp3JSLVRdSra54a/NW9Q6q7G
# Og/muiZCKLk/XQJ5izltrk7O8WW2I5otlv3vO2fsINXU+1fSPSehy5bAFy4=
# SIG # End signature block
