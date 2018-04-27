[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)
# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# NOTE: If -TestResources was used, the folloqing resources should be available
<#
    $TestResources = @{
        UserName        = $UserName
        SimpleUserName  = $SimpleUserName
        Password        = $Password
        Creds           = $Creds
    }
#>

# Make sure the Module is loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}
if (![bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Import-Module $env:BHPSModuleManifest -Force
}
$global:SudoCredentials = $null
$global:NewSessionAndOriginalStatus = $null

$FakeSystemConfigScriptHT = [ordered]@{
    "RegistryKeysCreated"               = $([System.Collections.ArrayList]::new())
    "RegistryKeyPropertiesCreate"       = $([System.Collections.ArrayList]::new())
    "WinRMStateChange"                  = $False
    "WSMANServerCredSSPStateChange"     = $False
    "WSMANClientCredSSPStateChange"     = $False
}

$FakeSystemRevertConfigScriptHT = [ordered]@{
    "RegistryKeysRemoved"               = $([System.Collections.ArrayList]::new())
    "RegistryKeyPropertiesRemoved"      = $([System.Collections.ArrayList]::new())
    "CredSSPServer"                     = "Off"
    "CredSSPClient"                     = "Off"
    "PSRemoting"                        = "Disabled"
    "WinRMService"                      = "Stopped"
    "WSMANServerAllowRemoteAccess"      = $False
}

$ConfigChangesFilePath = "$HOME\Downloads\Changes.xml"
$RevertChangesFilePath = "$HOME\Downloads\RevertChanges.xml"

$FakeOutputHT = [ordered]@{
    "ElevatedPSSession"         = $True
    "WSManAndRegistryChanges"   = [pscustomobject]$FakeSystemConfigScriptHT
    "ConfigChangesFilePath"     = $ConfigChangesFilePath
    "RevertedChangesFilePath"   = $RevertChangesFilePath
}

$Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
$LocalHostFQDN = "$env:ComputerName.$Domain"

$global:SudoCredentials = $null
$global:NewSessionAndOriginalStatus = $null

function Cleanup {
    [CmdletBinding()]
    Param (
        $SudoSessionInfo
    )

    if ($SudoSessionInfo -ne $null) {
        $RMSplat = @{
            Credentials         = $global:MockResources['Creds']
            SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
            OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
        }
        try {
            $null = Remove-SudoSession @RMSplat
        }
        catch {
            Write-Warning "Problem with 'Remove-SudoSession' function in New-SudoSession.Tests.ps1!"
        }
    }
    else {
        $SessionToRemove = Get-PSSession -Name "Sudo$($global:MockResources['SimpleUserName'])"
        if ($SessionToRemove) {
            Remove-PSSession -Session $SessionToRemove
        }
        try {
            Restore-OriginalSystemConfig -ForceCredSSPReset
        }
        catch {
            Write-Warning "Problem with 'Restore-OriginalSystemConfig' function in New-SudoSession.Tests.ps1!"
        }
    }
    
    $global:SudoCredentials = $null
    $global:NewSessionAndOriginalStatus = $null
}

function ItTestSeriesA {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True
        )]
        $InputObject
    )

    it "Should return some kind of output" {
        $InputObject | Assert-NotNull
    }

    it "Should return a PSCustomObject" {
        $InputObject | Assert-Type System.Management.Automation.PSCustomObject
    }

    it "Should return a PSCustomObject with Specific Properties" {
        [array]$ActualPropertiesArray = $($InputObject | Get-Member -MemberType NoteProperty).Name
        [array]$ExpectedPropertiesArray = $global:MockResources['FakeOutputHT'].Keys
        Assert-Equivalent -Actual $ActualPropertiesArray -Expected $ExpectedPropertiesArray
    }

    it "Should return a PSCustomObject Property ElevatedPSSession of Type PSSession" {
        $InputObject.ElevatedPSSession | Assert-Type System.Management.Automation.Runspaces.PSSession
    }

    it "Should return a PSCustomObject Property WSManAndRegistryChanges of Type PSCustomObject" {
        $InputObject.WSManAndRegistryChanges | Assert-Type System.Management.Automation.PSCustomObject
    }

    it "Should return a PSCustomObject Property ConfigChangesFilePath of Type String" {
        $InputObject.ConfigChangesFilePath | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property RevertedChangesFilePath of Type String" {
        $InputObject.RevertedChangesFilePath | Assert-Type System.String
    }

    it "Should output a file referenced by ConfigChangesFilePath" {
        Test-Path $InputObject.ConfigChangesFilePath | Assert-True
    }

    it "Should output a file referenced by RevertedChangesFilePath" {
        Test-Path $InputObject.RevertedChangesFilePath | Assert-True
    }
}

function ItTestSeriesB {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True
        )]
        $InputObject
    )

    it "Should return some kind of output" {
        $InputObject | Assert-NotNull
    }

    it "Should return a PSCustomObject" {
        $InputObject | Assert-Type System.Management.Automation.PSCustomObject
    }

    it "Should return a PSCustomObject with Specific Properties" {
        [array]$ActualPropertiesArray = $($InputObject | Get-Member -MemberType NoteProperty).Name
        [array]$ExpectedPropertiesArray = $global:MockResources['FakeOutputHT'].Keys
        Assert-Equivalent -Actual $ActualPropertiesArray -Expected $ExpectedPropertiesArray
    }

    it "Should return a PSCustomObject Property ElevatedPSSession of Type PSSession" {
        $InputObject.ElevatedPSSession | Assert-Type System.Management.Automation.Runspaces.PSSession
    }

    it "Should return a PSCustomObject Property WSManAndRegistryChanges of Type PSCustomObject" {
        $InputObject.WSManAndRegistryChanges | Assert-Type System.Management.Automation.PSCustomObject
    }

    it "Should return a PSCustomObject Property ConfigChangesFilePath of Type String" {
        $InputObject.ConfigChangesFilePath | Assert-Type System.String
    }

    it "Should return a PSCustomObject Property RevertedChangesFilePath with Null Value" {
        $InputObject.RevertedChangesFilePath | Assert-Null
    }

    it "Should output a file referenced by ConfigChangesFilePath" {
        Test-Path $InputObject.ConfigChangesFilePath | Assert-True
    }
}

$Functions = @(
    ${Function:Cleanup}.Ast.Extent.Text
    ${Function:ItTestSeriesA}.Ast.Extent.Text
    ${Function:ItTestSeriesB}.Ast.Extent.Text
)

$global:MockResources = @{
    Functions                           = $Functions
    UserName                            = $TestResources.UserName
    SimpleUsername                      = $TestResources.SimpleUserName
    Password                            = $TestResources.Password
    Creds                               = $TestResources.Creds
    Domain                              = $Domain
    LocalHostFQDN                       = $LocalHostFQDN
    FakeSystemConfigScriptHT            = $FakeSystemConfigScriptHT
    FakeSystemRevertConfigScriptHT      = $FakeSystemRevertConfigScriptHT
    FakeOutputHT                        = $FakeOutputHT
}

InModuleScope Sudo {
    Describe "Test New-SudoSession" {
        Context "Elevated PowerShell Session" {
            # IMPORTANT NOTE: Any functions that you'd like the 'it' blocks to use should be written in the 'Context' scope HERE!
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }

            Mock 'GetElevation' -MockWith {$True}
            Mock 'GetCurrentUser' -MockWith {"zero\zeroadmin"}

            # NOTE: Tests with just Assert-Throw will pass for both Terminating and Non-Terminating Errors
            # NOTE: Tests with Assert-Throw -AllowNonTerminatingError will only pass if there is NOT a Non-Terminating Error
            # 
            It "Should Throw An Error" {
                # New-SudoSession Common Parameters
                $NSSplat = @{
                    Credentials     = $global:MockResources['Creds']
                    WarningAction   = "SilentlyContinue"
                    OutVariable     = "SudoSessionInfo"
                }

                {New-SudoSession @NSSplat} | Assert-Throw

                # Just in case it does NOT error for some reason, we need to cleanup...
                if ($SudoSessionInfo) {
                    $RMSplat = @{
                        Credentials         = $global:MockResources['Creds']
                        SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                        OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                        ErrorAction         = "SilentlyContinue"
                    }
                    $null = Remove-SudoSession @RMSplat    
                }
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            
            <#
            It "Should Throw A Terminating Error Using '-ErrorAction Stop'" {
                # The below tests for a non-Terminating Error, so this test should fail
                New-SudoSession -ErrorAction Stop | Assert-Throw -AllowNonTerminatingError  
            }
            #>
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session w/ Explicitly Provided Credentials"
        Context $ContextStringBuilder {
            # IMPORTANT NOTE: Any functions that you'd like the 'it' blocks to use should be written in the 'Context' scope HERE!
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}
            Mock 'GetCurrentUser' -MockWith {"zero\zeroadmin"}

            # New-SudoSession Common Parameters
            $NSSplat = @{
                Credentials     = $global:MockResources['Creds']
                WarningAction   = "SilentlyContinue"
                ErrorAction     = "Stop"
            }
            $SudoSessionInfo = $null

            try {
                $SudoSessionInfo = New-SudoSession @NSSplat

                # Cleanup
                # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, wan to be sure it's from New-SudoSession
                $RMSplat = @{
                    Credentials         = $global:MockResources['Creds']
                    SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                    OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                    ErrorAction         = "SilentlyContinue"
                }
                $null = Remove-SudoSession @RMSplat
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            catch {
                # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
                Write-Warning $($_.Exception.Message)
                
                if ($SudoSessionInfo) {
                    Cleanup -SudoSessionInfo $SudoSessionInfo -ErrorAction SilentlyContinue
                }
                else {
                    Restore-OriginalSystemConfig -ForceCredSSPReset -ErrorAction SilentlyContinue
                }
            }

            if ($SudoSessionInfo) {
                $SudoSessionInfo | ItTestSeriesA
            }
            else {
                Write-Warning "Unable to un 'ItTestSeriesA' in Context...`n    '$ContextStringBuilder'`nbecause the 'New-SudoSession' function failed to output an object!"
            }
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session, `$global:SudoCredentials Already Available, " +
        "No UserName Explicitly Provided, Current User Different than `$global:SudoCredentials.UserName"
        Context $ContextStringBuilder {
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}
            Mock 'GetCurrentUser' -MockWith {"zero\zeroadmin"}

            $global:SudoCredentials = $global:MockResources['Creds']

            It "Should Throw An Error" {
                # New-SudoSession Common Parameters
                $NSSplat = @{
                    WarningAction   = "SilentlyContinue"
                    OutVariable     = "SudoSessionInfo"
                }

                {New-SudoSession @NSSplat} | Assert-Throw

                # Just in case it does NOT error for some reason, we need to cleanup...
                if ($SudoSessionInfo) {
                    $RMSplat = @{
                        Credentials     = $global:MockResources['Creds']
                        SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                        OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                        ErrorAction         = "SilentlyContinue"
                    }
                    $null = Remove-SudoSession @RMSplat    
                }
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session, `$global:SudoCredentials Already Available, " +
        "UserName Explicitly Provided, Provided UserName Different than `$global:SudoCredentials.UserName"
        Context $ContextStringBuilder {
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}
            Mock 'GetCurrentUser' -MockWith {"zero\zeroadmin"}

            $global:SudoCredentials = [pscredential]::new("zero\zeroadmin",$(ConvertTo-SecureString "NotReal" -AsPlainText -Force))

            # New-SudoSession Common Parameters
            $NSSplat = @{
                UserName        = $global:MockResources['UserName']
                Password        = $global:MockResources['Password']
                WarningAction   = "SilentlyContinue"
                ErrorAction     = "Stop"
            }
            $SudoSessionInfo = $null

            try {
                $SudoSessionInfo = New-SudoSession @NSSplat

                # Cleanup
                # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, wan to be sure it's from New-SudoSession
                $RMSplat = @{
                    Credentials         = $global:MockResources['Creds']
                    SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                    OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                    ErrorAction         = "SilentlyContinue"
                }
                $null = Remove-SudoSession @RMSplat
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            catch {
                # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
                Write-Warning $($_.Exception.Message)

                if ($SudoSessionInfo) {
                    Cleanup -SudoSessionInfo $SudoSessionInfo -ErrorAction SilentlyContinue
                }
                else {
                    Restore-OriginalSystemConfig -ForceCredSSPReset -ErrorAction SilentlyContinue
                }
            }

            if ($SudoSessionInfo) {
                $SudoSessionInfo | ItTestSeriesA
            }
            else {
                Write-Warning "Unable to un 'ItTestSeriesA' in Context...`n    '$ContextStringBuilder'`nbecause the 'New-SudoSession' function failed to output an object!"
            }
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session, `$global:SudoCredentials Already Available, " +
        "No UserName Explicitly Provided, Current User Same as `$global:SudoCredentials.UserName"
        Context $ContextStringBuilder {
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}
            Mock 'GetCurrentUser' -MockWith {$global:MockResources['UserName']}

            $global:SudoCredentials = $global:MockResources['Creds']

            # New-SudoSession Common Parameters
            $NSSplat = @{
                WarningAction   = "SilentlyContinue"
                ErrorAction     = "Stop"
            }
            $SudoSessionInfo = $null

            try {
                $SudoSessionInfo = New-SudoSession @NSSplat

                # Cleanup
                # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, wan to be sure it's from New-SudoSession
                $RMSplat = @{
                    Credentials         = $global:MockResources['Creds']
                    SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                    OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                    ErrorAction         = "SilentlyContinue"
                }
                $null = Remove-SudoSession @RMSplat
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            catch {
                # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
                Write-Warning $($_.Exception.Message)
                
                if ($SudoSessionInfo) {
                    Cleanup -SudoSessionInfo $SudoSessionInfo -ErrorAction SilentlyContinue
                }
                else {
                    Restore-OriginalSystemConfig -ForceCredSSPReset -ErrorAction SilentlyContinue
                }
            }

            if ($SudoSessionInfo) {
                $SudoSessionInfo | ItTestSeriesA
            }
            else {
                Write-Warning "Unable to un 'ItTestSeriesA' in Context...`n    '$ContextStringBuilder'`nbecause the 'New-SudoSession' function failed to output an object!"
            }
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session, `$global:SudoCredentials Already Available, " +
        "UserName Explicitly Provided, Provided UserName Same as `$global:SudoCredentials.UserName"
        Context $ContextStringBuilder {
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}
            Mock 'GetCurrentUser' -MockWith {$global:MockResources['UserName']}

            $global:SudoCredentials = $global:MockResources['Creds']

            # New-SudoSession Common Parameters
            $NSSplat = @{
                UserName        = $global:MockResources['UserName']
                Password        = $global:MockResources['Password']
                WarningAction   = "SilentlyContinue"
                ErrorAction     = "Stop"
            }
            $SudoSessionInfo = $null

            try {
                $SudoSessionInfo = New-SudoSession @NSSplat

                # Cleanup
                # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, wan to be sure it's from New-SudoSession
                $RMSplat = @{
                    Credentials         = $global:MockResources['Creds']
                    SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                    OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                    ErrorAction         = "SilentlyContinue"
                }
                $null = Remove-SudoSession @RMSplat
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            catch {
                # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
                Write-Warning $($_.Exception.Message)
                
                if ($SudoSessionInfo) {
                    Cleanup -SudoSessionInfo $SudoSessionInfo -ErrorAction SilentlyContinue
                }
                else {
                    Restore-OriginalSystemConfig -ForceCredSSPReset -ErrorAction SilentlyContinue
                }
            }

            if ($SudoSessionInfo) {
                $SudoSessionInfo | ItTestSeriesA
            }
            else {
                Write-Warning "Unable to un 'ItTestSeriesA' in Context...`n    '$ContextStringBuilder'`nbecause the 'New-SudoSession' function failed to output an object!"
            }
        }

        $ContextStringBuilder = "Non-Elevated PowerShell Session w/ Explicitly Provided Credentials and KeepOpen Switch"
        Context $ContextStringBuilder  {
            # IMPORTANT NOTE: Any functions that you'd like the 'it' blocks to use should be written in the 'Context' scope HERE!
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
            
            Mock 'GetElevation' -MockWith {$False}

            # New-SudoSession Common Parameters
            $NSSplat = @{
                Credentials     = $global:MockResources['Creds']
                WarningAction   = "SilentlyContinue"
                KeepOpen        = $True
            }
            $SudoSessionInfo = $null

            try {
                $SudoSessionInfo = New-SudoSession @NSSplat

                # Cleanup
                # NOTE: Using -EA SilentlyContinue for Remove-SudoSession because if we error, wan to be sure it's from New-SudoSession
                $RMSplat = @{
                    Credentials         = $global:MockResources['Creds']
                    SessionToRemove     = $SudoSessionInfo.ElevatedPSSession
                    OriginalConfigInfo  = $SudoSessionInfo.WSManAndRegistryChanges
                    ErrorAction         = "SilentlyContinue"
                }
                $null = Remove-SudoSession @RMSplat
                $global:SudoCredentials = $null
                $global:NewSessionAndOriginalStatus = $null
            }
            catch {
                # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
                Write-Warning $($_.Exception.Message)
                
                if ($SudoSessionInfo) {
                    Cleanup -SudoSessionInfo $SudoSessionInfo -ErrorAction SilentlyContinue
                }
                else {
                    Restore-OriginalSystemConfig -ForceCredSSPReset -ErrorAction SilentlyContinue
                }
            }

            if ($SudoSessionInfo) {
                $SudoSessionInfo | ItTestSeriesB
            }
            else {
                Write-Warning "Unable to un 'ItTestSeriesB' in Context...`n    '$ContextStringBuilder'`nbecause the 'New-SudoSession' function failed to output an object!"
            }
        }
    }
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyrH9Wx1WPqbbNOnr8QSnst+G
# beygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGZ4EP9R4Guem6mo
# Cs4pLbA20qE+MA0GCSqGSIb3DQEBAQUABIIBAKR4dUhjNuIjemET9+DssGifcghf
# W1YhivYHBPnhU2XhvrfSs5aTxmbZj9WaRBV0r3bORI4mAlzMIsjvI/57zf6SuzaD
# PqdiDiyPij0hiJPNulOFwz8w++JXEuH0h/M5XmEOLv0UFrpYjwwrNupXQalhsv0h
# uuOv3jN9UFbYZagQwhyuXszg/fAMFPtbY9Z6ymTio/ZEDt0d8Ag/kdL4YOAsEqHn
# ORves2lWnvMm8JR7F6SVt0MX6g81KlssG6/fS6kt5bqiyOe2byaxuxFMrls37Kl+
# U5TpUDJbkV2CE8r9LWctvQZi1lf6ZUYQXXU/VgTxj4dpQSnce9UrD+WwlW4=
# SIG # End signature block
