[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/sudo?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/sudo/branch/master)


# Sudo
Sudo for PowerShell! From a non-privileged PowerShell Session, run one-off commands, scriptblocks, or enter an interactive PSSession with 'Run As Administrator' privileges! If you have credentials for a different user account, you can switch to that user as well.

IMPORTANT NOTE: Functions in this Module will NOT run in a PowerShell Session that was already launched using 'Run As Administrator' (with the exception of the `Restore-OriginalSystemConfig` function)

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the Sudo folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module Sudo

# Import the module.
    Import-Module Sudo    # Alternatively, Import-Module <PathToSudoFolder>

# Get commands in the module
    Get-Command -Module Sudo

# Get help
    Get-Help New-SudoSession -Full
    Get-Help about_Sudo
```

## Examples

### Scenario 1: Using the Start-SudoSession function (alias 'sudo') to run a ScriptBlock with Elevated Privileges

```powershell
PS C:\Users\zeroadmin> sudo {Install-Package Nuget.CommandLine -Source chocolatey}
Please enter the password for zeroadmin: ***************

PSComputerName       : localhost
RunspaceId           : 0fdf310f-dcb3-4ba1-893e-d502c56ed6c0
FastPackageReference : $aHR0cDovL2Nob2NvbGF0ZXkub3JnL2FwaS92Mi8=\TnVHZXQuQ29tbWFuZExpbmU=\NC42LjI=\Y2hvY29sYXRleQ==
ProviderName         : Chocolatey
Source               : chocolatey
Status               : Installed
SearchKey            : chocolatey
FullPath             :
PackageFilename      : NuGet.CommandLine.4.6.2.nupkg
FromTrustedSource    : True
Summary              : NuGet is the package manager for the Microsoft development platforms
...[Truncated]...
```

### Scenario 2: Create a New PSSession with Sudo Privileges, and enter the session

```powershell
PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSession -UserName -Credentials $TestAdminCreds
PS C:\Users\zeroadmin> Enter-PSSession -Session $MyElevatedSession.ElevatedPSSession
[localhost]: PS C:\Users\testadmin\Documents> whoami
zero\testadmin
```

### Scenario 3: Create a New PSSession with Sudo Privileges and run one-off commands in that session

```powershell
PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSession -Credentials $ZeroAdminCreds
PS C:\Users\zeroadmin> Invoke-Command -Session $MyElevatedSession.ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}
...
# When you are finished running commands against this Sudo Session, remove it via:
PS C:\Users\zeroadmin> Remove-SudoSession -OriginalConfigInfo $MyElevatedSesion.WSManAndRegistryChanges -SessionToRemove $MyElevatedSession.ElevatedPSSession

```

### Scenario 4: You use the New-SudoSession function with the -KeepOpen switch. The PowerShell process that owns the new SudoSession is unexpectedly closed/killed before you get a chance to run the Remove-SudoSession.

Revert your WSMAN and CredSSP settings to what they was prior to using the `New-SudoSession` function by opening a new PowerShell Session (does not matter if it is elevated or not) and:

```powershell
PS C:\Users\zeroadmin> Import-Module Sudo
PS C:\Users\zeroadmin> $CurrentUser = $($(whoami) -split "\\")[-1]
PS C:\Users\zeroadmin> $SudoSessionFolder = "$HOME\SudoSession_$CurrentUser_$(Get-Date -Format MMddyyy)"
PS C:\Users\zeroadmin> $SudoSessionChangesLogFilePath = $(Get-ChildItem -Path $SudoSessionFolder -File -Filter "SudoSession_Config_Changes*.xml" | Sort-Object -Property CreationTime)[-1].FullName
PS C:\Users\zeroadmin> Restore-OriginalSystemConfig -SudoSessionChangesLogFilePath $SudoSessionChangesLogFilePath

```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/Sudo