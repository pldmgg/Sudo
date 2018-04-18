[![Build status](https://ci.appveyor.com/api/projects/status/0w4exgcant21qx6h/branch/master?svg=true)](https://ci.appveyor.com/project/pldmgg/sudo/branch/master)

# Sudo
Create an Elevated PowerShell Session as any user that you have credentials for

IMPORTANT:

* Functions in this Module will NOT run in a PowerShell Session that was already launched using 'Run As Administrator'

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the PSNeo4j folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module Sudo

# Import the module.
    Import-Module Sudo    #Alternatively, Import-Module \\Path\To\Sudo

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
# When you're finished running commands against this Sudo Session, remove it via:
PS C:\Users\zeroadmin> Remove-SudoSession -Credentials $ZeroAdminCreds -OriginalConfigInfo $MyElevatedSesion.OriginalWSManAndRegistryStatus -SessionToRemove $MyElevatedSession.ElevatedPSSession

```

### Scenario 4: Create a New PSSession with Sudo Privileges, Run a Single Expression, and Destroy the Sudo Session All in One Go

```powershell
PS C:\Users\zeroadmin> $ModuleToInstall = "PackageManagement"
PS C:\Users\zeroadmin> $LatestVersion = $(Find-Module PackageManagement).Version
# PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
PS C:\Users\zeroadmin> $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'
PS C:\Users\zeroadmin> Start-SudoSession -Credentials $ZeroAdminCreds -Expression $InstallModuleExpression
```

## Notes

* Available via PSGallery