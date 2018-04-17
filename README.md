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
    Import-Module Sudo    #Alternatively, Import-Module \\Path\To\PSNeo4j

# Get commands in the module
    Get-Command -Module Sudo

# Get help
    Get-Help New-SudoSession -Full
    Get-Help about_Sudo
```

## Examples

### Scenario 1: Create a New PSSession with Sudo Privileges, and enter the session

```powershell
PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSession -UserName -Credentials $TestAdminCreds
PS C:\Users\zeroadmin> Enter-PSSession -Session $MyElevatedSession.ElevatedPSSession
[localhost]: PS C:\Users\testadmin\Documents> whoami
zero\testadmin
```

### Scenario 2: Create a New PSSession with Sudo Privileges and run one-off commands in that session

```powershell
PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSession -Credentials $ZeroAdminCreds
PS C:\Users\zeroadmin> Invoke-Command -Session $MyElevatedSession.ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}
...
# When you're finished running commands against this Sudo Session, remove it via:
PS C:\Users\zeroadmin> Remove-SudoSession -Credentials $ZeroAdminCreds -OriginalConfigInfo $MyElevatedSesion.OriginalWSManAndRegistryStatus -SessionToRemove $MyElevatedSession.ElevatedPSSession

```

### Scenario 3: Create a New PSSession with Sudo Privileges, Run a Single Expression, and Destroy the Sudo Session All in One Go

```powershell
PS C:\Users\zeroadmin> $ModuleToInstall = "PackageManagement"
PS C:\Users\zeroadmin> $LatestVersion = $(Find-Module PackageManagement).Version
# PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
PS C:\Users\zeroadmin> $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'
PS C:\Users\zeroadmin> Start-SudoSession -Credentials $ZeroAdminCreds -Expression $InstallModuleExpression
```
