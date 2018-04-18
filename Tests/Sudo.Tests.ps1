$PSVersion = $PSVersionTable.PSVersion.Major
$ModuleName = $ENV:BHProjectName
$ProjectRoot = $env:BHProjectPath
$ModuleRoot = $(Get-ChildItem -Path $ProjectRoot -Recurse -File -Include "*.psm1").Directory.FullName

# Verbose output for non-master builds on appveyor
# Handy for troubleshooting.
# Splat @Verbose against commands as needed (here or in pester tests)
$Verbose = @{}
if($ENV:BHBranchName -notlike "master" -or $env:BHCommitMessage -match "!verbose") {
    $Verbose.add("Verbose",$True)
}

Describe -Name "General Project Validation: $ModuleName" -Tag 'Validation' -Fixture {
    $Scripts = Get-ChildItem $ProjectRoot -Include *.ps1,*.psm1,*.psd1 -Recurse

    # TestCases are splatted to the script so we need hashtables
    $TestCasesHashTable = $Scripts | foreach {@{file=$_}}         
    It "Script <file> should be valid powershell" -TestCases $TestCasesHashTable {
        param($file)

        $file.fullname | Should -Exist

        $contents = Get-Content -Path $file.fullname -ErrorAction Stop
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    #It "Module '$ModuleName' Should Load" -Test {
    #    {Import-Module $(Join-Path $ModuleRoot "$ModuleName.psm1") -Force} | Should Not Throw
    #}
}


Describe -Name "$ModuleName Loads in PS$PSVersion" -Tag 'LoadCheck' -Fixture {
    It 'Should Load' {
        $Module = Get-Module $ModuleName
        $Module.Name -contains $ModuleName | Should -Be $True
        $Commands = $Module.ExportedCommands.Keys
        $Commands -contains 'New-SudoSession' | Should -Be $True
        $Commands -contains 'Start-SudoSession' | Should -Be $True
        $Commands -contains 'Remove-SudoSession' | Should -Be $True
    }
}

Describe -Name 'Test New-SudoSession function' -Tag 'New-SudoSession' -Fixture {
    Function Invoke-VMScript {}
    Mock -ModuleName 'VMwareTemplatePatching' -CommandName Invoke-VMScript -MockWith {
        [pscustomobject]@{
            ExitCode = 0
        }
    }
    
    $secpasswd = ConvertTo-SecureString "password" -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("username", $secpasswd)

    Context "Test Test-InvokeVMScript outputs" {
        it "Evaluates Invoke-VMScript results exit code" {
            Test-InvokeVMScript -System 'MyTestSystem' -Credential $mycreds | should be $true
        }
    }
}