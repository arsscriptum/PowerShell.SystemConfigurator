
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

[CmdletBinding(SupportsShouldProcess)]
param ()


. "$PSScriptRoot\ps\log.ps1"

$RootPath = (Resolve-Path "$PSScriptRoot\..").Path

function Test-ModuleInstall{

    [CmdletBinding(SupportsShouldProcess)]
    param()
    $TestModules = @('Carbon',  'RunAsUser', 'Invoke-CommandAs', '7Zip4Powershell', 'PSScriptAnalyzer', 'InvokeBuild', 'WifiTools', 'WinSCP', 'Get-NetView')
    $MsGraphModules = @('Microsoft.Graph', 'Microsoft.Graph.Financials', 'Microsoft.Graph.DirectoryObjects', 'Microsoft.Graph.PersonalContacts', 
    'Microsoft.Graph.Search', 'Microsoft.Graph.People', 'Microsoft.Graph.Sites', 'Microsoft.Graph.Files', 'Microsoft.Graph.Security')
}

function Test-ModuleInstall{

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("m")]
        [string]$Module
    )

    Write-Host "`n`n===============================================================================" -f DarkRed
    Write-Host "VALIDATING MODULE $Module" -f DarkYellow;
    Write-Host "===============================================================================" -f DarkRed

    Import-Module -Name "$Module" -ErrorAction Ignore | Out-Null
    $ModPtr = Get-Module -Name "$Module" -ErrorAction Ignore
    if($ModPtr -eq $null){

        $a = Read-Host 'Do you want to install the required module? (y/n)'
        if($a -ne 'y'){
            Write-Host -n -f DarkRed "[EXITING]"
            return
        }
        $installationPath = Get-UserModulesPath
        Write-Host "⚡ Install $Module to $installationPath"
        Install-ModuleToDirectory -Name "$Module" -Path "$installationPath" -Import -Force   
        $ModPtr = Get-Module -Name $Module -ErrorAction Ignore
        if($ModPtr -eq $null){
            Write-Host "❗❗❗ Installation Error" -f DarkYellow
            return
        }
    }
}


