
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

[CmdletBinding(SupportsShouldProcess)]
param ()


. "$PSScriptRoot\ps\log.ps1"

$RootPath = (Resolve-Path "$PSScriptRoot\..").Path
$NewSettingsFile = "$RootPath\cfg\settings.json"
$TermSettings = "C:\Users\Client\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
$InitBatch = "$RootPath\cfg\init.bat"

$Exists1 = Test-Path $TermSettings
$Exists2 = Test-Path $NewSettingsFile

if(!$Exists1 -Or !$Exists2){ Write-Host "Missing file" -f Red ; return}
Write-Host "Windows Terminal Settings File ($Exists1):" -f DarkCyan -n ; Write-Host "`"$TermSettings`"" -f DarkGray
Write-Host "New Settings File ($Exists2):" -f DarkCyan -n ; Write-Host "`"$NewSettingsFile`"" -f DarkGray
$a = Read-Host "Update Settings File ?(y/n)"
if($a -eq 'y'){
    Get-Content $NewSettingsFile | Set-Content $TermSettings
    Write-Host "Done" -f Green ;
}else{ 
    Write-Host "Canceled" -f Red 
}
$a = Read-Host "Update init.bat ?(y/n)"
if($a -eq 'y'){
    New-Item -Path "~\scripts" -Force -ItemType Directory -ErrorAction Ignore | Out-Null
    Get-Content $InitBatch | Set-Content "~\scripts\init.bat"
    Write-Host "Done" -f Green ;
}else{ 
    Write-Host "Canceled" -f Red 
}
