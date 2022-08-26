
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

[CmdletBinding(SupportsShouldProcess)]
param ()

#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host " Launching in Admin mode" -f DarkRed
    Start-Process pwsh.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

$stopwatch = [System.Diagnostics.Stopwatch]::new()
$stopwatch.Start()

. "$PSScriptRoot\ps\log.ps1"
. "$PSScriptRoot\ps\windowsconfig.ps1"
$ms = $stopwatch.Elapsed.Milliseconds  
$stopwatch.Reset();$stopwatch.Start()
 Write-Host "✅ $PSScriptRoot\ps\windowsconfig.ps1 in $ms ms"
<#
Get-RemoteDesktopStatus
read-host 'ok'
Disable-Defender
Disable-RealTimeProtection
Disable-ExploitGuard
Disable-SecurityFeatures
Disable-SmartScreen
Disable-Telemetry
Disable-Cortana
Disable-WebSearch
Disable-AppSuggestions
Disable-ActivityHistory
Disable-Location 
Disable-MapUpdates
Disable-Feedback
Disable-AdvertisingID
Disable-TailoredExperiences 
Disable-ErrorReporting
Disable-DiagTrack
Disable-DownloadBlocking
Disable-RemoteAssistance
Disable-RemoteDesktop
read-host 'ok'#>
Uninstall-ThirdPartyBloat
Uninstall-MsftBloat
Disable-EdgePreload