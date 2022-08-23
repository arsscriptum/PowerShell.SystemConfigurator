
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

[CmdletBinding(SupportsShouldProcess)]
Param()

#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host " Launching in Admin mode" -f DarkRed
    Start-Process pwsh.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

. "$PSScriptRoot\ps\log.ps1"
. "$PSScriptRoot\ps\ssh.ps1"

$ServerInstalled = Get-SshServerInstalled
$ClientInstalled = Get-SshClientInstalled

Write-Log "SSH Server Installed => $ServerInstalled"
Write-Log "SSH Client Installed => $ClientInstalled"

if($False -eq $ClientInstalled){
    Write-Log "Install the OpenSSH Client"
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}

if($False -eq $ServerInstalled){
    Write-Log "Install the OpenSSH Server"
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    Write-Log "Add New sshd service"
    Set-Service -Name sshd -StartupType 'Automatic'

    Write-Log "Start the sshd service"
    Start-Service sshd
}




Write-Log "Confirm the firewall rule is configured for server..."
Write-Log "Get-NetFirewallRule -Name sshd"
$ServerRule = Get-NetFirewallRule -Name sshd
if($Null -eq $ServerRule){
    Write-Log "Create NewFirewall Rule..."
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    $ServerRule = Get-NetFirewallRule -Name sshd
}

Write-Log "Rule `"$($ServerRule.DisplayName)`"[$($ServerRule.Name)] Direction $($ServerRule.Direction) Action $($ServerRule.Action)"

Write-Log "Confirm the firewall rule is configured for client..."
Write-Log "Get-NetFirewallRule -Name sshclient"
$ClientRule = Get-NetFirewallRule -Name sshclient
if($Null -eq $ClientRule){
    Write-Log "Create NewFirewall Rule..."
    New-NetFirewallRule -Name sshclient -DisplayName 'OpenSSH Client (sshclient)' -Enabled True -Direction Outbound -Protocol TCP -Action Allow -LocalPort 22
    $ClientRule = Get-NetFirewallRule -Name sshclient
}

Write-Log "Rule `"$($ClientRule.DisplayName)`"[$($ClientRule.Name)] Direction $($ClientRule.Direction) Action $($ClientRule.Action)"

