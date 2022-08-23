
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>



function Get-SshClientInstalled{
    [CmdletBinding(SupportsShouldProcess)]
    Param()
    $State = Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Client*'
    if($Null -ne $State){
        $State = $State.State
        Write-Verbose "OpenSSH.Client State is $State"
        if($State -match 'installed'){
            return $True
        }
    }
    return $False
}

function Get-SshServerInstalled{
    [CmdletBinding(SupportsShouldProcess)]
    Param()
    $State = Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*'
    if($Null -ne $State){
        $State = $State.State
        Write-Verbose "OpenSSH.Server State is $State"
        if($State -match 'installed'){
            return $True
        }
    }
    return $False
}