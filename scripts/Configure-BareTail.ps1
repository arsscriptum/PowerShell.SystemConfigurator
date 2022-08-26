
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Force")]
        [Alias("f")]
        [switch]$Force
    )


. "$PSScriptRoot\ps\log.ps1"

$RootPath = (Resolve-Path "$PSScriptRoot\..").Path

function Get-BareTailHash{

    [CmdletBinding(SupportsShouldProcess)]
    param()
    return "49948E345439BADE86BB6FA9E0724635EB6EE8C2"
}

function Get-BareGrepHash{

    [CmdletBinding(SupportsShouldProcess)]
    param()
    return "EC1D593E0D9033D646D80AA76EA7D0779A0A8E40"
}
function Invoke-ClearBareTail{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $BarePath = "$ENV:ToolsRoot\Bare"
    $BareTailExe = Join-Path $BarePath "baretail.exe"
    $BareGrepExe = Join-Path $BarePath "baregrep.exe"
    Write-Log "Clearing $BarePath..."
    Remove-Item $BarePath -Recurse -Force -ErrorAction Ignore | Out-Null
}

function Install-BareTail{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $BarePath = "$ENV:ToolsRoot\Bare"
    $BareTailExe = Join-Path $BarePath "baretail.exe"
    $BareGrepExe = Join-Path $BarePath "baregrep.exe"
    Write-Log "Clearing $BarePath..."
    Remove-Item $BarePath -Recurse -Force -ErrorAction Ignore | Out-Null
    New-Item $BarePath -ItemType Directory -Force -ErrorAction Ignore | Out-Null
    Write-Log "Setting Environment Variables"
    Set-EnvironmentVariable -Name "BareTail" -Value "$BareTailExe" -Scope Session
    Set-EnvironmentVariable -Name "BareTail" -Value "$BareTailExe" -Scope User
    Set-EnvironmentVariable -Name "BareGrep" -Value "$BareGrepExe" -Scope Session
    Set-EnvironmentVariable -Name "BareGrep" -Value "$BareGrepExe" -Scope User
    $BareTailExe = "$ENV:BareTail"
    $u = "http://baremetalsoft.com/baretailpro/download.php?p=a"
    Write-Log "Installing BareTail..."
    Invoke-WebRequest -Uri $u -OutFile $BareTailExe
    $u = "http://baremetalsoft.com/baregrep/download.php?p=m"
    Write-Log "Installing BareGrep..."
    Invoke-WebRequest -Uri $u -OutFile $BareGrepExe
    $h1 = (Get-FileHash "$ENV:BareTail" -Algorithm SHA1).Hash
    $h2 = (Get-FileHash "$ENV:BareGrep" -Algorithm SHA1).Hash

    Write-Host "Checking BareTail..." -n
    if($h1 -eq $(Get-BareTailHash)){
        Write-Host "OK ($h1)" -f DarkGreen
    }else{
        Write-Host "NOT OK" -f DarkRed
    }

    Write-Host "Checking BareGrep..." -n
    if($h2 -eq $(Get-BareGrepHash)){
        Write-Host "OK ($h2)" -f DarkGreen
    }else{
        Write-Host "NOT OK" -f DarkRed
    }

}


function Get-BareTailPath{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $expectedLocations=@("$ENV:BareTail", "$ENV:ToolsRoot\Bare\baretail.exe")
    [String[]]$vPath=@($expectedLocations|?{test-path $_})
    $vPathCount = $vPath.Count
    if($vPathCount){
        return $vPath[0]
    }
    else{
        return $Null
    }
}


if($Force){
    Write-Host "Force: Clearing path..." -f DarkRed
    Invoke-ClearBareTail
}
Write-Host "Checking BareTail Install..." -n
$p = Get-BareTailPath
if($p -eq $Null){    
    Write-Host " NOT INSTALLED.... Installing." -f DarkRed
    Install-BareTail
}else{
    Write-Host "OK" -f DarkGreen
    $h1 = (Get-FileHash "$ENV:BareTail" -Algorithm SHA1).Hash
    $h2 = (Get-FileHash "$ENV:BareGrep" -Algorithm SHA1).Hash
    Write-Host "BareTail $ENV:BareTail [$h1]" -f DarkCyan
    Write-Host "BareGrep $ENV:BareGrep [$h2]" -f DarkCyan
}
    
