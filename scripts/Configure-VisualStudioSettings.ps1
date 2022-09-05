
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="test")]
    [Alias("t")]
    [switch]$Test
)

. "$PSScriptRoot\ps\log.ps1"

$RootPath = (Resolve-Path "$PSScriptRoot\..").Path
$InitBat = Join-Path $RootPath "cfg\init.bat"

function Get-DevCommonToolsPath{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $expectedLocations=@("${ENV:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\Tools", "$ENV:ProgramFiles\Microsoft Visual Studio\2019\Community\Common7\Tools")
    $ffFiles=$expectedLocations|%{Join-Path $_ 'VsDevCmd.bat'}
    [String[]]$vPath=@($expectedLocations|?{test-path $_})
    $vPathCount = $vPath.Count
    if($vPathCount){
        return $vPath[0]
    }
    else{
        return $Null
    }
}

function Invoke-ConfigureProfileInitScript{
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $ProfileInitBat = "$Home\Scripts\init.bat" 
    Write-Host "Setting up $ProfileInitBat...  " -f Gray -n
    $res = (Copy-Item -Path $InitBat -Destination $ProfileInitBat -Passthru -ErrorAction Ignore)
    if("$($res.FullName)" -eq "$ProfileInitBat"){       
         Write-Host "SUCCESS" -f DarkGreen
    }else{
        Write-Host "FAILURE" -f DarkRed
    }
}


function Test-VsSettings{
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $CommonLogs = "$ENV:Temp\commonlogs.log" 
    $ProfileInitBat = "$Home\Scripts\init.bat" 
    $BatchScript = @"
@echo off

:init
    setlocal
    pushd `"$Home`"

:main
    cls
    call `"$ProfileInitBat`"
    call :pssleep 2500
    goto :terminate


:pssleep
    powershell -nop -c "& {sleep -m %1}"
    goto :eof


:terminate
    popd
    endlocal
    goto :eof

"@

    $BatFileName = "$PSScriptRoot\RunTest.bat"
    Set-Content -Path "$BatFileName" -Value $BatchScript | Out-Null
    &"$BatFileName"

    $LAST_ERRORLEVEL = (Get-Content "$ENV:COMMON_LOG_FILE")
    $LAST_ERRORLEVEL = $LAST_ERRORLEVEL.Trim()
    Write-Host "Configuration Result: " -f Gray -n
    if("$LAST_ERRORLEVEL" -eq "0"){
        Write-Host "SUCCESS" -f DarkGreen
    }else{
        Write-Host "FAILURE ($LAST_ERRORLEVEL)" -f DarkRed
    }

    if($PSBoundParameters.ContainsKey('Verbose')){
         Write-Host "$($Res.Output)"
    }   
}


Invoke-ConfigureProfileInitScript

$DevCommonToolsPath = Get-DevCommonToolsPath
$CommonLogs         = "$ENV:Temp\commonlogs.log" 
$SettingName        = "COMMON_LOG_FILE"
$MsBuildExe         = Get-MsBuildExe
$MsBuildRoot        = (Get-Item $MsBuildExe | Select DirectoryName).DirectoryName
$Null = setx "VS140COMNTOOLS" "$DevCommonToolsPath" 
$Null = setx "COMMON_LOG_FILE" "$CommonLogs"
$Null = setx 'MsBuildExe' "$MsBuildExe"
$Null = setx 'MsBuildRoot' "$MsBuildRoot"
$CurrentUserPath = [System.Environment]::GetEnvironmentVariable("PATH",[System.EnvironmentVariableTarget]::User)
$UpdatedUserPath = $CurrentUserPath
if($CurrentUserPath.IndexOf($DevCommonToolsPath) -eq -1){
     Write-Host 'Updating USER::PATH value' -n ; Write-Host "Adding `$DevCommonToolsPath -> $DevCommonToolsPath"
    $UpdatedUserPath = "$UpdatedUserPath;$DevCommonToolsPath"
}
if($CurrentUserPath.IndexOf($MsBuildRoot) -eq -1){
    Write-Host 'Updating USER::PATH value' -n ; Write-Host "Adding `$MsBuildRoot -> $MsBuildRoot"
    $UpdatedUserPath = "$UpdatedUserPath;$MsBuildRoot"
}

$Null=[System.Environment]::SetEnvironmentVariable("PATH",$UpdatedUserPath,[System.EnvironmentVariableTarget]::User)
if($Test){
    Test-VsSettings
}