
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
function Get-DevEnvPath{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $expectedLocations=@("${ENV:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE", "$ENV:ProgramFiles\Microsoft Visual Studio\2019\Community\Common7\IDE")
    $ffFiles=$expectedLocations|%{Join-Path $_ 'devenv.exe'}
    [String[]]$vPath=@($expectedLocations|?{test-path $_})
    $vPathCount = $vPath.Count
    if($vPathCount){
        return $vPath[0]
    }
    else{
        return $Null
    }
}
function Push-DevEnvPath{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("e")]
        [switch]$Explorer
    )
    $p = Get-DevEnvPath
    pushd $p

    if($Explorer){
        $e = (Get-Command 'explorer.exe').Source
        &"$e" "$p"   
    }
}

function Get-DevEnvExe{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $expectedLocations=@("${ENV:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE", "$ENV:ProgramFiles\Microsoft Visual Studio\2019\Community\Common7\IDE")
    $ffFiles=$expectedLocations|%{Join-Path $_ 'devenv.exe'}
    [String[]]$validFiles=@($ffFiles|?{test-path $_})
    $validFilesCount = $validFiles.Count
    if($validFilesCount){
        return $validFiles[0]
    }
    else{
        return $Null
    }
}


function Invoke-DevEnv{

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("e")]
        [switch]$SafeMode
    )

    $DevEnvExe=Get-DevEnvExe
   
    if($SafeMode){
        Write-Log "Launching DevEnv in SAFEMODE"
        & "$DevEnvExe" "/NoSplash" "/SafeMode"
    }else{
        Write-Log "Launching DevEnv"
        & "$DevEnvExe" "/NoSplash"
    }
    
}



function Get-MsBuildExe{

    [CmdletBinding(SupportsShouldProcess)]
    param()

    $expectedLocations=@("${ENV:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin", "$ENV:ProgramFiles\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin")
    $ffFiles=$expectedLocations|%{Join-Path $_ 'msbuild.exe'}
    [String[]]$validFiles=@($ffFiles|?{test-path $_})
    $validFilesCount = $validFiles.Count
    if($validFilesCount){
        return $validFiles[0]
    }
    else{
        return $Null
    }
}


function Invoke-MsBuild{

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Arguments")]
        [Alias("a")]
        [string[]]$Arguments,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("e")]
        [switch]$Help
    )
    $MsBuildExe=Get-MsBuildExe
    if($Help){
        &"$MsBuildExe" "-h"
        Write-Log "Invoke-MsBuild -a @('MyApp.sln' ,'-t:Rebuild' ,'-p:Configuration=Release')"
        return
    }
    

    $ArgumentList = @('-noLogo')

    foreach($a in $Arguments){
        $ArgumentList += "$a"
    }    

    Start-Process -FilePath $MsBuildExe -ArgumentList $ArgumentList -NoNewWindow -Wait  
}

function Invoke-BuildProject{

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Arguments")]
        [Alias("p")]
        [string]$Project,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("c")]
        [string]$Configuration="Release",
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("t")]
        [string]$Type="Rebuild"
    )
     $MsBuildExe=Get-MsBuildExe
     &"$MsBuildExe" "-nologo" "$Project" "-t:$Type" "-p:Configuration=$Configuration"
}

function Invoke-DebugExe{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="ExecutableFile")]
        [Alias("e")]
        [string]$ExecutableFile
    )

    $DevEnvExe=Get-DevEnvExe
   
    & "$DevEnvExe" "/DebugExe" "$ExecutableFile"
}


function Invoke-RunBatchFile{

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Arguments")]
        [Alias("p")]
        [string]$Path,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="exp")]
        [Alias("a")]
        [switch]$Admin
    )
    $FNameOut = New-RandomFilename -Extension 'log' -CreateDirectory -CreateFile
    $ArgsList = @("/c")
    $ArgsList += "`"$Path > $FNameOut`""


    $ExePath = "$ENV:comspec"
    $WorkingDirectory=(Get-Location).Path
    
    if($Admin){
        $cmd = Start-Process -FilePath "$ExePath" -ArgumentList $ArgsList -Passthru -Wait -Verb RunAs  
    }else{
        $cmd = Start-Process -FilePath "$ExePath" -ArgumentList $ArgsList -Wait -Passthru
    }
    
    $cmdExitCode = $cmd.ExitCode
    $cmdId = $cmd.Id 
    $cmdHasExited=$cmd.HasExited 
    $cmdTotalProcessorTime=$cmd.TotalProcessorTime 

    $stdOut = Get-Content -Path $FNameOut -Raw
   
    if ([string]::IsNullOrEmpty($stdOut) -eq $false) {
        $stdOut = $stdOut.Trim()
    }
  
    $res = [PSCustomObject]@{
        HasExited          = $cmdHasExited
        TotalProcessorTime = $cmdTotalProcessorTime
        Id                 = $cmdId
        ExitCode           = $cmdExitCod
        Output             = $stdOut
        Error              = $stdErr
        ElapsedSeconds     = $stopwatch.Elapsed.Seconds
        ElapsedMs          = $stopwatch.Elapsed.Milliseconds
    }
    return $res   
}

function Invoke-ConfigureVsSetting{
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $DevCommonToolsPath = "c:\Temp" 
    $DevCommonToolsPath = Get-DevCommonToolsPath

    $BatFile = "$ENV:Temp\temporary.bat" 
    $SettingName = "VS140COMNTOOLS"
    
    New-Item -Path $BatFile -ItemType File -Force -ErrorAction Ignore | Out-Null
    Set-Content $BatFile -Value "@ECHO OFF"
    Add-Content $BatFile -Value "setx $SettingName `"$DevCommonToolsPath`" > NUL"
    Add-Content $BatFile -Value "setx $SettingName `"$DevCommonToolsPath`" /m  > NUL"
    $Res = Invoke-RunBatchFile $BatFile -a
    Write-Host "$($Res.Output)"   
    $Null = Set-EnvironmentVariable -Name "VS140COMNTOOLS" -Value "$DevCommonToolsPath" -Scope Session
    $Null = Set-EnvironmentVariable -Name "VS140COMNTOOLS" -Value "$DevCommonToolsPath" -Scope User

    Write-Host "Setting VS140COMNTOOLS to " -f Gray -n
    Write-Host "`"$DevCommonToolsPath`" : " -f Gray -n

    if("$DevCommonToolsPath" -eq "$ENV:VS140COMNTOOLS"){
        Write-Host "SUCCESS" -f DarkGreen
    }else{
        Write-Host "FAILURE [$ENV:VS140COMNTOOLS]" -f DarkRed
    }

    remove-item $BatFile -Force -ErrorAction Ignore | Out-Null
}


function Invoke-ConfigureCommonLogFile{
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $CommonLogs = "$ENV:Temp\commonlogs.log" 

    $BatFile = "$ENV:Temp\temporary.bat" 
    $SettingName = "COMMON_LOG_FILE"
    
    New-Item -Path $BatFile -ItemType File -Force -ErrorAction Ignore | Out-Null
    Set-Content $BatFile -Value "@ECHO OFF"
    Add-Content $BatFile -Value "setx $SettingName `"$CommonLogs`" > NUL"
    Add-Content $BatFile -Value "setx $SettingName `"$CommonLogs`" /m  > NUL"
    $Res = Invoke-RunBatchFile $BatFile -a
    Write-Host "$($Res.Output)"   
    $Null = Set-EnvironmentVariable -Name "$SettingName" -Value "$CommonLogs" -Scope Session
    $Null = Set-EnvironmentVariable -Name "$SettingName" -Value "$CommonLogs" -Scope User

    Write-Host "Setting $SettingName to " -f Gray -n
    Write-Host "`"$CommonLogs`" : " -f Gray -n

    if("$CommonLogs" -eq "$ENV:COMMON_LOG_FILE"){
        Write-Host "SUCCESS" -f DarkGreen
    }else{
        Write-Host "FAILURE [$ENV:COMMON_LOG_FILE]" -f DarkRed
    }
    remove-item $BatFile -Force -ErrorAction Ignore | Out-Null
}

if(-not $ENV:COMMON_LOG_FILE){
    Invoke-ConfigureCommonLogFile
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
     $Res = Invoke-RunBatchFile $InitBat
    #
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



$Test = $True


Invoke-ConfigureProfileInitScript
Invoke-ConfigureVsSetting

if($Test){
    Test-VsSettings
}