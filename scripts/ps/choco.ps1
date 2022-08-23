
<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>


function Install-ChocoApps{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, Position=0)]
        [String]$Path
    )
    try{
        $TestMode = $false
        if($PSBoundParameters.ContainsKey('WhatIf')){
            $TestMode = $True
            Write-Verbose "[WhatIf] TestMode Enabled"
        }
        
        $CsvData = Import-csv -Path $Path -Delimiter '|'
        $ChocoExe = (Get-Command 'choco.exe').Source
        ForEach($c in $CsvData){ 
            $app = $c.'Program '
            $LogFile = "$ENV:Temp\choco\automatic-install-$app. log"
            $Null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Ignore
            if($TestMode){
                Write-Host "[WhatIf] " -f DarkYellow -n
                Write-Host "`"ChocoExe`" `"install`" `"$app`" `"-y`"" -f DarkRed
            }else{
                try{
                    Write-Verbose "`"$ChocoExe`" `"install`" `"$app`" `"--log-file=$LogFile`" `"-y`"  "
                    &"$ChocoExe" "install" "$app" "--log-file=$LogFile" "-y"  
                    $Size = (Get-Item "C:\Users\Client\AppData\Local\Temp\choco\automatic-install.log").Length
                    Write-Verbose "Log File is $Size Bytes"
                }catch{
                    Write-Host "Problem when installing `"$app`""
                }
            }
        }

    }catch{
        Write-Error $_
    }

}


function Export-InstalledAppList{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, Position=0)]
        [String]$Path,
        [Parameter(Mandatory = $false)]
        [switch]$Import
    )
    try{
        Set-Content -Path $Path -Value "Program | Version"
        $Apps = [System.Collections.ArrayList]::new()
        $ChocoExe = (Get-Command 'choco.exe').Source
        $List = &"$ChocoExe" "list" "-lo"
        Write-Verbose "Start write to $Path"
        $TotalPackages = $List.Count - 2
        For($i = 1 ; $i -le $TotalPackages ; $i++){
            $line = $List[$i]
            $line = $line.replace(' ', ' | ') 
            $Null = $Apps.Add($line)
            Add-Content -Path $Path -value $line
            Write-Verbose " => $line"
        }  
        Write-Host "Write Completed to $Path"

        if($Import){
            $CsvData = Import-csv -Path $Path -Delimiter '|'
            return $CsvData
        }
        return
        
    }catch{
        Write-Error $_
    }

}

function Install-ChocolateyPackageManager{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, Position=0)]
        [String]$Path
    )
    try{
        <#
        NOT YET IMPLEMENTED
            @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
        #>
    }catch{
        Write-Error $_
    }
}