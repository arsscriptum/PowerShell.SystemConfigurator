# PowerShell.SystemConfigurator
The SystemConfigurator script suites is a powershell solution providing all the functions required to setup a new Windows system

```
	# This will install all chocolatey package manager
    . ./choco.ps1
    Install-Chocolatey 
    
	# This will install all essential windows applications via Chocolatey
    . ./choco.ps1
    Install-ChocoApps -Path .\scripts\ChocoAppsNew.csv
```

![SystemConfigurator](https://raw.githubusercontent.com/arsscriptum/PowerShell.SystemConfigurator/master/img/sysconfig.png)
