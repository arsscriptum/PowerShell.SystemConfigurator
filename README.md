# PowerShell.SystemConfigurator
The SystemConfigurator script suites is a powershell solution providing all the functions required to setup a new Windows system

```
	# This will install all chocolatey package manager
    . ./choco.ps1
    Install-Install-Chocolatey 

	# This will install all essential windows applications via Chocolatey
    . ./choco.ps1
    Install-ChocoApps 
```

### Overview of operations to be executed
- Create the permanent directory structure
- Setup the PowerShell user profile
- Setup the PowerShell module development environment: builder and environment values

![SystemConfigurator](https://raw.githubusercontent.com/arsscriptum/PowerShell.SystemConfigurator/master/img/sysconfig.png)
