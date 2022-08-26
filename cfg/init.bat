
@echo off
setlocal EnableDelayedExpansion

:: ==============================================================================
:: 
::      init.bat
::
:: ==============================================================================
::   arsccriptum - made in quebec 2020 <guillaumeplante.qc@gmail.com>
:: ==============================================================================
SET /A errno=0
SET /A ERROR_PATH_NOT_FOUND=2
SET /A ERROR_FILE_NOT_FOUND=4
SET /A ERROR_OTHERCOMMAND_FAILED=8
SET /A ERROR_OCCURED=0
goto :init

:init
    set "__scripts_root=%AutomationScriptsRoot%"
    call :read_script_root development\build-automation  BuildAutomation
    set "__script_file=%~0"
    set "__target=%~1"
    set "__logfile=%COMMON_LOG_FILE%"
    set "__script_path=%~dp0"
    set "__makefile=%__scripts_root%\make\make.bat"
    set "__lib_date=%__scripts_root%\batlibs\date.bat"
    set "__lib_out=%__scripts_root%\batlibs\out.bat"
    ::*** This is the important line ***
   
    set "__build_cancelled=0"
    goto :console_setup


:header
    echo. %__script_name% v%__script_version%
    echo.    This script is part of arsscriptum build wrappers.
    echo.
    goto :eof

:header_err
    echo.**************************************************
    echo.This script is part of arsscriptum build wrappers.
    echo.**************************************************
    echo.
    echo. YOU NEED TO HAVE THE BuildAutomation Scripts setup on you system...
    echo. https://github.com/arsscriptum/BuildAutomation
    goto :eof


:read_script_root
    set regpath=%OrganizationHKCU::=%
    for /f "tokens=2,*" %%A in ('REG.exe query %regpath%\%1 /v %2') do (
            set "__scripts_root=%%B"
        )
    goto :eof


:load_config
	set BATCHFILE="%~1"
	call %__lib_out% :__out_n_l_gry " [*] %BATCHFILE%"
	IF EXIST "%BATCHFILE%" (
    	call "%BATCHFILE%" > NUL
    	call %__lib_out% :__out_d_grn " SUCCESS"
 	)ELSE (
		goto :error_missing_script "%BATCHFILE%"
	)
	goto :eof


:console_setup
	if not exist "%VS140COMNTOOLS%" (
	 call :show_error "ERROR Environment variable VS140COMNTOOLS set to invalid path" 
	)
	pushd %VS140COMNTOOLS%
	call %__lib_out% :__out_underline_red "Configuration Visual Studio 14.0 environment"
	call :load_config "VsMSBuildCmd.bat"
	call :load_config "VsDevCmd.bat"
	popd
    IF %ERROR_OCCURED% EQU 0 (
        call %__lib_out% :__out_n_l_gry " [*] Current Visual Studio Version: "
        call %__lib_out% :__out_d_grn "%VisualStudioVersion%"
        goto :finished_success
    )ELSE (
        goto :finished_logs 
    )
    goto :eof
	



:show_error
	set ERROR_STRING="%~1"
    echo.
    call %__lib_out% :__out_d_yel "----------------------------------"
    call %__lib_out% :__out_d_red "ERROR! %ERROR_STRING%"
    call %__lib_out% :__out_d_yel "----------------------------------"
    echo.
    SET /A errno^|=%ERROR_OTHERCOMMAND_FAILED%
    goto :eof



:error_missing_script
    set MISSING_FILE="%~1"
    echo.
    call %__lib_out% :__out_d_yel "----------------------------------"
    call %__lib_out% :__out_d_red "ERROR! MISSING FILE %MISSING_FILE%"
    call %__lib_out% :__out_d_yel "----------------------------------"
    echo.
    SET /A ERROR_OCCURED^|=%ERROR_FILE_NOT_FOUND%
    SET /A errno^|=%ERROR_FILE_NOT_FOUND%
    goto :eof



:finished_success
    call %__lib_out% :__out_d_yel "----------------------------------"
    call %__lib_out% :__out_d_grn "           CONSOLE READY          "
    call %__lib_out% :__out_d_yel "----------------------------------"
    goto :finished_logs 
	goto :eof


:finished_logs
    call %__lib_out% :__out_n_l_gry "%__logfile% "
    call %__lib_out% :__out_d_grn "%errno%"
    echo %errno% > "%__logfile%"
    goto :eof

EXIT /B %errno%