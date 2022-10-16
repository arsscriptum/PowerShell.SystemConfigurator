@echo off

:init
    setlocal
    pushd "C:\Users\gp"

:main
    cls
    call "C:\Users\gp\Scripts\init.bat"
    call :pssleep 2500
    goto :terminate


:pssleep
    powershell -nop -c "& {sleep -m %1}"
    goto :eof


:terminate
    popd
    endlocal
    goto :eof

