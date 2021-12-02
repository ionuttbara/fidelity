pushd "%CD%"
CD /D "%~dp0"
regedit /s fidelityreg_reg11.reg
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
PowerRun "Command.bat"
PowerRun "Toggle Camera in menu.bat"
PowerRun "Toggle Microphone in menu.bat"
pause