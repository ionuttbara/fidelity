pushd "%CD%"
CD /D "%~dp0"
::network
echo Now installing Root certs
for /f "delims=" %%f in ('dir /b "%~dp0\certificates\*"') do (
	echo Installing %%f...
	certutil -f -addstore Root "%~dp0\certificates\%%f"
)
"powershell.exe" "get-appxpackage -AllUsers *windowsalarms* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *windowscommunicationsapps* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *officehub* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *skypeapp* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *getstarted* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *zunemusic* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *windowsmaps* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *solitairecollection* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *bingfinance* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *zunevideo* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *bingnews* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *onenote* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *people* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *windowsphone* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *photos* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *bingsports* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *soundrecorder* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *bingweather* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *connectivitystore* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *messaging* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *sway* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *3d* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *holographic* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers  Microsoft.XboxGamingOverlay | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers *3dbuilder* | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.MicrosoftEdge.Stable | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.PowerAutomateDesktop | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.XboxGameOverlay | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers MicrosoftWindows.Client.WebExperience | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.WindowsFeedbackHub | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.GetHelp | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.MicrosoftStickyNotes | Remove-AppxPackage"
"powershell.exe" "get-appxpackage -AllUsers Microsoft.ScreenSketch | Remove-AppxPackage"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.ScreenSketch | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.MicrosoftStickyNotes | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.GetHelp | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.WindowsFeedbackHub | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online MicrosoftWindows.Client.WebExperience | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.YourPhone | Remove-AppxProvisionedPackage -online"
"powershell.exe" "Get-AppxProvisionedPackage -online Microsoft.XboxGameOverlay | Remove-AppxProvisionedPackage -online"

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" /V "DisableSecuritySettingsCheck" /T "REG_DWORD" /D "00000001" /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RuntimeBroker.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WmiPrvSE.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RuntimeBroker.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BlueMail.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Update.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Rambox.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontdrvhost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option\RAVBg64.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RAVCpl64.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\spoolsv.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0.\ma.ps1""' -Verb RunAs}"

powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient"
powershell.exe "Disable-NetAdapterBinding -Name "*" -ComponentID ms_server"
netsh int tcp set supp internet congestionprovider=ctcp
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global initialRto=2000
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackttresiliency=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global fastopen=enabled
netsh int tcp set global fastopenfallback=enabled
netsh int tcp set global pacingprofile=off
netsh int tcp set global hystart=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=disabled
netsh int 6to4 set state state=enabled
netsh int udp set global uro=enabled
netsh winsock set autotuning on
powershell.exe "Disable-NetAdapterPowerManagement -Name *"
powershell.exe "Enable-NetAdapterChecksumOffload -Name * " 
powershell.exe "Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled"
powershell.exe "Disable-NetAdapterLso -Name *"
powershell.exe "Disable-NetAdapterVmq -Name "*"
netsh int tcp set supplemental template=custom icw=10
netsh interface teredo set state enterprise
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
netsh interface ipv6 set subinterface "Ethernet" mtu=1500 store=persistent
netsh interface ipv6 set subinterface "Ethernet" mtu=1500 store=persistent
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "*RSSProfile" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "ParamDesc" /t REG_SZ /d "RSS load balancing profile" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "default" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "type" /t REG_SZ /d "enum" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "1" /t REG_SZ /d "ClosestProcessor" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "2" /t REG_SZ /d "ClosestProcessorStatic" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "3" /t REG_SZ /d "NUMAScaling" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "4" /t REG_SZ /d "NUMAScalingStatic" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "5" /t REG_SZ /d "ConservativeScaling" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /t REG_DWORD /d 0000001 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /t REG_DWORD /d 0000000 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /t REG_DWORD /d 0000001 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "JointResize" /T REG_DWORD /D "0" /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "SnapAssist" /T REG_DWORD /D "0" /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "SnapFill" /T REG_DWORD /D "0" /F
netsh int tcp set global autotuning=experimental
PowerRun.exe Regedit.exe /S fidelityreg_reg11.reg
Regedit.exe /S fidelityreg_reg11.reg
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
"powershell.exe" Enable-WindowsOptionalFeature -Online -FeatureName LegacyComponents -all -NoRestart
"powershell.exe" Enable-WindowsOptionalFeature -Online -FeatureName DirectPlay -all -NoRestart
::Telemetry
sc config WerSvc start= disabled
sc config Wecsvc start= disabled
sc config MsKeyboardFilter start= disabled
sc config GraphicsPerfSvc start= disabled
sc config DiagTrack start= disabled
sc config TroubleshootingSvc start= disabled
sc config RemoteRegistry start= disabled
sc config shpamsvc start= disabled
sc config UevAgentService start= disabled
sc config MSiSCSI start= disabled
sc config NetTcpPortSharing start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config diagsvc start= disabled
sc config dmwappushservice start= disabled
sc config edgeupdate start= disabled

::Search

sc config WSearch start= disabled

::Remote Desktop Native

sc config tsusbflt start= disabled
sc config tsusbhub start= disabled
sc config TsUsbGD start= disabled
sc config TermService start= disabled
sc config SessionEnv start= disabled

::Networking Services

sc config PNRPsvc start= disabled
sc config p2psvc start= disabled
sc config p2pimsvc start= disabled
sc config PeerDistSvc start= disabled
sc config PerfHost start= disabled
sc config PNRPAutoReg start= disabled
sc config ALG start= disabled
sc config Fax start= disabled
sc config SNMPTrap start= disabled
sc config autotimesvc start= disabled
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config webthreatdefsvc start= disabled
sc config webthreatdefusersvc_63b8d start= disabled
sc config InventorySvc start= disabled
sc config MapsBroker start= disabled
sc config pla start= disabled

::VR Services

sc config perceptionsimulation start= disabled
sc config SharedRealitySvc start= disabled
sc config spectrum start= disabled
sc config MixedRealityOpenXRSvc start= disabled

::Retail Demo

sc config RetailDemo start= disabled

::Virtual Machine

sc config HvHost start= disabled
sc config vmickvpexchange start= disabled
sc config vmicguestinterface start= disabled
sc config vmicshutdown start= disabled
sc config vmicheartbeat start= disabled
sc config vmicvmsession start= disabled
sc config vmicrdv start= disabled
sc config vmictimesync start= disabled
sc config vmicvss start= disabled
sc config VMAuthdService start=demand
sc config VMnetDHCP start= demand
sc config VMware NAT Service start= demand
sc config VMUSBArbService start= demand
sc config VMwareHostd start= demand
sc config wcncsvc start= disabled

::Blotware


sc config lfsvc start= disabled
sc config GoogleChromeBetaElevationService start= demand
sc config gupdate start= demand
sc config gupdatem start= demand
sc config GamingServices start= demand
sc config sppsvc start= demand
sc config DoSvc start= demand
sc config CDPSvc start= demand
sc config ClickToRunSvc start= demand
sc config DtsApo4Service start= demand
sc config TrkWks start= demand
sc config VacSvc start= disabled
sc config VSStandardCollectorService150
sc config ss_conn_service start= demand
sc config ss_conn_service2 start= demand
sc config AudioEndpointBuilder start= demand
sc config RpcLocator start= disabled
sc config Sense start= disabled
sc config TapiSrv start= disabled
sc config KtmRm start= disabled
sc config SEMgrSvc start= disabled
sc config SCardSvr start= disabled
sc config ScDeviceEnum start= disabled
sc config AppVClient start= disabled
sc config SysMain start= disabled
sc config SSDPSRV start= disabled
sc config IKEEXT start= demand
sc config FontCache3.0.0.0 start= disabled
sc config WinRM start= disabled
sc config AxInstSV start= disabled
sc config WpcMonSvc start= disabled
sc config pla start= disabled
sc config COMSysApp start= disabled
sc config AGMService start= disabled
sc config AGSService start= disabled
::Fidelity - Task Disabler 
::Applies to EAS and n-EAS Fidelity Version

::disable task for performance and low cpu
::.net

schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /disable

::ad tms management

schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" /disable
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" /disable 

::Mentenanta

schtasks /Change /TN "\Microsoft\Windows\Chkdsk\ProactiveScan" /disable
schtasks /Change /TN "\Microsoft\Windows\Chkdsk\SyspartRepair" /disable
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan" /disable
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan" /disable
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery" /disable
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /disable
schtasks /Change /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /disable
schtasks /Change /TN "\Microsoft\Windows\Registry\RegIdleBackup" /disable

:: telemetry 
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /TN "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\AppUriVerifierDaily" /disable
schtasks /Change /TN "\Microsoft\Windows\Device information\Device" /disable
schtasks /Change /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" /disable
schtasks /Change /TN "\Microsoft\Windows\Flighting\OneSettings\RefreshCache" /disable
schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /disable
schtasks /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
schtasks /Change /TN "\Microsoft\Windows\AppListBackup\Backup" /disable
schtasks /Change /TN "\Microsoft\Windows\Device Information\Device" /disable
schtasks /Change /TN "\Microsoft\Windows\Device Information\Device User" /disable
schtasks /Change /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\DirectX\DXGIAdapterCache" /disable
schtasks /Change /TN "\Microsoft\Windows\DirectX\DirectXDatabaseUpdater" /disable
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\StorageSense" /disable
schtasks /Change /TN "\Microsoft\Windows\DUSM\dusmtask" /disable
schtasks /Change /TN "\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /Change /TN "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /disable
schtasks /Change /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /disable
schtasks /Change /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /disable
schtasks /Change /TN "\Microsoft\Windows\Flighting\OneSettings\RefreshCache" /disable
schtasks /Change /TN "\Microsoft\Windows\Input\LocalUserSyncDataAvailable" /disable
schtasks /Change /TN "\Microsoft\Windows\Input\MouseSyncDataAvailable" /disable
schtasks /Change /TN "\Microsoft\Windows\Input\PenSyncDataAvailable" /disable
schtasks /Change /TN "\Microsoft\Windows\Input\TouchpadSyncDataAvailable" /disable
schtasks /Change /TN "\Microsoft\Windows\International\Synchronize Language Settings" /disable
schtasks /Change /TN "\Microsoft\Windows\Kernel\La57Cleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /disable
schtasks /Change /TN "\Microsoft\Windows\Management\Provisioning\Logon" /disable
schtasks /Change /TN "\Microsoft\Windows\Management\Provisioning\Cellular" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /disable
schtasks /Change /TN "\Microsoft\Windows\NlaSvc\WiFiTask" /disable
schtasks /Change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /disable
schtasks /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /disable
schtasks /Change /TN "\Microsoft\Windows\Servicing\StartComponentCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" /disable
schtasks /Change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /disable
schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
schtasks /Change /TN "\Microsoft\Windows\TPM\Tpm-HASCertRetr" /disable
schtasks /Change /TN "\Microsoft\Windows\TPM\Tpm-Maintenance" /disable
schtasks /Change /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" /disable
schtasks /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /disable
schtasks /Change /TN "\Microsoft\Windows\WlanSvc\CDSSync" /disable
schtasks /Change /TN "\Microsoft\Windows\WwanSvc\NotificationTask" /disable
schtasks /Change /TN "\Microsoft\Windows\WwanSvc\OobeDiscovery" /disable


::automatic App Update Windows
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic ` Update" /disable

:: Office Telemetry Disable

schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable


schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" /disable
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand" /disable
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" /disable
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePolicyChange" /disable
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceProtectionStateChanged" /disable
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceSettingChange" /disable


::TabletPC

sc config SensorDataService start= disabled
sc config SensrSvc start= disabled
sc config SensorService start= disabled
sc config SmsRouter start= disabled
sc config PhoneSvc start= disabled

::Data


sc config DusmSvc start= disabled
takeown /f C:\Windows\System32\GamePanel.exe
cacls C:\Windows\System32\GamePanel.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\GamePanel.exe"
takeown /f C:\Windows\System32\wermgr.exe
cacls C:\Windows\System32\wermgr.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\wermgr.exe"
takeown /f C:\Windows\System32\wersvc.dll
cacls C:\Windows\System32\wersvc.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\wersvc.dll"
takeown /f C:\Windows\System32\werui.dll
cacls C:\Windows\System32\werui.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\werui.dll"
takeown /f C:\Windows\System32\WerEnc.dll
cacls C:\Windows\System32\WerEnc.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\WerEnc.dll"
takeown /f C:\Windows\System32\WerFault.exe
cacls C:\Windows\System32\WerFault.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\WerFault.exe"
takeown /f C:\Windows\System32\wercplsupport.dll
cacls C:\Windows\System32\wercplsupport.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\wercplsupport.dll"
takeown /f C:\Windows\System32\werdiagcontroller.dll
cacls C:\Windows\System32\werdiagcontroller.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\werdiagcontroller.dll"
takeown /f C:\Windows\System32\lfsvc.dll
cacls C:\Windows\System32\lfsvc.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\lfsvc.dll"
takeown /f C:\Windows\System32\WerEnc.dll
cacls C:\Windows\System32\WerEnc.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\WerEnc.dll"
takeown /f C:\Windows\System32\werui.dll
cacls C:\Windows\System32\werui.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\werui.dll"
takeown /f C:\Windows\System32\WerFaultSecure.exe
cacls C:\Windows\System32\WerFaultSecure.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\WerFaultSecure.exe"
takeown /f C:\Windows\System32\gameux.dll
cacls C:\Windows\System32\gameux.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\gameux.dll"
takeown /f C:\Windows\System32\GamePanelExternalHook.dll
cacls C:\Windows\System32\GamePanelExternalHook.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\GamePanelExternalHook.dll"
takeown /f C:\Windows\System32\GamePanel.exe
cacls C:\Windows\System32\GamePanel.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\GamePanel.exe"
takeown /f C:\Windows\System32\gamemode.dll
cacls C:\Windows\System32\gamemode.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\gamemode.dll"
takeown /f C:\Windows\System32\GameBarPresenceWriter.exe
cacls C:\Windows\System32\GameBarPresenceWriter.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\GameBarPresenceWriter.exe"
takeown /f C:\Windows\System32\smartscreen.exe
cacls C:\Windows\System32\smartscreen.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\smartscreen.exe"
takeown /f C:\Windows\System32\smartscreenps.dll
cacls C:\Windows\System32\smartscreenps.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\smartscreenps.dll"
takeown /f C:\Windows\System32\DeviceCensus.exe
cacls C:\Windows\System32\DeviceCensus.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\DeviceCensus.exe"
takeown /f C:\Windows\System32\CompatTelRunner.exe
cacls C:\Windows\System32\CompatTelRunner.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\CompatTelRunner.exe"
takeown /f C:\Windows\System32\zipcontainer.dll
cacls C:\Windows\System32\zipcontainer.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\zipcontainer.dll"
takeown /f C:\Windows\System32\msfeeds.dll
cacls C:\Windows\System32\msfeeds.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\msfeeds.dll"
takeown /f C:\Windows\System32\MsSpellCheckingHost.exe
cacls C:\Windows\System32\MsSpellCheckingHost.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\MsSpellCheckingHost.exe"
takeown /f C:\Windows\System32\ieapfltr.dll
cacls C:\Windows\System32\ieapfltr.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\ieapfltr.dll"
takeown /f C:\Windows\System32\MsSpellCheckingFacility.dll
cacls C:\Windows\System32\MsSpellCheckingFacility.dll /E /P %username%:F
del /F /Q "C:\Windows\System32\MsSpellCheckingFacility.dll"
takeown /f C:\Windows\System32\LocationNotificationWindows.exe
cacls C:\Windows\System32\LocationNotificationWindows.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\LocationNotificationWindows.exe"
takeown /f C:\Windows\System32\msfeedssync.exe
cacls C:\Windows\System32\msfeedssync.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\msfeedssync.exe"
takeown /f C:\Windows\System32\dmclient.exe
cacls C:\Windows\System32\dmclient.exe /E /P %username%:F
del /F /Q "C:\Windows\System32\dmclient.exe"
takeown /f C:\Windows\hh.exe
cacls C:\Windows\hh.exe /E /P %username%:F
del /F /Q "C:\Windows\hh.exe"
takeown /f C:\Windows\HelpPane.exe
cacls C:\Windows\HelpPane.exe /E /P %username%:F
del /F /Q "C:\Windows\HelpPane.exe"
takeown /f C:\Windows\winhlp32.exe
cacls C:\Windows\winhlp32.exe /E /P %username%:F
del /F /Q "C:\Windows\winhlp32.exe"
takeown /f C:\Windows\System32\WpcMon.exe
cacls "C:\Windows\System32\WpcMon.exe" /E /P %username%:F
del /F /Q "C:\Windows\System32\WpcMon.exe"
takeown /f C:\Windows\System32\atieclxx.exe
cacls "C:\Windows\System32\atieclxx.exe" /E /P %username%:F
del /F /Q "C:\Windows\System32\atieclxx.exe"
takeown /f C:\Windows\System32\OneDriveSetup.exe
cacls "C:\Windows\System32\OneDriveSetup.exe" /E /P %username%:F
del /F /Q "C:\Windows\System32\OneDriveSetup.exe"
::Handwriting

dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~af-ZA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~bs-LATN-BA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ca-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~cs-CZ~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~cy-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~da-DK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~de-DE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~el-GR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~en-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~en-US~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~es-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~es-MX~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~eu-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~fi-FI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~fr-FR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ga-IE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~gd-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~gl-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~hi-IN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~hr-HR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~id-ID~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~it-IT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ja-JP~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ko-KR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~lb-LU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~mi-NZ~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ms-BN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ms-MY~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nb-NO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nl-NL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nn-NO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nso-ZA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pl-PL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pt-BR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pt-PT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~rm-CH~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ro-RO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ru-RU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~rw-RW~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sk-SK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sl-SI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sq-AL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sr-CYRL-RS~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sr-LATN-RS~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sv-SE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sw-KE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~tn-ZA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~tr-TR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~wo-SN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~xh-ZA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-CN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-HK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-TW~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zu-ZA~0.0.1.0  /NoRestart


::OCR

dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~ar-SA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~bg-BG~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~bs-LATN-BA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~cs-CZ~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~da-DK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~de-DE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~el-GR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~en-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~es-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~es-MX~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~fi-FI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~fr-CA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~fr-FR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~hr-HR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~hu-HU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~it-IT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~ja-JP~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~ko-KR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~nb-NO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~nl-NL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~pl-PL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~pt-BR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~pt-PT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~ro-RO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~ru-RU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~sk-SK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~sl-SI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~sr-CYRL-RS~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~sr-LATN-RS~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~sv-SE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~tr-TR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-CN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-HK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-TW~0.0.1.0  /NoRestart

::Speech Recongnition

dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~da-DK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~de-DE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-AU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-CA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-IN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-US~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~es-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~es-MX~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~fr-CA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~fr-FR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~it-IT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~ja-JP~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~pt-BR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-CN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-HK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-TW~0.0.1.0  /NoRestart


::TTS Packs

dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ar-EG~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ar-SA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~bg-BG~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ca-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~cs-CZ~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~da-DK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-AT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-CH~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-DE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~el-GR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-AU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-CA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-GB~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-IE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-IN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-US~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~es-ES~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~es-MX~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fi-FI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-CA~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-CH~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-FR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~he-IL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hi-IN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hr-HR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hu-HU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~id-ID~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~it-IT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ja-JP~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ko-KR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ms-MY~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nb-NO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nl-BE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nl-NL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pl-PL~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pt-BR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pt-PT~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ro-RO~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ru-RU~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sk-SK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sl-SI~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sv-SE~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ta-IN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~th-TH~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~tr-TR~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~vi-VN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-CN~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-HK~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-TW~0.0.1.0  /NoRestart

::Network Drivers
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Ethernet.Client.Intel.E1i68x64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Ethernet.Client.Intel.E2f68~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Ethernet.Client.Vmware.Vmxnet3~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Ethernet.Client.Realtek.Rtcx21x64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Broadcom.Bcmpciedhd63~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Broadcom.Bcmwl63al~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Broadcom.Bcmwl63a~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwbw02~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwew00~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwew01~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwlv64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwns64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwsw00~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwtw02~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwtw04~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwtw06~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwtw08~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Intel.Netwtw10~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Marvel.Mrvlpcie8897~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Qualcomm.Athw8x~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Qualcomm.Athwnx~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Qualcomm.Qcamain10x64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Ralink.Netr28x~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtl8187se~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtl8192se~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtl819xp~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtl85n64~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtwlane01~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtwlane13~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.Wifi.Client.Realtek.Rtwlane~~~~0.0.1.0  /NoRestart

::Windows Tools
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.IoTDeviceUpdateCenter~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Microsoft.Windows.WordPad~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OneCoreUAP.OneSync~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OneCoreUAP.OneSync~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Print.Fax.Scan~~~~0.0.1.0 /NoRestart
dism /Online /Remove-Capability /CapabilityName:MathRecognizer~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Media.WindowsMediaPlayer~~~~0.0.12.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Accessibility.Braille~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Analog.Holographic.Desktop~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:App.StepsRecorder~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:App.Support.QuickAssist~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:App.WirelessDisplay.Connect~~~~0.0.1.0  /NoRestart
dism /Online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart
dism /Online /Remove-Capability /CapabilityName:Hello.Face.20134~~~~0.0.1.0  /NoRestart
xcopy "*.exe" "C:\Windows\System32" /Y
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RuntimeBroker.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WmiPrvSE.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RuntimeBroker.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BlueMail.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Update.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "2" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Rambox.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontdrvhost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option\RAVBg64.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RAVCpl64.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\spoolsv.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString().Replace(\" \", \"\").Replace(\"`n\", \"\") -ErrorAction SilentlyContinue}"
echo Enabling KMM...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
echo Disabling Meltdown and Spectre patches...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
echo Disabling Kernel Control Flow Guard...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
echo Disabling kernel Exception Chain Validation...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
echo Disabling kernel SEHOP...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
echo Copying SDL...
copy "%~dp0\SDL.dll" "C:\Windows\System32\SDL.dll" /Y
copy "%~dp0\SDL.dll" "C:\Windows\SysWOW64\SDL.dll" /Y
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete wercplsupport
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DEFRAGSVC" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_1c6e8" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_77ac1" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "2" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\irmon" /v Start /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AxInstSV" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinRM" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TrkWks" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\luafv" /v "Start" /t REG_DWORD /d "4" /f
bcdedit /set allowedinmemorysettings 0 
bcdedit /set useplatformclock No 
bcdedit /set useplatformtick No 
bcdedit /set hypervisorlaunchtype Off 
bcdedit /set tscsyncpolicy Enhanced 
bcdedit /set debug No 
bcdedit /set isolatedcontext No 
bcdedit /set pae ForceEnable 
bcdedit /set bootmenupolicy Legacy 
bcdedit /set usefirmwarepcisettings No 
bcdedit /set sos Yes 
bcdedit /set disabledynamictick Yes 
bcdedit /set disableelamdrivers Yes 
bcdedit /set x2apicpolicy Enable 
bcdedit /set vsmlaunchtype Off 
bcdedit /set usephysicaldestination No 
bcdedit /set ems No 
bcdedit /set firstmegabytepolicy UseAll 
bcdedit /set configaccesspolicy Default 
bcdedit /set linearaddress57 optin 
bcdedit /set noumex Yes 
bcdedit /set bootems No 
bcdedit /set graphicsmodedisabled No 
bcdedit /set extendedinput Yes 
bcdedit /set highestmode Yes 
bcdedit /set forcefipscrypto No 
bcdedit /set perfmem 0 
bcdedit /set clustermodeaddressing 1 
bcdedit /set configflags 0 
bcdedit /set uselegacyapicmode No 
bcdedit /set onecpu No
bcdedit /set halbreakpoint No 
bcdedit /set forcelegacyplatform No 
bcdedit /set nx AlwaysOff
bcdedit /set {current} recoveryenabled no
bcdedit /set nointegritychecks on
bcdedit /set useplatformclock No
bcdedit /set pae ForceEnable
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock false
bcdedit /set tscsyncpolicy legacy
bcdedit /set tpmbootentropy ForceDisable 
bcdedit /timeout 0
bcdedit /set allowedinmemorysettings 0x0 
bcdedit /set isolatedcontext No 
bcdedit /set x2apicpolicy disable
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set vm No
bcdedit /set bootmenupolicy legacy
xcopy "*.ico" "C:\Windows" /Y
::Disable VBS

bcdedit /create {0cb3b571-2f2e-4343-a879-d86a476d7215} /d
bcdedit /set {bootmgr} bootsequence {0cb3b571-2f2e-4343-a879-d86a476d7215}
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,,DISABLE-VBS
bcdedit /set {current} disableelamdrivers yes  
bcdedit /set vsmlaunchtype off
bcdedit /set recoveryenabled NO 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 222202202222222220020000002000200000000000000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 0 /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

::test


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /V BluetoothLastDisabledNearShare /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /V NearShareChannelUserAuthzPolicy /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /V CdpSessionUserAuthzPolicy /T REG_DWORD /D 1 /F
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V link /T REG_Binary /D 00000000 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\IrisService" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\History" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Telephony" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\StorageSense" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Holographic" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TWinUI\FilePicker\LastVisitedPidlMRU" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TabletMode" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\BannerStore" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Dsh" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Dialer" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Census" /f


reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 222202202222222220020000002000200000000000000000 /f

REM Other Mitigation stuff
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 0 /f


REM Telemetry
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REM the one below is actually 0 to disable customer improvement program, idk why
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
REM same thing, 1 to disable
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f

REM Defender and SmartScreen
REM we cannot disable Defender in Win11 but at least make it slimmer and stop it from taking actions on its own
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "6" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "6" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "6" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "6" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d 1 /f

REM Disabled features
REM Get Insider Updates without joining the Insider Program and without having Telemetry enabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fidelity" /v DisplayName /t reg_sz /d "Fidelity (EAS)" /f
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do Reg delete "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul
for /f %%i in ('wmic path win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul
(for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f) >nul
for /f %%a in ('Reg query HKLM /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
for /f %%i in ('Reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (Reg add "%%i" /v "GigaLite" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (Reg add "%%i" /v "*EEE" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (Reg add "%%i" /v "*FlowControl" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (Reg add "%%i" /v "PowerSavingMode" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableSavePowerNow" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnablePowerManagement" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableGreenEthernet" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableDynamicPowerGating" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableDynamicPowerGating" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableConnectedPowerGating" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableConnectedPowerGating" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (Reg add "%%i" /v "AutoPowerSaveModeEnabled" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "AutoDisableGigabit" ^| findstr "HKEY"') do (Reg add "%%i" /v "AutoDisableGigabit" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (Reg add "%%i" /v "AdvancedEEE" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (Reg add "%%i" /v "ULPMode" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (Reg add "%%i" /v "ReduceSpeedOnPowerDown" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnablePME" /t Reg_SZ /d "0" /f)
) 

Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t Reg_DWORD /d "4" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t Reg_DWORD /d "3" /f >nul

Reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t Reg_DWORD /d "38" /f >nul 2>&1
for /f %%i in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
	Reg add "%%i" /v "DmaRemappingCompatible" /t Reg_DWORD /d "0" /f >nul 2>&1
)

for /f %%r in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /f "PCI\VEN_" /d /s^|Findstr HKEY_') do (
Reg add %%r /v "AutoDisableGigabit" /t Reg_SZ /d "0" /f >nul
Reg add %%r /v "EnableGreenEthernet" /t Reg_SZ /d "0" /f >nul
Reg add %%r /v "GigaLite" /t Reg_SZ /d "0" /f >nul
Reg add %%r /v "PowerSavingMode" /t Reg_SZ /d "0" /f >nul
)

netsh int tcp set global initialRto=2000 >nul 2>&1
netsh int tcp set global autotuninglevel=normal >nul 2>&1
netsh int tcp set global chimney=disabled >nul 2>&1
netsh int tcp set global dca=enabled >nul 2>&1
netsh int tcp set global netdma=disabled >nul 2>&1
netsh int tcp set global ecncapability=enabled >nul 2>&1
netsh int tcp set global nonsackrttresiliency=disabled >nul 2>&1
netsh int tcp set global rss=enabled >nul 2>&1
netsh int tcp set global MaxSynRetransmissions=2 >nul 2>&1
netsh int tcp set heuristics disabled >nul 2>&1
netsh int tcp set supplemental Internet congestionprovider=ctcp >nul 2>&1
netsh int tcp set global timestamps=disabled >nul 2>&1
netsh int tcp set global rsc=disabled >nul 2>&1

for /f "tokens=3*" %%s in ('Reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
	::Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched\Parameters\Adapters\%%s" /v "NonBestEffortLimit" /t Reg_DWORD /d "0" /f >nul
	::Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "DeadGWDetectDefault" /t Reg_DWORD /d "1" /f >nul
	::Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "PerformRouterDiscovery" /t Reg_DWORD /d "1" /f >nul
	::Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpInitialRTT" /t Reg_DWORD /d "0" /f >nul
 	Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TCPNoDelay" /t Reg_DWORD /d "1" /f  >nul
	Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f >nul
	Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f >nul
	)


for %%i in (edge chrome notepad++ steamwebviewer winword powerpnt excel mysummercar metin2 csgo VALORANT-Win64-Shipping javaw FortniteClient-Win64-Shipping ModernWarfare r5apex) do (
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t Reg_SZ /d "%%i.exe" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t Reg_SZ /d "1.0" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t Reg_SZ /d "46" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t Reg_SZ /d "-1" /f
) >nul 2>nul
Reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >nul 2>&1
sc stop lmhosts 
sc config lmhosts start=disabled
sc stop LanmanWorkstation
sc config LanmanWorkstation start=disabled
echo Security Tweaks

Reg add "HKLM\System\CurrentControlSet\Control\Class{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control\Class{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control\Class{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control\Class{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control\Class{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control\Class{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t Reg_MULTI_SZ /d "" /f >nul 2>&1
::Disable Preemption
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /t Reg_DWORD /d "0" /f >nul 2>&1
echo Disable Preemption

::kboost
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /t Reg_DWORD /d "1" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /t Reg_DWORD /d "1" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /t Reg_DWORD /d "1" /f >nul

::
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t Reg_DWORD /d "0" /f >nul 2>&1


Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t Reg_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableTiledDisplay" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t Reg_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t Reg_DWORD /d "1" /f >nul 2>&1

Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_AllowTDRAfterECC" /t Reg_DWORD /d "1" /f >nul 2>&1
REM ; related to record
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DVRSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
REM ; related to vm

Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DisableAutoWattman" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DisableLightSleep" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableEDIDManagementSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableEventLog" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableHWSHighPriorityQueue" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableSDMAPaging" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableSVMSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FramePacingSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_UseBestGPUPowerOption" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "MobileServerEnabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "MobileServerRemotePlayEnabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_CCCNextEnabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_IoMmuGpuIsolation" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableSeamlessBoot" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_IsGamingDriver" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_RadeonBoostEnabled" /t Reg_DWORD /d "1" /f >nul 2>&1
REM ; amd software
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalOptimizeEdpLinkRate" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalPSRFeatureEnable" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableAspmL0s" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableAspmL1" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePllOffInL1" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSamuClockGating" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSamuLightSleep" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableGPUVirtualizationFeature" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_BlockchainSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_ChillEnabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableGDIAcceleration" /t Reg_DWORD /d "1" /f >nul 2>&1
REM ; HDMI Feature
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DisableAutoWattman" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DisableLightSleep" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3D_Refresh_Rate_Override_DEF" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3to2Pulldown_NA" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Adaptive De-interlacing" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSkins" /t Reg_SZ /d "false" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSnapshot" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSubscription" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AutoColorDepthReduction_NA" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL0s" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t Reg_DWORD /d "0" /f >nul 2>&1




::AMD Reg Keys
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f >nul 2>&1
REM ; related to record
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableeRecord" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_SDIEnable" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableAspmSWL1" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ForcePcieLinkSpeed" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_GameManagerSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_10BitMode" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1SS" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSamuBypassMode" /t Reg_DWORD /d "1" /f >nul 2>&1
REM ; Load Balancing Per Watt
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableLBPWSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablePllOffInL1" /t Reg_DWORD /d "0" /f >nul 2>&1
REM ; Related to Intel SpeedStep Technology
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablePPSMSupport" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableSpreadSpectrum" /t Reg_DWORD /d "0" /f >nul 2>&1
REM ; c.f https://docs.nvidia.com/gameworks/content/developertools/desktop/timeout_detection_recovery.htm

bcdedit -set NOINTEGRITYCHECKS OFF
bcdedit -set TESTSIGNING OFF
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\rdbss" /v "Start" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\pcmcia" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\luafv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\lltdio" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\hwpolicy" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\vdrvroot" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "2" /
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\TrustedInstaller" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\srvnet" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\rspndr" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\TrkWks" /v "Start" /t REG_DWORD /d "3" /f-nojoy -high -fullscreen -disable_d3d9ex  -softparticlesdefaultoff   -novid  +net_graph "1" 
powershell "Set-ProcessMitigation -Name vgc.exe -Enable AuditDynamicCode"
powershell "Set-ProcessMitigation -Name vgc.exe -Enable CFG"
powershell "Set-ProcessMitigation -System -Enable CFG"
powershell "Set-ProcessMitigation -Name csgo.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name chrome.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name winword.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name excel.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name powerpnt.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name mpc-hc64.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name cmd.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name Photoshop.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name notepad.exe -Disable CFG"
powershell "Set-ProcessMitigation -Name Notepad++.exe -Disable CFG"
shutdown /r /f /t 0