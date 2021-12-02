pushd "%CD%"
CD /D "%~dp0"

takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.InternalWebApi.dll"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.InternalWebApi.dll" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.InternalWebApi.dll"

takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHost.dll"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHost.dll" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHost.dll"


takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Cortana.UI"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Cortana.UI" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Cortana.UI"

takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.MiniUI"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.MiniUI" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchUx.MiniUI"

takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe"


takeown /f "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy"
cacls "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy"

takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"


takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ScreenClippingHost.exe"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ScreenClippingHost.exe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ScreenClippingHost.exe"


takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WebExperienceHostApp.exe"


takeown /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\MiniSearchHost.exe"
cacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\MiniSearchHost.exe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\MiniSearchHost.exe"


takeown /f "C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe"
cacls "C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe"


takeown /f "C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy"
cacls "C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy"


takeown /f "C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy"
cacls "C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy" /E /P %username%:F
del /F /Q "C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy"


pause