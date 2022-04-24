Write-Host "[1] Installing Visual Studio Community"
# Download Visual Studio Community Setup
wget https://aka.ms/vs/17/release/vs_community.exe -UseBasicParsing -OutFile C:\Windows\Temp\vs_community.exe

# Installing .NET Desktop Environment
# https://docs.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-community?view=vs-2022&preserve-view=true#net-desktop-development

C:\Windows\Temp\vs_community.exe --add Microsoft.VisualStudio.Workload.ManagedDesktop --installPath "C:\Program Files\Microsoft Visual Studio\2022\Community" --addProductLang en-US --includeRecommended --passive
