# Set the output directory
$outputDir = "C:\IncidentResponse\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# System Information
$systemInfo = @{
    "Hostname" = $env:COMPUTERNAME
    "OS Version" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    "Uptime" = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    "Installed Software" = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
    "Running Processes" = Get-Process | Select-Object Name, ID, Path
    "Network Configuration" = Get-NetIPConfiguration
}
$systemInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\SystemInfo.json"

# Startup Items
$startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location, Name
$startupItems | ConvertTo-Json | Out-File -FilePath "$outputDir\StartupItems.json"

# User and Group Information
$userInfo = @{
    "Local Users" = Get-LocalUser | Select-Object Name, Enabled, LastLogon
    "User Groups" = Get-LocalGroup | Select-Object Name, SID
    "Recent User Accounts" = Get-LocalUser | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
}
$userInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\UserInfo.json"

# Event Logs
$eventLogs = @("Security", "System", "Application")
foreach ($log in $eventLogs) {
    $events = Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
    $events | Export-Csv -Path "$outputDir\$log.csv" -NoTypeInformation
}

# Network Connections
$networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$networkConnections | ConvertTo-Json | Out-File -FilePath "$outputDir\NetworkConnections.json"

# Registry Analysis
$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $registryKeys) {
    $keyName = $key.Split("\")[-1]
    $keyValues = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $keyValues | ConvertTo-Json | Out-File -FilePath "$outputDir\Registry_$keyName.json"
}

# File System Analysis
$criticalDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Users\Public")
foreach ($dir in $criticalDirs) {
    $recentFiles = Get-ChildItem -Path $dir -Recurse -File | Where-Object {$_.LastWriteTime -ge (Get-Date).AddHours(-24)}
    $recentFiles | Select-Object FullName, LastWriteTime, Length, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash}} | Export-Csv -Path "$outputDir\RecentFiles_$($dir.Replace(':', '').Replace('\', '_')).csv" -NoTypeInformation
}

# Artifact Collection
$artifactDirs = @("C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt", "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History")
foreach ($dir in $artifactDirs) {
    $artifacts = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue
    if ($artifacts) {
        $artifacts | Copy-Item -Destination $outputDir -Force
    }
}

# Firefox Extension Collection
$firefoxExtensions = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*" -ErrorAction SilentlyContinue
$firefoxExtensions | Select-Object FullName | ConvertTo-Json | Out-File -FilePath "$outputDir\FirefoxExtensions.json"

# Google Chrome Extension Collection
$UserPaths = (Get-WmiObject win32_userprofile | Where-Object localpath -notmatch 'Windows').localpath
foreach ($Path in $UserPaths) {
    $ExtPath = $Path + '\' + '\AppData\Local\Google\Chrome\User Data\Default\Extensions'
    if (Test-Path $ExtPath) {
        $Username = $Path | Split-Path -Leaf
        $ExtFolders = Get-Childitem $ExtPath | Where-Object Name -ne 'Temp'
        foreach ($Folder in $ExtFolders) {
            $VerFolders = Get-Childitem $Folder.FullName
            foreach ($Version in $VerFolders) {
                if (Test-Path -Path ($Version.FullName + '\manifest.json')) {
                    $Manifest = Get-Content ($Version.FullName + '\manifest.json') | ConvertFrom-Json
                    if ($Manifest.name -like '__MSG*') {
                        $AppId = ($Manifest.name -replace '__MSG_','').Trim('_')
                        @('\_locales\en_US\', '\_locales\en\') | ForEach-Object {
                            if (Test-Path -Path ($Version.Fullname + $_ + 'messages.json')) {
                                $AppManifest = Get-Content ($Version.Fullname + $_ +
                                'messages.json') | ConvertFrom-Json
                                @($AppManifest.appName.message, $AppManifest.extName.message,
                                $AppManifest.extensionName.message, $AppManifest.app_name.message,
                                $AppManifest.application_title.message, $AppManifest.$AppId.message) |
                                ForEach-Object {
                                    if (($_) -and (-not($ExtName))) {
                                        $ExtName = $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        $ExtName = $Manifest.name
                    }
                    Write-Output (($Path | Split-Path -Leaf) + ": " + [string] $ExtName +
                    " v" + $Manifest.version + " (" + $Folder.name + ")")
                    if ($ExtName) {
                        Remove-Variable -Name ExtName
                    }
                }
            }
        }
    }
}

# Chrome History Collection
$chromeHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue
$chromeHistoryFiles | Copy-Item -Destination $outputDir -Force

# Firefox History Collection
$firefoxHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite" -ErrorAction SilentlyContinue
$firefoxHistoryFiles | Copy-Item -Destination $outputDir -Force

# Search for Password Files
$passwordFiles = Get-ChildItem -Path C:\ -Include *password* -File -Recurse -ErrorAction SilentlyContinue
$passwordFiles | Select-Object FullName | ConvertTo-Json | Out-File -FilePath "$outputDir\PasswordFiles.json"

# User PowerShell History
$Users = (Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
$Pasts = @($Users)

foreach ($Past in $Pasts) {
    Write-Host "`n----User Pwsh History Path $Past---" -ForegroundColor Magenta
    Get-Content $Past | Out-File -FilePath "$outputDir\PowerShellHistory_$($Past.Split('\')[-2]).txt"
}

# Compress and Timestamp Output
$zipFile = "$outputDir.zip"
Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force
Remove-Item -Path $outputDir -Recurse -Force
