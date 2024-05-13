# Set the output directory
$outputDir = "C:\IncidentResponse\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Initialize the log file
$logFile = "$outputDir\script_log.txt"
Start-Transcript -Path $logFile -Append

# Function to calculate file hash
function Get-FileHash {
    param(
        [string]$FilePath,
        [string]$Algorithm = 'SHA256'
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        Write-Warning "Error calculating hash for file: $FilePath"
        Write-Warning $_.Exception.Message
        return $null
    }
}

# System Information
try {
    $systemInfo = @{
        "Hostname" = $env:COMPUTERNAME
        "OS Version" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        "Uptime" = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        "Installed Software" = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
        "Running Processes" = Get-Process | Select-Object Name, ID, Path, @{Name="User";Expression={$_.GetOwner().User}}
        "Network Configuration" = Get-NetIPConfiguration
    }
    $systemInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\SystemInfo.json"
}
catch {
    Write-Warning "Error collecting system information"
    Write-Warning $_.Exception.Message
}

# Startup Items
try {
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location, Name
    $startupItems | ConvertTo-Json | Out-File -FilePath "$outputDir\StartupItems.json"
}
catch {
    Write-Warning "Error collecting startup items"
    Write-Warning $_.Exception.Message
}

# User and Group Information
try {
    $userInfo = @{
        "Local Users" = Get-LocalUser | Select-Object Name, Enabled, LastLogon
        "User Groups" = Get-LocalGroup | Select-Object Name, SID
        "Recent User Accounts" = Get-LocalUser | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
    }
    $userInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\UserInfo.json"
}
catch {
    Write-Warning "Error collecting user and group information"
    Write-Warning $_.Exception.Message
}

# Event Logs
try {
    $eventLogs = @("Security", "System", "Application")
    foreach ($log in $eventLogs) {
        $events = Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        $events | Export-Csv -Path "$outputDir\$log.csv" -NoTypeInformation
    }
}
catch {
    Write-Warning "Error collecting event logs"
    Write-Warning $_.Exception.Message
}

# Network Connections
try {
    $networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    $networkConnections | ConvertTo-Json | Out-File -FilePath "$outputDir\NetworkConnections.json"
}
catch {
    Write-Warning "Error collecting network connections"
    Write-Warning $_.Exception.Message
}

# Registry Analysis
try {
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
}
catch {
    Write-Warning "Error collecting registry data"
    Write-Warning $_.Exception.Message
}

# Shimcache Collection
try {
    $shimcacheFile = "$outputDir\Shimcache.reg"
    & reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
}
catch {
    Write-Warning "Error collecting Shimcache data"
    Write-Warning $_.Exception.Message
}

# File System Analysis
try {
    $criticalDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Users\Public")
    foreach ($dir in $criticalDirs) {
        $recentFiles = Get-ChildItem -Path $dir -Recurse -File | Where-Object {$_.LastWriteTime -ge (Get-Date).AddHours(-24)}
        $recentFiles | Select-Object FullName, LastWriteTime, Length, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName).Hash}} | Export-Csv -Path "$outputDir\RecentFiles_$($dir.Replace(':', '').Replace('\', '_')).csv" -NoTypeInformation
    }
}
catch {
    Write-Warning "Error collecting file system data"
    Write-Warning $_.Exception.Message
}

# Artifact Collection
try {
    $artifactDirs = @("C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt", "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History")
    foreach ($dir in $artifactDirs) {
        $artifacts = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue
        if ($artifacts) {
            $artifacts | Copy-Item -Destination $outputDir -Force
        }
    }
}
catch {
    Write-Warning "Error collecting artifact data"
    Write-Warning $_.Exception.Message
}

# Firefox Extension Collection
try {
    $firefoxExtensions = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*" -ErrorAction SilentlyContinue
    $firefoxExtensions | Select-Object FullName | ConvertTo-Json | Out-File -FilePath "$outputDir\FirefoxExtensions.json"
}
catch {
    Write-Warning "Error collecting Firefox extensions"
    Write-Warning $_.Exception.Message
}

# Google Chrome Extension Collection
try {
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
}
catch {
    Write-Warning "Error collecting Google Chrome extensions"
    Write-Warning $_.Exception.Message
}

# Chrome History Collection
try {
    $chromeHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue
    $chromeHistoryFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting Chrome history"
    Write-Warning $_.Exception.Message
}

# Firefox History Collection
try {
    $firefoxHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite" -ErrorAction SilentlyContinue
    $firefoxHistoryFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting Firefox history"
    Write-Warning $_.Exception.Message
}

# Microsoft Edge History Collection
try {
    $edgeHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History" -ErrorAction SilentlyContinue
    $edgeHistoryFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting Microsoft Edge history"
    Write-Warning $_.Exception.Message
}

# Search for Password Files
try {
    $passwordFiles = Get-ChildItem -Path C:\ -Include *password* -File -Recurse -ErrorAction SilentlyContinue
    $passwordFiles | Select-Object FullName, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName).Hash}} | ConvertTo-Json | Out-File -FilePath "$outputDir\PasswordFiles.json"
}
catch {
    Write-Warning "Error searching for password files"
    Write-Warning $_.Exception.Message
}

# User PowerShell History
try {
    $Users = (Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
    $Pasts = @($Users)

    foreach ($Past in $Pasts) {
        Write-Host "`n----User Pwsh History Path $Past---" -ForegroundColor Magenta
        Get-Content $Past | Out-File -FilePath "$outputDir\PowerShellHistory_$($Past.Split('\')[-2]).txt"
    }
}
catch {
    Write-Warning "Error collecting user PowerShell history"
    Write-Warning $_.Exception.Message
}

# Prefetch Files Collection
try {
    $prefetchFiles = Get-ChildItem -Path "C:\Windows\Prefetch" -ErrorAction SilentlyContinue
    $prefetchFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting prefetch files"
    Write-Warning $_.Exception.Message
}

# Jump Lists Collection
try {
    $jumpListFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -ErrorAction SilentlyContinue
    $jumpListFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting jump list files"
    Write-Warning $_.Exception.Message
}

# Windows Timeline Collection
try {
    $timelineRegistry = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityDataModel"
    $timelineRegistryFile = "$outputDir\Timeline.reg"
    & reg export $timelineRegistry $timelineRegistryFile /y

    $timelineFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -ErrorAction SilentlyContinue
    $timelineFiles | Copy-Item -Destination $outputDir -Force
}
catch {
    Write-Warning "Error collecting Windows Timeline data"
    Write-Warning $_.Exception.Message
}

# Hashing of Collected Files
try {
    $collectedFiles = Get-ChildItem -Path $outputDir -File -Recurse
    foreach ($file in $collectedFiles) {
        $hash = Get-FileHash -FilePath $file.FullName
        if ($hash) {
            Add-Content -Path "$outputDir\Hashes.csv" -Value "$($file.FullName),$($hash.Hash)"
        }
    }
}
catch {
    Write-Warning "Error calculating hashes for collected files"
    Write-Warning $_.Exception.Message
}

# Compress and Timestamp Output
try {
    $zipFile = "$outputDir.zip"
    Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force
    Remove-Item -Path $outputDir -Recurse -Force
}
catch {
    Write-Warning "Error compressing output directory"
    Write-Warning $_.Exception.Message
}

# Stop logging
Stop-Transcript
