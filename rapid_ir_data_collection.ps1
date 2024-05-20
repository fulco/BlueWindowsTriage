# Ensure the script is running with administrative privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as an Administrator."
    exit
}

# Parameterize the output directory and log file path
param(
    [string]$outputDir = "C:\IncidentResponse\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Create the output directory
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Initialize the log file
$logFile = "$outputDir\script_log.txt"
Start-Transcript -Path $logFile -Append

# Global error logging function
function Write-Output-error  {
    param (
        [string] $Message,
        [string] $LogFile = "$outputDir\error_log.txt"
    )
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message"
}

# Function to calculate file hash
function Get-FileHash {
    param(
        [string]$FilePath,
        [string]$Algorithm = 'SHA256'
    )
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash
    } catch {
        Write-Output-error  "Error calculating hash for file: $FilePath - $_"
        return $null
    }
}

# Core Parallel Processing
$jobs = @()

# Collect system information
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $systemInfo = @{
            "Hostname"             = $env:COMPUTERNAME
            "OS Version"           = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            "Uptime"               = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            "Installed Software"   = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
            "Running Processes"    = Get-Process | Select-Object Name, ID, Path, @{Name="User";Expression={$_.GetOwner().User}}
            "Network Configuration"= Get-NetIPConfiguration
        }
        $systemInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\SystemInfo.json"
    } catch {
        Write-Output-error  "Error collecting system information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect startup items
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location, Name
        $startupItems | ConvertTo-Json | Out-File -FilePath "$outputDir\StartupItems.json"
    } catch {
        Write-Output-error  "Error collecting startup items - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect information about local users and groups
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $userInfo = @{
            "Local Users"        = Get-LocalUser | Select-Object Name, Enabled, LastLogon
            "User Groups"        = Get-LocalGroup | Select-Object Name, SID
            "Recent User Accounts"= Get-LocalUser | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
        }
        $userInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\UserInfo.json"
    } catch {
        Write-Output-error  "Error collecting user and group information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect event logs for the last 24 hours in parallel
$eventLogs = @("Security", "Application", "System")
$logScriptBlock = {
    param($logName, $outputDir)
    try {
        $startTime = (Get-Date).AddHours(-24)
        $events = Get-WinEvent -FilterHashtable @{LogName = $logName; StartTime = $startTime} -ErrorAction SilentlyContinue
        $events | Export-Csv -Path "$outputDir\${logName}.csv" -NoTypeInformation
    } catch {
        Write-Output-error "Error collecting event logs for $logName - $_" "$outputDir\error_log.txt"
    }
}
foreach ($log in $eventLogs) {
    Start-Job -ScriptBlock $logScriptBlock -ArgumentList $log, $outputDir
}

# Collect current network connections
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $networkConnections | ConvertTo-Json | Out-File -FilePath "$outputDir\NetworkConnections.json"
    } catch {
        Write-Output-error  "Error collecting network connections - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect registry startup items
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
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
    } catch {
        Write-Output-error  "Error collecting registry data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Export Shimcache data
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $shimcacheFile = "$outputDir\Shimcache.reg"
        & reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
    } catch {
        Write-Output-error  "Error collecting Shimcache data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect recent files from critical directories
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $criticalDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Users\Public")
        foreach ($dir in $criticalDirs) {
            $recentFiles = Get-ChildItem -Path $dir -Recurse -File | Where-Object {$_.LastWriteTime -ge (Get-Date).AddHours(-24)}
            $recentFiles | Select-Object FullName, LastWriteTime, Length, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName).Hash}} | Export-Csv -Path "$outputDir\RecentFiles_$($dir.Replace(':', '').Replace('\', '_')).csv" -NoTypeInformation
        }
    } catch {
        Write-Output-error  "Error collecting file system data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect cookies from browsers for further analysis
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $cookiePaths = @(
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"
        )
        foreach ($path in $cookiePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Copy-Item -Destination $using:outputDir -Force
        }
    } catch {
        Write-Output-error  "Error collecting browser cookies - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect scheduled tasks information
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Actions
        $scheduledTasks | ConvertTo-Json | Out-File -FilePath "$outputDir\ScheduledTasks.json"
    } catch {
        Write-Output-error  "Error collecting scheduled tasks - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Gather detailed information about services, including their status and configs
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    try {
        $servicesInfo = Get-Service | Select-Object Name, DisplayName, Status, StartType, @{Name="Path";Expression={(Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").PathName}}
        $servicesInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\ServicesInfo.json"
    } catch {
        Write-Output-error  "Error collecting service information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Wait for all jobs to complete and collect their output
$jobs | Wait-Job | Receive-Job
$jobs | Remove-Job

# Artifact collection
try {
    $artifactDirs = @(
        "C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History"
    )
    foreach ($dir in $artifactDirs) {
        $artifacts = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue
        if ($artifacts) {
            $artifacts | Copy-Item -Destination $outputDir -Force
        }
    }
} catch {
    Write-Output-error  "Error collecting artifact data - $_" "$outputDir\error_log.txt"
}

# Firefox Extension Collection
try {
    $firefoxExtensions = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*" -ErrorAction SilentlyContinue
    $firefoxExtensions | Select-Object FullName | ConvertTo-Json | Out-File -FilePath "$outputDir\FirefoxExtensions.json"
} catch {
    Write-Output-error  "Error collecting Firefox extensions - $_" "$outputDir\error_log.txt"
}

# Google Chrome Extension Collection
try {
    $UserPaths = (Get-WmiObject win32_userprofile | Where-Object localpath -notmatch 'Windows').localpath
    foreach ($Path in $UserPaths) {
        $ExtPath = $Path + '\AppData\Local\Google\Chrome\User Data\Default\Extensions'
        if (Test-Path $ExtPath) {
            $ExtFolders = Get-ChildItem $ExtPath | Where-Object Name -ne 'Temp'
            foreach ($Folder in $ExtFolders) {
                $VerFolders = Get-ChildItem $Folder.FullName
                foreach ($Version in $VerFolders) {
                    if (Test-Path -Path ($Version.FullName + '\manifest.json')) {
                        $Manifest = Get-Content ($Version.FullName + '\manifest.json') | ConvertFrom-Json
                        if ($Manifest.name -like '__MSG*') {
                            $AppId = ($Manifest.name -replace '__MSG_', '').Trim('_')
                            @('\_locales\en_US\', '\_locales\en\') | ForEach-Object {
                                if (Test-Path -Path ($Version.Fullname + $_ + 'messages.json')) {
                                    $AppManifest = Get-Content ($Version.Fullname + $_ + 'messages.json') | ConvertFrom-Json
                                    @($AppManifest.appName.message, $AppManifest.extName.message, $AppManifest.extensionName.message, $AppManifest.app_name.message, $AppManifest.application_title.message, $AppManifest.$AppId.message) | ForEach-Object {
                                        if (($_) -and (-not($ExtName))) {
                                            $ExtName = $_
                                        }
                                    }
                                }
                            }
                        } else {
                            $ExtName = $Manifest.name
                        }
                        Write-Output (($Path | Split-Path -Leaf) + ": " + [string] $ExtName + " v" + $Manifest.version + " (" + $Folder.name + ")")
                        if ($ExtName) {
                            Remove-Variable -Name ExtName
                        }
                    }
                }
            }
        }
    }
} catch {
    Write-Output-error  "Error collecting Google Chrome extensions - $_" "$outputDir\error_log.txt"
}

# Chrome History Collection
try {
    $chromeHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue
    $chromeHistoryFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting Chrome history - $_" "$outputDir\error_log.txt"
}

# Firefox History Collection
try {
    $firefoxHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite" -ErrorAction SilentlyContinue
    $firefoxHistoryFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting Firefox history - $_" "$outputDir\error_log.txt"
}

# Microsoft Edge History Collection
try {
    $edgeHistoryFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History" -ErrorAction SilentlyContinue
    $edgeHistoryFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting Microsoft Edge history - $_" "$outputDir\error_log.txt"
}

# Search for Password Files
try {
    $passwordFiles = Get-ChildItem -Path C:\ -Include *password* -File -Recurse -ErrorAction SilentlyContinue
    $passwordFiles | Select-Object FullName, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName).Hash}} | ConvertTo-Json | Out-File -FilePath "$outputDir\PasswordFiles.json"
} catch {
    Write-Output-error  "Error searching for password files - $_" "$outputDir\error_log.txt"
}

# User PowerShell History
try {
    $Users = (Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
    $Pasts = @($Users)
    foreach ($Past in $Pasts) {
        Write-Host "`n----User Pwsh History Path $Past---" -ForegroundColor Magenta
        Get-Content $Past | Out-File -FilePath "$outputDir\PowerShellHistory_$($Past.Split('\')[-2]).txt"
    }
} catch {
    Write-Output-error  "Error collecting user PowerShell history - $_" "$outputDir\error_log.txt"
}

# Prefetch Files Collection
try {
    $prefetchFiles = Get-ChildItem -Path "C:\Windows\Prefetch" -ErrorAction SilentlyContinue
    $prefetchFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting prefetch files - $_" "$outputDir\error_log.txt"
}

# Jump Lists Collection
try {
    $jumpListFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -ErrorAction SilentlyContinue
    $jumpListFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting jump list files - $_" "$outputDir\error_log.txt"
}

# Windows Timeline Collection
try {
    $timelineRegistry = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityDataModel"
    $timelineRegistryFile = "$outputDir\Timeline.reg"
    & reg export $timelineRegistry $timelineRegistryFile /y
    $timelineFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -ErrorAction SilentlyContinue
    $timelineFiles | Copy-Item -Destination $outputDir -Force
} catch {
    Write-Output-error  "Error collecting Windows Timeline data - $_" "$outputDir\error_log.txt"
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
} catch {
    Write-Output-error  "Error calculating hashes for collected files - $_" "$outputDir\error_log.txt"
}

# Compress and Timestamp Output
try {
    $zipFile = "$outputDir.zip"
    Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force
    Remove-Item -Path $outputDir -Recurse -Force
} catch {
    Write-Output-error  "Error compressing output directory - $_" "$outputDir\error_log.txt"
}

# Stop logging
Stop-Transcript
