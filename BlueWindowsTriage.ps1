# Parameterize the output directory and log file path
param(
    [string]$outputDir = "C:\\IncidentResponse\\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Ensure the script is running with administrative privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as an Administrator."
    exit
}

# Record the start time
$scriptStartTime = Get-Date

# Create the output directory
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Initialize the log file
$logFile = "$outputDir\\script_log.txt"
Start-Transcript -Path $logFile -Append

# Initialize a mutex for synchronized logging
$logMutex = New-Object System.Threading.Mutex($false, "LogMutex")
$logMutex2 = New-Object System.Threading.Mutex($false, "LogMutex2")
# Global error logging function with batch processing to reduce call depth
function Write-Output-error {
    param (
        [string] $Message,
        [string] $LogFile = "$outputDir\\error_log.txt"
    )
    # Collect errors in a list and log them periodically to avoid frequent I/O operations
    if (-not $global:errorList) {
        $global:errorList = @()
    }
    $global:errorList += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message"
    if ($global:errorList.Count -gt 100) {
        $logMutex.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path $LogFile
            $global:errorList.Clear()
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
}

function Write-Output-log {
    param (
        [string] $Message,
        [string] $LogFile = "$outputDir\\error_log.txt"
    )
    # Collect errors in a list and log them periodically to avoid frequent I/O operations
    if (-not $global:errorList) {
        $global:errorList = @()
    }
    $global:errorList += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message"
    if ($global:errorList.Count -gt 100) {
        $logMutex2.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path $LogFile
            $global:errorList.Clear()
        } finally {
            $logMutex2.ReleaseMutex() | Out-Null
        }
    }
}

# Ensure any remaining errors are logged at the end of the script
function Clear-ErrorLog {
    if ($global:errorList -and $global:errorList.Count -gt 0) {
        $logMutex.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path "$outputDir\\error_log.txt"
            $global:errorList.Clear()
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
}
# Ensure any remaining errors are logged at the end of the script
function Clear-Log {
    if ($global:errorList -and $global:errorList.Count -gt 0) {
        $logMutex2.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path "$outputDir\\error_log.txt"
            $global:errorList.Clear()
        } finally {
            $logMutex2.ReleaseMutex() | Out-Null
        }
    }
}

# Function to calculate file hash with error handling and no recursion
function Get-FileHashSafely {
    param(
        [string]$FilePath,
        [string]$Algorithm = 'SHA256'
    )
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction SilentlyContinue
        return $hash.Hash
    } catch {
        Write-Output-error "Error calculating hash for file: $FilePath - $_"
        return $null
    }
}

function Export-RegistryKey {
    param (
        [string]$keyPath,
        [string]$outputDir
    )

    $logMutex2.WaitOne() | Out-Null
    try {
        Write-Output "Exporting registry key: $keyPath" | Add-Content -Path "$outputDir\\script_log.txt"
    } finally {
        $logMutex2.ReleaseMutex() | Out-Null
    }

    try {
        REG EXPORT $keyPath "$outputDir\\$(($keyPath -replace '\\', '_')).reg" /y
    } catch {
        Write-Output-error "Failed to export registry key: $keyPath. Error: $_"
    }
}

# Script block injected into every background job via -InitializationScript so
# job-scope code can log errors directly. Jobs run in separate processes and
# don't inherit functions defined above, so without this, calls to
# Write-Output-error inside a job silently fail (the function doesn't exist there).
$jobInitScript = {
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")
    function Write-Output-error {
        param([string]$Message, [string]$LogFile)
        $logMutex.WaitOne() | Out-Null
        try {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
}

# Core Parallel Processing
$jobs = @()

# Collect system information
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        # Enumerate installed software from the registry instead of Win32_Product.
        # Win32_Product forces an MSI consistency/self-repair check against every
        # installed package, which can take minutes and has real side effects.
        $installedSoftware = @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue) +
                              @(Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue) |
                              Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, InstallDate

        $systemInfo = @{
            "Hostname"             = $env:COMPUTERNAME
            "OS Version"           = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            "Uptime"               = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            "Installed Software"   = $installedSoftware
            # -IncludeUserName resolves the owning user via a lightweight token
            # lookup instead of a per-process WMI GetOwner() call.
            "Running Processes"    = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Select-Object Name, ID, Path, UserName
            "Network Configuration"= Get-NetIPConfiguration
        }
        $systemInfo | ConvertTo-Json -Depth 4 | Out-File -FilePath "$outputDir\SystemInfo.json"
    } catch {
        Write-Output-error "Error collecting system information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Collect startup items
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location, Name
        $startupItems | ConvertTo-Json | Out-File -FilePath "$outputDir\StartupItems.json"
    } catch {
        Write-Output-error "Error collecting startup items - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Collect information about local users and groups
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $localUsers = Get-LocalUser
        $userInfo = @{
            "Local Users"          = $localUsers | Select-Object Name, Enabled, LastLogon
            "User Groups"          = Get-LocalGroup | Select-Object Name, SID
            "Recent User Accounts" = $localUsers | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
        }
        $userInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\UserInfo.json"
    } catch {
        Write-Output-error "Error collecting user and group information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Collect event logs in parallel
# Collect application logs
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    $tempEvtxPath = "$outputDir\Application_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
    try {
        $events = Get-WinEvent -LogName Application -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        Write-Output-error "Failed to collect Application event logs: $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect security logs
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    $tempEvtxPath = "$outputDir\Security_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        Write-Output-error "Failed to collect Security event logs: $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect system logs
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    $tempEvtxPath = "$outputDir\System__$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
    try {
        $events = Get-WinEvent -LogName System -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        Write-Output-error "Failed to collect System event logs: $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect current network connections
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $networkConnections = Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
        $networkConnections | Export-Csv -Path "$outputDir\\NetworkConnections.csv" -NoTypeInformation
    } catch {
        Write-Output-error "Error collecting network connections - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect registry startup items
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $registryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $registryKeys) {
            $hive = ($key -split ':')[0]
            $keyName = $key.Split("\")[-1]
            $keyValues = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $keyValues | ConvertTo-Json | Out-File -FilePath "$outputDir\Registry_${hive}_${keyName}.json"
        }
    } catch {
        Write-Output-error "Error collecting registry data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Export Shimcache data
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $shimcacheFile = "$outputDir\Shimcache.reg"
        & reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
    } catch {
        Write-Output-error "Error collecting Shimcache data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect recent files from critical directories
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $criticalDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Users\Public")
        foreach ($dir in $criticalDirs) {
            $recentFiles = Get-ChildItem -Path $dir -Recurse -File -ErrorAction Ignore | Where-Object {$_.LastWriteTime -ge (Get-Date).AddHours(-24) -and $_.Extension -ne ".evtx"}
            $recentFiles | Select-Object FullName, LastWriteTime, Length, @{Name="Hash"; Expression={(Get-FileHash -Path $_.FullName).Hash}} | Export-Csv -Path "$outputDir\RecentFiles_$($dir.Replace(':', '').Replace('\', '_')).csv" -NoTypeInformation -ErrorAction Ignore
        }
    } catch {
        Write-Output-error "Error collecting file system data - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir

# Collect cookies from browsers for further analysis
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $cookiePaths = @(
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"
        )
        foreach ($path in $cookiePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir -Force
        }
    } catch {
        Write-Output-error "Error collecting browser cookies - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Collect scheduled tasks information
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        $scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Actions
        $scheduledTasks | ConvertTo-Json | Out-File -FilePath "$outputDir\ScheduledTasks.json"
    } catch {
        Write-Output-error "Error collecting scheduled tasks - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Gather detailed information about services, including their status and configs
$jobs += Start-Job -InitializationScript $jobInitScript -ScriptBlock {
    param($outputDir)

    try {
        # Look up all service paths in a single bulk CIM call instead of
        # issuing a separate WMI query per service (N+1 query pattern).
        $servicePaths = @{}
        Get-CimInstance -ClassName Win32_Service | ForEach-Object { $servicePaths[$_.Name] = $_.PathName }
        $servicesInfo = Get-Service | Select-Object Name, DisplayName, Status, StartType, @{Name="Path";Expression={$servicePaths[$_.Name]}}
        $servicesInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\ServicesInfo.json"
    } catch {
        Write-Output-error "Error collecting service information - $_" "$outputDir\error_log.txt"
    }
} -ArgumentList $outputDir


# Wait for all jobs to complete
$jobs | ForEach-Object { $_ | Wait-Job | Receive-Job }
$jobs | Remove-Job

# Firefox Extension Collection
try {
    $firefoxExtensionsPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\extensions"
    $firefoxExtensions = Get-ChildItem -Path $firefoxExtensionsPath -Recurse -Directory -ErrorAction SilentlyContinue
    $firefoxExtensions | ForEach-Object {
        $manifestPath = "$($_.FullName)\\manifest.json"
        if (Test-Path -Path $manifestPath) {
            $extensionInfo = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
            [PSCustomObject]@{
                Id = $_.Name
                Name = $extensionInfo.name
                Version = $extensionInfo.version
                Description = $extensionInfo.description
            }
        }
    } | ForEach-Object {
        $_ | Out-File -FilePath "$outputDir\\FirefoxExtensions.txt" -Append -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Firefox extensions - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}


# Google Chrome Extension Collection
try {
    $chromeExtensionsPath = "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions"
    $chromeExtensions = Get-ChildItem -Path $chromeExtensionsPath -Recurse -Directory -ErrorAction SilentlyContinue
    $chromeExtensions | ForEach-Object {
        $manifestPath = "$($_.FullName)\\manifest.json"
        if (Test-Path -Path $manifestPath) {
            $extensionInfo = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
            [PSCustomObject]@{
                Id = $_.Name
                Name = $extensionInfo.name
                Version = $extensionInfo.version
                Description = $extensionInfo.description
            } | Out-File -FilePath "$outputDir\\ChromeExtensions.txt" -Append -Force
        }
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Google Chrome extensions - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Chrome History Collection
try {
    $chromeHistoryPath = "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
    $chromeHistoryFiles = Get-ChildItem -Path $chromeHistoryPath -ErrorAction SilentlyContinue
    $chromeHistoryFiles | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$outputDir\\ChromeHistory" -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Chrome history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}


# Firefox History Collection
try {
    $firefoxHistoryPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite"
    $firefoxHistoryFiles = Get-ChildItem -Path $firefoxHistoryPath -ErrorAction SilentlyContinue
    $firefoxHistoryFiles | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$outputDir\\FirefoxHistory" -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Firefox history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}


# Microsoft Edge History Collection
try {
    $edgeHistoryPath = "C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
    $edgeHistoryFiles = Get-ChildItem -Path $edgeHistoryPath -ErrorAction SilentlyContinue
    $edgeHistoryFiles | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$outputDir\\EdgeHistory.sqlite" -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Microsoft Edge history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Search for Password Files
try {
    $passwordFiles = Get-ChildItem -Path "C:\\Users\\*\\Documents\\*password*" -Recurse -ErrorAction SilentlyContinue
    $passwordFiles | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$outputDir\\PasswordFiles" -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error searching for password files - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# User PowerShell History Collection
try {
    $powershellHistoryPath = "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
    $powershellHistoryFiles = Get-ChildItem -Path $powershellHistoryPath -ErrorAction SilentlyContinue
    $powershellHistoryFiles | ForEach-Object {
        $destinationPath = "$outputDir\\$($_.Directory.Name)"
        New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
        Copy-Item -Path $_.FullName -Destination $destinationPath -Force
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting PowerShell history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Prefetch Files Collection
try {
    # Create a subdirectory for prefetch files
    $prefetchDir = "$outputDir\\PreFetch"
    New-Item -ItemType Directory -Path $prefetchDir -Force | Out-Null

    # Collect prefetch files
    $prefetchFiles = Get-ChildItem -Path "C:\\Windows\\Prefetch" -ErrorAction SilentlyContinue
    $prefetchFiles | Copy-Item -Destination $prefetchDir -Force
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting prefetch files - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Jump Lists Collection
try {
    $jumpListFiles = Get-ChildItem -Path "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations" -ErrorAction SilentlyContinue
    $jumpListFiles | Copy-Item -Destination "$outputDir\\JumpLists" -Force
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting jump list files - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Windows Timeline Collection
try {
    $timelineRegistry = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ActivityDataModel"
#    $timelineRegistryFile = "$outputDir\\Timeline.reg"
    Export-RegistryKey -keyPath $timelineRegistry -outputDir $outputDir
    $timelineFiles = Get-ChildItem -Path "C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db" -ErrorAction SilentlyContinue
    $timelineFiles | Copy-Item -Destination "$outputDir\\WindowsTimeline" -Force
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Windows Timeline data - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Hashing of Collected Files
try {
    $collectedFiles = Get-ChildItem -Path $outputDir -File -Recurse
    # Buffer hash results and write them out once instead of taking the mutex
    # and opening/closing the CSV for every single file.
    $hashLines = New-Object System.Collections.Generic.List[string]
    foreach ($file in $collectedFiles) {
        $hash = Get-FileHashSafely -FilePath $file.FullName
        if ($hash) {
            $hashLines.Add("$($file.FullName),$hash")
        }
    }
    if ($hashLines.Count -gt 0) {
        $logMutex.WaitOne() | Out-Null
        try {
            Add-Content -Path "$outputDir\\Hashes.csv" -Value $hashLines
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error calculating hashes for collected files - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Compress the output directory directly into a zip file in the parent
# directory. (Previously this copied the entire output directory into a
# sibling temp folder first, then zipped that copy - doubling disk I/O and
# time for no benefit, since Compress-Archive can zip the source in place.)
$parentDirectory = Split-Path -Path $outputDir -Parent
$zipFileName = "IR-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
$zipFilePath = "$parentDirectory\$zipFileName"
$zipParams = @{
    path = $outputDir
    destinationPath = $zipFilePath
    CompressionLevel = "Optimal"
}
Compress-Archive @zipParams

# Check if the zip file was created successfully
if (Test-Path $zipFilePath) {
    $logMutex2.WaitOne() | Out-Null
    try {
        Write-Output "Backup created successfully: $zipFilePath" | Add-Content -Path "$outputDir\script_log.txt"
    } finally {
        $logMutex2.ReleaseMutex() | Out-Null
    }
} else {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Zip file was not created. - $_" "$outputDir\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Stop logging
Stop-Transcript | Out-Null

# Calculate and log total script execution time in a readable format
$scriptEndTime = Get-Date
$executionTime = $scriptEndTime - $scriptStartTime

# Translate execution time to a readable format
$days = $executionTime.Days
$hours = $executionTime.Hours
$minutes = $executionTime.Minutes
$seconds = $executionTime.Seconds
$readableExecutionTime = "$days days, $hours hours, $minutes minutes, $seconds seconds"

$logMutex2.WaitOne() | Out-Null
try {
    Write-Output "Total script execution time: $readableExecutionTime" | Add-Content -Path "$outputDir\script_log.txt"
} finally {
    $logMutex2.ReleaseMutex() | Out-Null
}
Clear-ErrorLog
