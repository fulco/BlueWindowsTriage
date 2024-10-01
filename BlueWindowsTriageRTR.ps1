# Parameterize the output directory
param(
    [string]$outputDir = "C:\IncidentResponse\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as an Administrator."
    exit
}

# Record the start time
$scriptStartTime = Get-Date

# Create the output directory
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Initialize the log file
$logFile = Join-Path $outputDir "script_log.txt"
Start-Transcript -Path $logFile -Append

# Initialize error logging functions
$global:errorList = @()
function Write-ErrorLog {
    param (
        [string] $Message,
        [string] $LogFile = (Join-Path $outputDir "error_log.txt")
    )
    $errorEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message"
    $global:errorList += $errorEntry
    if ($global:errorList.Count -gt 100) {
        $global:errorList | Add-Content -Path $LogFile
        $global:errorList = @()
    }
}

function Clear-ErrorLog {
    if ($global:errorList.Count -gt 0) {
        $global:errorList | Add-Content -Path (Join-Path $outputDir "error_log.txt")
        $global:errorList = @()
    }
}

# Function to calculate file hash with error handling
function Get-FileHashSafely {
    param(
        [string]$FilePath,
        [string]$Algorithm = 'SHA256'
    )
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash
    } catch {
        Write-ErrorLog "Error calculating hash for file: $FilePath - $_"
        return $null
    }
}

# Function to copy items maintaining directory structure
function Copy-ItemWithHierarchy {
    param (
        [string]$source,
        [string]$destination
    )
    try {
        Get-ChildItem -Path $source -Recurse | ForEach-Object {
            $relativePath = $_.FullName.Substring($source.Length)
            $targetPath = Join-Path $destination $relativePath
            if ($_.PSIsContainer) {
                New-Item -ItemType Directory -Path $targetPath -Force -ErrorAction SilentlyContinue | Out-Null
            } else {
                $targetDir = Split-Path -Path $targetPath -Parent
                if (-not (Test-Path -Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-ErrorLog "Error copying items from $source to $destination - $_"
    }
}

# Detect Windows version
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [Version]$os.Version
    $valueBasedOnOS = switch ($osVersion.Major) {
        10 { if ($osVersion.Minor -eq 0) { "Windows 10" } else { "Windows 11" } }
        6 { switch ($osVersion.Minor) {
                3 { "Windows 8.1" }
                2 { "Windows 8" }
                1 { "Windows 7" }
                0 { "Windows Vista" }
            }
        }
        5 { "Windows XP" }
        default { "Unknown OS Version" }
    }
    # Output the value
    "Windows Version: $valueBasedOnOS" | Add-Content -Path (Join-Path $outputDir "winver_log.txt")
} catch {
    Write-ErrorLog "Error detecting Windows version - $_"
}

# Create subdirectories
$subDirs = @("CE", "FF", "BB", "PreFetch", "JumpLists", "PasswordFiles")
$subDirs | ForEach-Object {
    try {
        New-Item -ItemType Directory -Path (Join-Path $outputDir $_) -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-ErrorLog "Error creating subdirectory $_ - $_"
    }
}

# Brave Browser Check
try {
    $braveInstalled = Test-Path "HKLM:\Software\BraveSoftware"
    if ($braveInstalled) {
        "Brave Browser is installed" | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
    } else {
        "Brave Browser is not installed." | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
    }
} catch {
    Write-ErrorLog "Error checking for Brave browser - $_"
}

# Functions for each data collection task

function Get-SystemInfo {
    param($outputDir)
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $uptime = (Get-Date) - $osInfo.LastBootUpTime

        $installedSoftware = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*) +
                             @(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*)
        $installedSoftware = $installedSoftware | Select-Object DisplayName, DisplayVersion, InstallDate | Where-Object { $_.DisplayName }

        $runningProcesses = Get-Process | Select-Object Name, ID, Path

        $systemInfo = @{
            "Hostname" = $env:COMPUTERNAME
            "OS Version" = $osInfo.Caption
            "Uptime" = $uptime
            "Installed Software" = $installedSoftware
            "Running Processes" = $runningProcesses
        }
        $systemInfo | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $outputDir "SystemInfo.json")
    } catch {
        Write-ErrorLog "Error collecting system information - $_"
    }
}

function Get-StartupItems {
    param($outputDir)
    try {
        $startupLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        $startupItems = @()
        foreach ($location in $startupLocations) {
            $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue | Select-Object *
            if ($items) {
                $startupItems += $items
            }
        }
        $startupItems | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "StartupItems.json")
    } catch {
        Write-ErrorLog "Error collecting startup items - $_"
    }
}

function Get-UserInfo {
    param($outputDir)
    try {
        $localUsers = net user | Select-String -Pattern '^---' -Context 0,1000 | ForEach-Object {
            $_.Context.PostContext | Where-Object { $_ -match '\S' }
        }

        $localGroups = net localgroup | Select-String -Pattern '^---' -Context 0,1000 | ForEach-Object {
            $_.Context.PostContext | Where-Object { $_ -match '\S' }
        }

        $userInfo = @{
            "Local Users" = $localUsers
            "Local Groups" = $localGroups
        }
        $userInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "UserInfo.json")
    } catch {
        Write-ErrorLog "Error collecting user and group information - $_"
    }
}

function Get-EventLogs {
    param($outputDir)
    $eventLogs = @("Application", "Security", "System")
    foreach ($logName in $eventLogs) {
        try {
            $events = Get-EventLog -LogName $logName -Newest 1500 -ErrorAction Stop
            if ($events -and $events.Count -gt 0) {
                $events | Export-Clixml -Path (Join-Path $outputDir "${logName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml")
            } else {
                Write-ErrorLog "No events found in $logName log"
            }
        } catch {
            Write-ErrorLog "Failed to collect $logName event logs: $_"
        }
    }
}

function Get-NetworkConnections {
    param($outputDir)
    try {
        $netstatOutput = netstat -ano
        $netstatOutput | Out-File -FilePath (Join-Path $outputDir "NetworkConnections.txt")
    } catch {
        Write-ErrorLog "Error collecting network connections - $_"
    }
}

function Get-RegistryStartupItems {
    param($outputDir)
    try {
        $registryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $registryKeys) {
            $keyName = ($key -split '\\')[-1]
            $keyValues = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Select-Object *
            if ($keyValues) {
                $keyValues | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "Registry_$keyName.json")
            }
        }
    } catch {
        Write-ErrorLog "Error collecting registry startup items - $_"
    }
}

function Get-ShimcacheData {
    param($outputDir)
    try {
        $shimcacheFile = Join-Path $outputDir "Shimcache.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
    } catch {
        Write-ErrorLog "Error collecting Shimcache data - $_"
    }
}

function Get-BrowserData {
    param($outputDir)
    try {
        # Firefox data
        $ffPath = Join-Path $outputDir "FF"
        $firefoxPaths = @(
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\places.sqlite",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\bookmarkbackups\*.jsonlz4",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json"
        )
        foreach ($path in $firefoxPaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $destinationFile = Join-Path $ffPath ($_.Name + "_" + (Get-Random))
                Copy-Item -Path $_.FullName -Destination $destinationFile -Force -ErrorAction SilentlyContinue
            }
        }

        # Chrome data
        $cePath = Join-Path $outputDir "CE"
        $chromePaths = @(
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Bookmarks",
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Web Data"
        )
        foreach ($path in $chromePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $destinationFile = Join-Path $cePath ($_.Name + "_" + (Get-Random))
                Copy-Item -Path $_.FullName -Destination $destinationFile -Force -ErrorAction SilentlyContinue
            }
        }

        # Edge data
        $edgePaths = @(
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Web Data"
        )
        foreach ($path in $edgePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $destinationFile = Join-Path $cePath ($_.Name + "_Edge_" + (Get-Random))
                Copy-Item -Path $_.FullName -Destination $destinationFile -Force -ErrorAction SilentlyContinue
            }
        }

        # Brave Browser artifacts if installed
        if ($braveInstalled) {
            $bboutputDir = Join-Path $outputDir "BB"
            $sourcePath = "C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
            Copy-ItemWithHierarchy -source $sourcePath -destination $bboutputDir
            "Brave Browser artifacts have been copied to $bboutputDir" | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
        }
    } catch {
        Write-ErrorLog "Error collecting browser data - $_"
    }
}

function Get-BrowserExtensions {
    param($outputDir)
    try {
        # Firefox extensions
        $firefoxExtensionsPath = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\extensions"
        $firefoxExtensions = Get-ChildItem -Path $firefoxExtensionsPath -Recurse -Directory -ErrorAction SilentlyContinue
        $ffExtFile = Join-Path $outputDir "FirefoxExtensions.txt"
        foreach ($ext in $firefoxExtensions) {
            $manifestPath = Join-Path $ext.FullName "manifest.json"
            if (Test-Path -Path $manifestPath) {
                $extensionInfo = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                [PSCustomObject]@{
                    Id = $ext.Name
                    Name = $extensionInfo.name
                    Version = $extensionInfo.version
                    Description = $extensionInfo.description
                } | Out-File -FilePath $ffExtFile -Append
            }
        }

        # Chrome and Edge extensions
        $browserPaths = @(
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\*\*",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\*\*"
        )
        $ceExtFile = Join-Path $outputDir "ChromeEdgeExtensions.txt"
        foreach ($path in $browserPaths) {
            Get-ChildItem -Path $path -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path -Path $manifestPath) {
                    $extensionInfo = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                    [PSCustomObject]@{
                        Id = $_.Name
                        Name = $extensionInfo.name
                        Version = $extensionInfo.version
                        Description = $extensionInfo.description
                    } | Out-File -FilePath $ceExtFile -Append
                }
            }
        }
    } catch {
        Write-ErrorLog "Error collecting browser extensions - $_"
    }
}

function Get-AdditionalArtifacts {
    param($outputDir)
    try {
        # Password files
        $passwordFiles = Get-ChildItem -Path "C:\Users\*\Documents\*password*" -Recurse -ErrorAction SilentlyContinue
        if ($passwordFiles) {
            $passwordDir = Join-Path $outputDir "PasswordFiles"
            foreach ($file in $passwordFiles) {
                $destPath = Join-Path $passwordDir ($file.Name + "_" + (Get-Random))
                Copy-Item -Path $file.FullName -Destination $destPath -Force -ErrorAction SilentlyContinue
            }
        }

        # PowerShell history
        $powershellHistoryPath = "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        Get-ChildItem -Path $powershellHistoryPath -ErrorAction SilentlyContinue | ForEach-Object {
            $destinationPath = Join-Path $outputDir "PowerShellHistory" ($_.Directory.Name)
            if (-not (Test-Path -Path $destinationPath)) {
                New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
            }
            Copy-Item -Path $_.FullName -Destination $destinationPath -Force -ErrorAction SilentlyContinue
        }

        # Prefetch files
        $prefetchDir = Join-Path $outputDir "PreFetch"
        Get-ChildItem -Path "C:\Windows\Prefetch\*" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $prefetchDir -Force -ErrorAction SilentlyContinue
        }

        # Jump Lists
        $jumpListFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" -ErrorAction SilentlyContinue
        $jumpListDir = Join-Path $outputDir "JumpLists"
        foreach ($file in $jumpListFiles) {
            Copy-Item -Path $file.FullName -Destination $jumpListDir -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-ErrorLog "Error collecting additional artifacts - $_"
    }
}

function Get-FileHashes {
    param($outputDir)
    try {
        $collectedFiles = Get-ChildItem -Path $outputDir -File -Recurse -ErrorAction Stop
        $hashes = @()
        foreach ($file in $collectedFiles) {
            $hash = Get-FileHashSafely -FilePath $file.FullName
            if ($hash) {
                $hashes += [PSCustomObject]@{
                    FilePath = $file.FullName
                    Hash = $hash
                }
            }
        }
        if ($hashes.Count -gt 0) {
            $hashes | Export-Csv -Path (Join-Path $outputDir "Hashes.csv") -NoTypeInformation
        } else {
            Write-ErrorLog "No file hashes were generated"
        }
    } catch {
        Write-ErrorLog "Error during file hashing: $_"
    }
}

# Now, call the functions sequentially

Get-SystemInfo -outputDir $outputDir
Get-StartupItems -outputDir $outputDir
Get-UserInfo -outputDir $outputDir
Get-EventLogs -outputDir $outputDir
Get-NetworkConnections -outputDir $outputDir
Get-RegistryStartupItems -outputDir $outputDir
Get-ShimcacheData -outputDir $outputDir
Get-BrowserData -outputDir $outputDir
Get-BrowserExtensions -outputDir $outputDir
Get-AdditionalArtifacts -outputDir $outputDir
Get-FileHashes -outputDir $outputDir

# Create backup
try {
    $parentDirectory = Split-Path -Path $outputDir -Parent
    $zipFileName = "IR-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    $zipFilePath = Join-Path $parentDirectory $zipFileName
    Compress-Archive -Path $outputDir -DestinationPath $zipFilePath -CompressionLevel Optimal
    if (Test-Path $zipFilePath) {
        #"Backup created successfully: $zipFilePath" | Add-Content -Path (Join-Path $outputDir "script_log.txt")
    } else {
        Write-ErrorLog "Zip file was not created."
    }
} catch {
    Write-ErrorLog "Error creating backup zip file - $_"
}

# Stop logging
Stop-Transcript

# Calculate and log total script execution time
$scriptEndTime = Get-Date
$executionTime = $scriptEndTime - $scriptStartTime
$readableExecutionTime = "{0:dd} days {0:hh} hours {0:mm} minutes {0:ss} seconds" -f $executionTime

"Total script execution time: $readableExecutionTime" | Add-Content -Path (Join-Path $outputDir "script_log.txt")

# Final error log flush
Clear-ErrorLog
