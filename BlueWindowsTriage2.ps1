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
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error calculating hash for file: $FilePath - $_"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
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
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output "Failed to export registry key: $keyPath. Error: $_" | Add-Content -Path "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
}

# Detect Windows version
# Get the OS version information
$os = Get-CimInstance -ClassName Win32_OperatingSystem

# Extract the version number
$osVersion = [Version]$os.Version

# Initialize the variable to hold the value based on OS version
$valueBasedOnOS = ""

# Conditional logic to set the value based on the OS version
if ($osVersion.Major -eq 10) {
    if ($osVersion.Minor -eq 0) {
        $valueBasedOnOS = "Windows 10"
    } elseif ($osVersion.Minor -eq 1) {
        $valueBasedOnOS = "Windows 11"
    }
} elseif ($osVersion.Major -eq 6) {
    switch ($osVersion.Minor) {
        3 { $valueBasedOnOS = "Windows 8.1" }
        2 { $valueBasedOnOS = "Windows 8" }
        1 { $valueBasedOnOS = "Windows 7" }
        0 { $valueBasedOnOS = "Windows Vista" }
    }
} elseif ($osVersion.Major -eq 5) {
    $valueBasedOnOS = "Windows XP"
}else {
    $valueBasedOnOS = "Unknown OS Version"
}

# Output the value
Write-Output "Windows Version: $valueBasedOnOS" | Add-Content -Path "$outputDir\\winver_log.txt"

# FireFox Version Collection
# Define the registry path
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
# Initialize variable for Firefox version
$firefoxVersion = ""
$firefoxVersion = Get-ChildItem -Path "$registryPath" | Where-Object { $_.PSChildName -like "Mozilla *" } | ForEach-Object { Get-ItemProperty -Path $_.PSPath } | Select-Object -Property DisplayVersion

# Remove unwanted parts of the string
$ffversion = $firefoxVersion -replace "@{DisplayVersion=", "" -replace "}", ""

# Output the extracted version
Write-Output "FFVersion: $ffversion" | Add-Content -Path "$outputDir\\ff_log.txt"

# Core Parallel Processing
$jobs = @()

# Collect system information
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $systemInfo = @{
            "Hostname"             = $env:COMPUTERNAME
            "OS Version"           = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            "Uptime"               = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            "Installed Software"   = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
            "Running Processes"    = Get-Process | Select-Object Name, ID, Path, @{Name="User";Expression={$_.GetOwner().User}}, @{Name="ExecutablePath";Expression={$_.Path}}
            "Network Configuration"= Get-NetIPConfiguration
        }
        $systemInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\SystemInfo.json"
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting system information - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Collect startup items
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location, Name
        $startupItems | ConvertTo-Json | Out-File -FilePath "$outputDir\StartupItems.json"
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting startup items - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Collect information about local users and groups
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $userInfo = @{
            "Local Users"        = Get-LocalUser | Select-Object Name, Enabled, LastLogon
            "User Groups"        = Get-LocalGroup | Select-Object Name, SID
            "Recent User Accounts"= Get-LocalUser | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
        }
        $userInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\UserInfo.json"
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting user and group information - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Collect event logs in parallel
# Collect application logs
$jobs += Start-Job -ScriptBlock {
    param($outputDir)

    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")
    $tempEvtxPath = "$outputDir\Application_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    try {
        $events = Get-WinEvent -LogName Application -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output "Failed to collect Application event logs: $_" | Add-Content -Path "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir

# Collect security logs
$jobs += Start-Job -ScriptBlock {
    param($outputDir)

    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")
    $tempEvtxPath = "$outputDir\Security_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output "Failed to collect Security event logs: $_" | Add-Content -Path "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir

# Collect system logs
$jobs += Start-Job -ScriptBlock {
    param($outputDir)

    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")
    $tempEvtxPath = "$outputDir\System__$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    try {
        $events = Get-WinEvent -LogName System -MaxEvents 1500
        $events | Export-Clixml -Path $tempEvtxPath
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output "Failed to collect System event logs: $_" | Add-Content -Path "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir

# Collect current network connections
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $networkConnections = Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
        $networkConnections | Export-Csv -Path "$outputDir\\NetworkConnections.csv" -NoTypeInformation
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting network connections - $_"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir

# Collect registry startup items
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")
	$i = 1
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
            $keyValues | ConvertTo-Json | Out-File -FilePath "$outputDir\Registry_$keyName$1.json"
			$i++
        }
    } catch {
		$i++
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting registry data - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Export Shimcache data
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $shimcacheFile = "$outputDir\Shimcache.reg"
        & reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting Shimcache data - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir

# Collect FF browser history and bookmark based on OS version
if ($valueBasedOnOS -eq "Windows XP") {
    $firefoxHistoryPath = "C:\\Documents and Settings\\*\\Application Data\Mozilla\Firefox\Profiles\*\places.sqlite"
    $firefoxHistoryPath2 = "C:\\Documents and Settings\\*\\Application Data\Mozilla\Firefox\Profiles\*\bookmarkbackups\*.jsonlz4"
    try {
        Get-ChildItem $firefoxHistoryPath $path -ErrorAction Stop | Copy-Item -Destination $outputDir\\FFplaces.sqlite -Force
        Get-ChildItem $firefoxHistoryPath2 $path -ErrorAction Stop | Copy-Item -Destination $outputDir\\FFBookmarks.jsonlz4 -Force
    } catch {
        Write-Output-error "Error collecting FF1 browser history: $_" "$outputDir\error_log.txt"
    }
} elseif ($valueBasedOnOS -eq "Unknown OS Version" -or $valueBasedOnOS -eq "") {
    Write-Output-error "Error collecting FF0 browser history due to OS version - $_" "$outputDir\error_log.txt"
} elseif($valueBasedOnOS -eq "Windows Vista" -or $valueBasedOnOS -eq "Windows 7" -or $valueBasedOnOS -eq "Windows 8" -or $valueBasedOnOS -eq "Windows 8.1" -or $valueBasedOnOS -eq "Windows 10" -or $valueBasedOnOS -eq "Windows 11") {
    $firefoxHistoryPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\places.sqlite"
    $firefoxHistoryPath2 = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\bookmarkbackups\*.jsonlz4"
    try {
        Get-ChildItem $firefoxHistoryPath $path -ErrorAction Stop | Copy-Item -Destination $outputDir\\FFplaces.sqlite -Force
        Get-ChildItem $firefoxHistoryPath2 $path -ErrorAction Stop | Copy-Item -Destination $outputDir\\FFBookmarks.jsonlz4 -Force
    } catch {
        Write-Output-error "Error collecting FF2 browser history: $_" "$outputDir\error_log.txt"
    }
} else {
    Write-Output-error "Error collecting FF3 browser history - $_" "$outputDir\error_log.txt"
}

# Collect cookies from browsers for further analysis
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $cookiePaths = @(
            "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"
        )
        $c = 1
        foreach ($path in $cookiePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\cookies$c.sqlite -Force
            $c++
        }
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting browser cookies - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Collect scheduled tasks information
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Actions
        $scheduledTasks | ConvertTo-Json | Out-File -FilePath "$outputDir\ScheduledTasks.json"
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting scheduled tasks - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Gather detailed information about services, including their status and configs
$jobs += Start-Job -ScriptBlock {
    param($outputDir)
    
    # Initialize a mutex for synchronized logging
    $logMutex = [System.Threading.Mutex]::OpenExisting("LogMutex")

    try {
        $servicesInfo = Get-Service | Select-Object Name, DisplayName, Status, StartType, @{Name="Path";Expression={(Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").PathName}}
        $servicesInfo | ConvertTo-Json | Out-File -FilePath "$outputDir\ServicesInfo.json"
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting service information - $_" "$outputDir\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} -ArgumentList $outputDir


# Wait for all jobs to complete
$jobs | ForEach-Object { $_ | Wait-Job | Receive-Job }
$jobs | Remove-Job

# Firefox Extension Collection
try {
    $firefoxExtensionsPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default*\\extensions"
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
    $chromeExtensionsPaths = @(
        "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\*\Extensions\*\*",
        "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*\*"
    )
    $chromeExtensionsPaths | ForEach-Object {
        $chromeExtensions = Get-ChildItem -Path $_ -Recurse -Directory -ErrorAction SilentlyContinue
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
    }
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Google Chrome extensions - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# Collect Chrome/Edge browser history based on OS version
    if ($valueBasedOnOS -eq "Windows XP") {
        $chromeHistoryPath = "%USERPROFILE%\Local Settings\Application Data\Google\Chrome\User Data\*\History"
        Get-ChildItem  $chromeHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\chromeedgeHistory -Force
        Write-Output "Exporting Chrome/Edge browser history for XP: $firefoxHistoryPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
    } elseif ($valueBasedOnOS -eq "Windows Vista" -or $valueBasedOnOS -eq "Unknown OS Version") {
        Write-Output-error "Error collecting Chrome/Edge history - $_" "$outputDir\\error_log.txt"
    } else {
        $chromeHistoryPath = "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\*\History"
        Get-ChildItem  $chromeHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\chromeedgeHistory -Force
        $chromeHistoryPath2 = "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\*\History"
        Get-ChildItem  $chromeHistoryPath2 $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\chromeedgeHistory2 -Force
        # Write-Output "Exporting Chrome/Edge browser history for Vista and above: $firefoxHistoryPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
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

#Media History Collection
try {
    $chromeMediaHistoryPath = "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\*\Media History"
    Get-ChildItem  $chromeMediaHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\chromeMediaHistory -Force
    # Write-Output "Exporting Chrome browser media history: $chromeMediaHistoryPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Chrome media history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}
try {
    $edgeMediaHistoryPath = "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\*\Media History"
    Get-ChildItem  $edgeMediaHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $outputDir\\EdgeMediaHistory -Force
    # Write-Output "Exporting Edge browser media history: $edgeMediaHistoryPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Edge media history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

# %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random_text.default\places.sqlite
# %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random_text.default\bookmarkbackups\bookmarks.<data>.jsonlz4
# %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random_text.default\bookmarkbackups\bookmarks.<data>.json
# %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random_text.default\bookmarkbackups\bookmarks.<data>.html
# %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random_text.default\bookmarkbackups\bookmarks.<data>.json
if ($ffversion -gt 2) {
    try {
        $firefoxBookmarksPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default*\\bookmarkbackups"
        $firefoxBookmarks = Get-ChildItem $firefoxBookmarksPath $path -ErrorAction SilentlyContinue
        Write-Output "Exporting Firefox browser bookmarks: $firefoxBookmarksPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        $firefoxBookmarks | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $outputDir -Force
            Write-Output "Exporting Firefox browser bookmarks 1 : $_ for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        }
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting FF Bookmarks 1 - $_" "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
    try {
        $firefoxBookmarksPath2 = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default*\\bookmarkbackups"
        Get-ChildItem $firefoxBookmarksPath2 $path -ErrorAction SilentlyContinue
        Write-Output "Exporting Firefox browser bookmarks: $firefoxBookmarksPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        $firefoxBookmarksPath2 | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $outputDir -Force
            Write-Output "Exporting Firefox browser bookmarks 2: $_ for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        }
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting FF Bookmarks 2 $_" "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
    try {
        $firefoxPlacesPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default*\\places.sqlite"
        Get-ChildItem $firefoxPlacesPath  $path -ErrorAction SilentlyContinue
        Write-Output "Exporting Firefox browser places: $firefoxPlacesPath for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        $firefoxPlacesPath | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $outputDir -Force
            Write-Output "Error collecting FF Places: $_ for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        }
    } catch {
        $logMutex.WaitOne() | Out-Null
        try {
            Write-Output-error "Error collecting FF Places - $_" "$outputDir\\error_log.txt"
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
} else {
    Write-Output-error "Error collecting Firefox bookmarks - $_" "$outputDir\\error_log.txt"
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

# Hashing of Collected Files
try {
    $collectedFiles = Get-ChildItem -Path $outputDir -File -Recurse
    foreach ($file in $collectedFiles) {
        $hash = Get-FileHashSafely -FilePath $file.FullName
        if ($hash) {
            $logMutex.WaitOne() | Out-Null
            try {
                Add-Content -Path "$outputDir\\Hashes.csv" -Value "$($file.FullName),$hash"
            } finally {
                $logMutex.ReleaseMutex() | Out-Null
            }
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

# Define the current working directory and the parent directory
$parentDirectory = Split-Path -Path $outputDir -Parent
$tempFolderName = "Temp$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$tempFolderPath = "$parentDirectory\$tempFolderName"
New-Item -ItemType Directory -Path $tempFolderPath -Force

# Copy all files and folders recursively to the temporary folder while maintaining the directory structure
Get-ChildItem -Path $outputDir -Recurse | ForEach-Object {
    if ($_.FullName -ne $tempFolderPath) {
        $destination = Join-Path -Path $tempFolderPath -ChildPath $_.FullName.Substring($outputDir.Length-1)
        if ($_.PSIsContainer) {
            $logMutex.WaitOne() | Out-Null
            try {
                if ($_.FullName -ne $tempFolderPath -and $_.Name -ne $tempFolderName -and !(Test-Path $destination)) {
                    New-Item -ItemType Directory -Path $destination -Force
                }
            } finally {
                $logMutex.ReleaseMutex() | Out-Null
            }
        } else {
            $logMutex.WaitOne() | Out-Null
            try {
                if ($_.DirectoryName -ne $tempFolderPath -and !(Test-Path $destination)) {
                    Copy-Item -Path $_.FullName -Destination $destination -Force
                }
            } finally {
                $logMutex.ReleaseMutex() | Out-Null
            }
        }
    }
}

# Compress the temporary folder into a zip file in the output directory
$zipFileName = "IR-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
$zipFilePath = "$parentDirectory\$zipFileName"
$zipParams = @{
    path = $tempFolderPath
    destinationPath = $zipFilePath
    CompressionLevel = "Optimal"
}
Compress-Archive @zipParams -ErrorAction Ignore

# Check if the zip file was created successfully
if (Test-Path $zipFilePath) {
    # Delete the temporary folder
    Remove-Item -Recurse -Force -Path $tempFolderPath
    wait-event -timeout 3
    $logMutex2.WaitOne() | Out-Null
    try {
        Write-Output "Backup created successfully: $zipFilePath" | Add-Content -Path "$outputDir\script_log.txt" -ErrorAction SilentlyContinue
    } finally {
        $logMutex2.ReleaseMutex() | Out-Null
    }
} else {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Zip file was not created. - $_" "$outputDir\error_log.txt" -ErrorAction SilentlyContinue
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
