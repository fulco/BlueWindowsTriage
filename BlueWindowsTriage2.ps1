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

$cePath = "$outputDir\CE"
if (-Not (Test-Path $cePath)) {
    New-Item -ItemType Directory -Path $cePath
}
$ffPath = "$outputDir\FF"
if (-Not (Test-Path $ffPath)) {
    New-Item -ItemType Directory -Path $ffPath
}

# FireFox Version Collection
# Define the registry path
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
# Initialize variable for Firefox version
$firefoxVersion = ""
$firefoxVersion = Get-ChildItem -Path "$registryPath" | Where-Object { $_.PSChildName -like "Mozilla *" } | ForEach-Object { Get-ItemProperty -Path $_.PSPath } | Select-Object -Property DisplayVersion

# Remove unwanted parts of the string
$ffversion = $firefoxVersion -replace "@{DisplayVersion=", "" -replace "}", ""

# Define registry paths to search for Chrome installations
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKU:\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Google\Chrome\*",
    "HKCU:\Software\Google\Chrome\*",
    "HKU:\*\Software\Google\Chrome\*",
    "HKLM:\Software\Classes\Installer\Products\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-21-*\Products\*"
)

# Initialize an array to store Chrome installations
$chromeInstallations = @()

# Function to check registry paths for Chrome installations
function Get-ChromeInstallations {
    param (
        [string]$path
    )
    
    Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_.PSPath
        $displayName = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).DisplayName
        $displayVersion = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).DisplayVersion
        
        if ($displayName -like "*Chrome*") {
            $chromeInstallations += [PSCustomObject]@{
                Path    = $key
                Name    = $displayName
                Version = $displayVersion
            }
        }
    }
}

# Search each registry path for Chrome installations
foreach ($path in $registryPaths) {
    Get-ChromeInstallations -path $path -ErrorAction SilentlyContinue
}

# Output the results
if ($chromeInstallations.Count -gt 0) {
    Write-Output "Google Chrome Version: $chromeVersion"
    Write-Output "Google Chrome Version: $chromeVersion" | Add-Content -Path "$outputDir\\chrome_log.txt"
    $chromeInstallations | Format-Table -AutoSize
} else {
    Write-Output "No Google Chrome installations found."
}

function Get-ChromeVersion {
    param (
        [string]$registryPath
    )
    if (Test-Path $registryPath) {
        $chromeInfo = Get-ItemProperty $registryPath
        return $chromeInfo.DisplayVersion
    }
    return $null
}


# Define the registry path for Brave Browser
$registryPath = "HKLM:\Software\BraveSoftware"

# Initialize variables
$braveInstalled = $false

# Check if the registry path exists
if (Test-Path $registryPath) {
    $braveInstalled = $true
}

# Output the installation status and version
$braveInstalled
if ($braveInstalled) {
    Write-Output "Brave Browser is installed" | Add-Content -Path "$outputDir\\brave_log.txt"
} else {
    Write-Output "Brave Browser is not installed."
}

# Define the registry path for Chrome Browser
$chromeRegistryPath = "HKLM:\Software\Google\Chrome"
$chromeRegistryPathWow6432Node = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"

# Initialize variables
$chromeInstalled = $false
$chromeVersion = ""

# Function to check Chrome installation and get version
function Get-ChromeVersion {
    param (
        [string]$registryPath
    )
    if (Test-Path $registryPath) {
        $chromeInfo = Get-ItemProperty $registryPath
        return $chromeInfo.DisplayVersion
    }
    return $null
}

# Check if Chrome is installed
$chromeVersion = Get-ChromeVersion -registryPath $chromeRegistryPath
if (-not $chromeVersion) {
    $chromeVersion = Get-ChromeVersion -registryPath $chromeRegistryPathWow6432Node
}

# Set installation status
if ($chromeVersion) {
    $chromeInstalled = $true
}

if ($chromeInstalled) {
    Write-Output "Google Chrome Version: $chromeVersion"
    Write-Output "Google Chrome Version: $chromeVersion" | Add-Content -Path "$outputDir\\chrome_log.txt"
} else {
    Write-Output "Googßle Chrome is not installed."
}


# Function to copy items maintaining directory structure
function Copy-ItemWithHierarchy {
    param (
        [string]$source,
        [string]$destination
    )

    Get-ChildItem -Path $source -Recurse | ForEach-Object {
        $relativePath = $_.FullName.Substring($source.Length)
        $destPath = Join-Path -Path $destination -ChildPath $relativePath

        if ($_.PSIsContainer) {
            if (-Not (Test-Path $destPath)) {
                New-Item -ItemType Directory -Path $destPath
            }
        } else {
            Copy-Item -Path $_.FullName -Destination $destPath
        }
    }
}

if ($braveInstalled -eq $true) {
    Write-Output "Brave Browser is installed."
    $bboutputDir = "$outputDir\BB"
    # Define source and destination paths
    $sourcePath = "C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"

    # Create the destination folder if it does not exist
    if (-Not (Test-Path $bboutputDir)) {
        New-Item -ItemType Directory -Path $bboutputDir
    }

    # Copy the artifacts
    Copy-ItemWithHierarchy -source $sourcePath -destination $bboutputDir

    Write-Output "Brave Browser artifacts have been copied to $bboutputDir"

} else {
    Write-Output "Brave Browser is not installed." | Add-Content -Path "$outputDir\\brave_log.txt"
}
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
        Get-ChildItem $firefoxHistoryPath $path -ErrorAction Stop | Copy-Item -Destination $ffPath\\FFplaces.sqlite -Force
        Get-ChildItem $firefoxHistoryPath2 $path -ErrorAction Stop | Copy-Item -Destination $ffPath\\FFBookmarks.jsonlz4 -Force
    } catch {
        Write-Output-error "Error collecting FF1 browser history: $_" "$outputDir\error_log.txt"
    }
} elseif ($valueBasedOnOS -eq "Unknown OS Version" -or $valueBasedOnOS -eq "") {
    Write-Output-error "Error collecting FF0 browser history due to OS version - $_" "$outputDir\error_log.txt"
} elseif($valueBasedOnOS -eq "Windows Vista" -or $valueBasedOnOS -eq "Windows 7" -or $valueBasedOnOS -eq "Windows 8" -or $valueBasedOnOS -eq "Windows 8.1" -or $valueBasedOnOS -eq "Windows 10" -or $valueBasedOnOS -eq "Windows 11") {
    $ffPaths = @(
        "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\places.sqlite",
        "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\bookmarkbackups\*.jsonlz4",
        "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\logins.json"
        )
        $counter = 1
        foreach ($path in $ffPaths) {
            $fileName = Split-Path -Leaf $path
            $extension = [System.IO.Path]::GetExtension($fileName)
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
            #Write-Output "Attempting to Export FFpaths $counter and logins for $baseName"
            $destination = Join-Path $ffPath ("$baseName$counter$extension" -replace '[\\/:*?"<>|]', '')
            Get-ChildItem $path -ErrorAction SilentlyContinue | Copy-Item -Destination $destination -Force
            $counter++
        }
        #Write-Output "Attempting to Export FF Bookmarks and logins for $valueBasedOnOS"
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
            "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"
        )
        $c = 1
        foreach ($path in $cookiePaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Copy-Item -Destination $cePath\\cookies$c.sqlite -Force
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
        "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Extensions\*\*",
        "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\*\*"
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
                } | Out-File -FilePath "$cePath\\ChromeExtensions.txt" -Append -Force
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
        $chromePathsXP = @(
            "c:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\Default\Bookmarks"
        )
        $b=1
        foreach ($path in $chromePathsXP) {
            $fileName = Split-Path -Leaf $path
            $destination = Join-Path $outputDir $fileName$b
            Get-ChildItem $path -ErrorAction SilentlyContinue | Copy-Item -Destination $destination -Force
            Write-Output "Exporting $fileName for $valueBasedOnOS" | Add-Content -Path "$cePath\\script_log.txt"
            $b++
        }
        #Write-Output "Attempting to Export Chrome/Edge Bookmarks for $valueBasedOnOS"
    } elseif ($valueBasedOnOS -eq "Windows Vista" -or $valueBasedOnOS -eq "Windows 7" -or $valueBasedOnOS -eq "Windows 8" -or $valueBasedOnOS -eq "Windows 8.1" -or $valueBasedOnOS -eq "Windows 10" -or $valueBasedOnOS -eq "Windows 11") {
        $chromePaths = @(
            "C:\\Users\\*\\Local Settings\Application Data\Google\Chrome\User Data\*\History",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Bookmarks",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Bookmarks.bak",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks.msbak",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Login Data For Account",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Login Data For Account",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Local Storage\*",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\*",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\File System",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\File System",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Web Data",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Web Data",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Shortcuts",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Shortcuts",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Network Action Predictor",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Network Action Predictor",
            "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
        )
        $counter = 1
        foreach ($path in $chromePaths) {
            if (Test-Path $path) {
                if (Test-Path $path -PathType Container) {
                    $lastFolder = Split-Path -Leaf $path
                    $destination = Join-Path $cePath ("$counter$lastFolder" -replace '[\\/:*?"<>|]', '')
                    Write-Output "Attempting to Error check $path at $destination for $valueBasedOnOS"
                    Copy-Item $path -Destination $destination -Recurse -Force
                } elseif (Test-Path $path -PathType Leaf) {
                    $fileName = Split-Path -Leaf $path
                    $extension = [System.IO.Path]::GetExtension($fileName)
                    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
                    $destination = Join-Path $cePath "$baseName$counter$extension"
                    Copy-Item $path -Destination $destination -Force
                }
                $counter++
            } else {
            Write-Output "Path $path does not exist."
            }
        }
        Write-Output "Attempting to Export Chrome/Edge Bookmarks & Login Data for $valueBasedOnOS"
    } else {
        Write-Output-error "Error collecting Chrome/Edge history - $_" "$outputDir\\error_log.txt"
    }

if ($ffversion -lt 26 -and $ffversion -gt 2) {
    $ffDLPaths = @(
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\downloads.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\downloads.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\extensions.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\extensions.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\addons.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\addons.sqlite"
    )
    $b=1
    foreach ($path in $ffDLPaths) {
        $fileName = Split-Path -Leaf $path
        $destination = Join-Path $ffPath $fileName$b
        Get-ChildItem $path -ErrorAction SilentlyContinue | Copy-Item -Destination $destination -Force
        Write-Output "Exporting $fileName for $valueBasedOnOS" | Add-Content -Path "$outputDir\\script_log.txt"
        $b++
    }
    #Write-Output "Attempting to Export FF Downloads for $valueBasedOnOS and FF:$ffversion"
} elseif ($ffversion -gt 25) {
    $ffDLPaths = @(
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\formhistory.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\formhistory.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\extensions.json",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\extensions.json",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\addons.json",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\addons.json"
    )
    $counter = 1
    foreach ($path in $chromePaths) {
        if (Test-Path $path -PathType Container) {
            $lastFolder = Split-Path -Leaf $path
            $destination = Join-Path $ffPath ("$counter$lastFolder" -replace '[\\/:*?"<>|]', '')
            #Write-Output "Attempting to Error check $path at $destination for $valueBasedOnOS and FF:$ffversion"
            Copy-Item $path -Destination $destination -Recurse -Force
        } elseif (Test-Path $path -PathType Leaf) {
            $fileName = Split-Path -Leaf $path
            $extension = [System.IO.Path]::GetExtension($fileName)
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
            $destination = Join-Path $ffPath "$baseName$counter$extension"
            Copy-Item $path -Destination $destination -Force
        }
        $counter++
    }
    #Write-Output "Attempting to Export FF Downloads for $valueBasedOnOS and FF:$ffversion"
} else {
    Write-Output-error "Error collecting Chrome/Edge history - $_" "$outputDir\\error_log.txt"
}


# Firefox History Collection
try {
    $ffPaths = @(
        "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite",
        "C:\\Users\\*\\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\webappstore.sqlite"
    )
    $counter = 1
    foreach ($path in $ffPaths) {
        $fileName = Split-Path -Leaf $path
        $extension = [System.IO.Path]::GetExtension($fileName)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $destination = Join-Path $ffPath "$baseName$counter$extension"
        Get-ChildItem $path -ErrorAction Continue | Copy-Item -Destination $destination -Force
        $counter++
    }
    #Write-Output "Attempting to Export FF History & HTML5 Storage"
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting FF History & HTML5 Storage - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

#Media History Collection
try {
    $chromeMediaHistoryPath = "C:\\Users\\*\\AppData\Local\Google\Chrome\User Data\Default\Media History"
    Get-ChildItem  $chromeMediaHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $cePath\\chromeMediaHistory -Force
    Write-Output "Exporting Chrome browser media history: $chromeMediaHistoryPath for $valueBasedOnOS"
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Chrome media history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}
try {
    $edgeMediaHistoryPath = "C:\\Users\\*\\AppData\Local\Microsoft\Edge\User Data\Default\Media History"
    Get-ChildItem  $edgeMediaHistoryPath $path -ErrorAction SilentlyContinue | Copy-Item -Destination $cePath\\EdgeMediaHistory -Force
    Write-Output "Exporting Edge browser media history: $edgeMediaHistoryPath for $valueBasedOnOS"
} catch {
    $logMutex.WaitOne() | Out-Null
    try {
        Write-Output-error "Error collecting Edge media history - $_" "$outputDir\\error_log.txt"
    } finally {
        $logMutex.ReleaseMutex() | Out-Null
    }
}

if ($ffversion -gt 2) {
    try {
        $firefoxBookmarksPath = "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default*\\bookmarkbackups"
        $firefoxBookmarks = Get-ChildItem $firefoxBookmarksPath $path -ErrorAction SilentlyContinue
        Write-Output "Exporting Firefox browser bookmarks: $firefoxBookmarksPath for $valueBasedOnOS"
        $firefoxBookmarks | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $ffPath -Force
            Write-Output "Exporting Firefox browser bookmarks 1 : $_ for $valueBasedOnOS"
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
        Write-Output "Exporting Firefox browser bookmarks: $firefoxBookmarksPath for $valueBasedOnOS"
        $firefoxBookmarksPath2 | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $ffPath -Force
            Write-Output "Exporting Firefox browser bookmarks 2: $_ for $valueBasedOnOS"
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
        Write-Output "Exporting Firefox browser places: $firefoxPlacesPath for $valueBasedOnOS"
        $firefoxPlacesPath | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $ffPath -Force
            Write-Output "Error collecting FF Places: $_ for $valueBasedOnOS"
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
        Copy-Item -Path $_.FullName -Destination "$cePath\\EdgeHistory.sqlite" -Force
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
