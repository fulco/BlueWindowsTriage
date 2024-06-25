# Parameterize the output directory and log file path
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

# Initialize a mutex for synchronized logging
$logMutex = New-Object System.Threading.Mutex($false, "LogMutex")

# Global error logging function with batch processing
$global:errorList = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

function Write-Output-Error {
    param (
        [string] $Message,
        [string] $LogFile = (Join-Path $outputDir "error_log.txt")
    )
    $global:errorList.Add("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $Message")
    if ($global:errorList.Count -gt 100) {
        $logMutex.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path $LogFile
            $global:errorList = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
    }
}

# Function to flush remaining errors
function Clear-ErrorLog {
    if ($global:errorList.Count -gt 0) {
        $logMutex.WaitOne() | Out-Null
        try {
            $global:errorList | Add-Content -Path (Join-Path $outputDir "error_log.txt")
            $global:errorList = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
        } finally {
            $logMutex.ReleaseMutex() | Out-Null
        }
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
        Write-Output-Error "Error calculating hash for file: $FilePath - $_"
        return $null
    }
}

# Function to export registry keys
function Export-RegistryKey {
    param (
        [string]$keyPath,
        [string]$outputDir
    )
    try {
        $sanitizedPath = ($keyPath -replace '\\', '_')
        REG EXPORT $keyPath (Join-Path $outputDir "$sanitizedPath.reg") /y
    } catch {
        Write-Output-Error "Failed to export registry key: $keyPath. Error: $_"
    }
}

# Function to safely wait for and remove jobs
function Wait-AndRemoveJobs {
    param (
        [Array]$JobsArray
    )
    foreach ($job in $JobsArray) {
        $job | Wait-Job | Receive-Job
        if (Get-Job -Id $job.Id -ErrorAction SilentlyContinue) {
            Remove-Job -Id $job.Id
        }
    }
}

# Convert the Write-Output-Error function to a string
$WriteOutputErrorString = ${function:Write-Output-Error}.ToString()

# Detect Windows version
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

# Create subdirectories
$subDirs = @("CE", "FF")
$subDirs | ForEach-Object {
    New-Item -ItemType Directory -Path (Join-Path $outputDir $_) -ErrorAction SilentlyContinue
}

# Brave Browser Check
$braveInstalled = Test-Path "HKLM:\Software\BraveSoftware"
if ($braveInstalled) {
    "Brave Browser is installed" | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
} else {
    "Brave Browser is not installed." | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
}

# Function to copy items maintaining directory structure
function Copy-ItemWithHierarchy {
    param (
        [string]$source,
        [string]$destination
    )
    Get-ChildItem -Path $source -Recurse | ForEach-Object {
        $targetPath = Join-Path $destination $_.FullName.Substring($source.Length)
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Path $targetPath -ErrorAction SilentlyContinue
        } else {
            Copy-Item -Path $_.FullName -Destination $targetPath -Force
        }
    }
}

# Brave Browser artifact collection
if ($braveInstalled) {
    $bboutputDir = Join-Path $outputDir "BB"
    $sourcePath = "C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
    New-Item -ItemType Directory -Path $bboutputDir -ErrorAction SilentlyContinue
    Copy-ItemWithHierarchy -source $sourcePath -destination $bboutputDir
    "Brave Browser artifacts have been copied to $bboutputDir" | Add-Content -Path (Join-Path $outputDir "brave_log.txt")
}

# Core Parallel Processing
$jobs = @()

# Define job functions
$jobFunctions = @{
    "SystemInfo" = {
        param($outputDir, $WriteOutputErrorString)
        # Recreate the Write-Output-Error function in the job's context
        $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
        Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
        try {
            $systemInfo = @{
                "Hostname" = $env:COMPUTERNAME
                "OS Version" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                "Uptime" = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
                "Installed Software" = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate
                "Running Processes" = Get-Process | Select-Object Name, ID, Path, @{Name="User";Expression={$_.GetOwner().User}}, @{Name="ExecutablePath";Expression={$_.Path}}
                "Network Configuration" = Get-NetIPConfiguration
            }
            $systemInfo | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $outputDir "SystemInfo.json")
        } catch {
            Write-Output-Error "Error collecting system information - $_"
        }
    }
    "StartupItems" = {
        param($outputDir, $WriteOutputErrorString)
        # Recreate the Write-Output-Error function in the job's context
        $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
        Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
        try {
            $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command, Description, User, Location, Name
            $startupItems | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "StartupItems.json")
        } catch {
            Write-Output-Error "Error collecting startup items - $_"
        }
    }
    "UserInfo" = {
        param($outputDir, $WriteOutputErrorString)
        # Recreate the Write-Output-Error function in the job's context
        $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
        Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
        try {
            $userInfo = @{
                "Local Users" = Get-LocalUser | Select-Object Name, Enabled, LastLogon
                "User Groups" = Get-LocalGroup | Select-Object Name, SID
                "Recent User Accounts" = Get-LocalUser | Where-Object {$_.CreateDate -ge (Get-Date).AddDays(-7)} | Select-Object Name, CreateDate
            }
            $userInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "UserInfo.json")
        } catch {
            Write-Output-Error "Error collecting user and group information - $_"
        }
    }
}

# Start jobs
foreach ($jobName in $jobFunctions.Keys) {
    $jobs += Start-Job -Name $jobName -ScriptBlock $jobFunctions[$jobName] -ArgumentList $outputDir, $WriteOutputErrorString
}

# Event Log Collection
$eventLogs = @("Application", "Security", "System")
foreach ($logName in $eventLogs) {
    $jobs += Start-Job -Name "EventLog_$logName" -ScriptBlock {
        param($outputDir, $logName)
        # Recreate the Write-Output-Error function in the job's context
        $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
        Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents 1500 -ErrorAction Stop
            if ($events -and $events.Count -gt 0) {
                $events | Export-Clixml -Path (Join-Path $outputDir "${logName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml")
            } else {
                Write-Output-Error "No events found in $logName log"
            }
        } catch {
            Write-Output-Error "Failed to collect $logName event logs: $_"
        }
    } -ArgumentList $outputDir, $logName, $WriteOutputErrorString
}

# Network Connections
$jobs += Start-Job -Name "NetworkConnections" -ScriptBlock {
    param($outputDir, $WriteOutputErrorString)
    # Recreate the Write-Output-Error function in the job's context
    $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
    Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
    try {
        $networkConnections = Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
        $networkConnections | Export-Csv -Path (Join-Path $outputDir "NetworkConnections.csv") -NoTypeInformation
    } catch {
        Write-Output-Error "Error collecting network connections - $_"
    }
} -ArgumentList $outputDir

# Registry Startup Items
$jobs += Start-Job -Name "RegistryStartupItems" -ScriptBlock {
    param($outputDir, $WriteOutputErrorString)
    # Recreate the Write-Output-Error function in the job's context
    $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
    Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
    try {
        $registryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $registryKeys) {
            $keyName = ($key -split '\\')[-1]
            $keyValues = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $keyValues | ConvertTo-Json | Out-File -FilePath (Join-Path $outputDir "Registry_$keyName.json")
        }
    } catch {
        Write-Output-Error "Error collecting registry data - $_"
    }
} -ArgumentList $outputDir, $WriteOutputErrorString

# Shimcache Data
$jobs += Start-Job -Name "ShimcacheData" -ScriptBlock {
    param($outputDir, $WriteOutputErrorString)
    # Recreate the Write-Output-Error function in the job's context
    $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
    Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
    try {
        $shimcacheFile = Join-Path $outputDir "Shimcache.reg"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $shimcacheFile /y
    } catch {
        Write-Output-Error "Error collecting Shimcache data - $_"
    }
} -ArgumentList $outputDir, $WriteOutputErrorString

# Browser Data Collection
$browserDataJobs = @(
    @{
        Name = "FirefoxData"
        ScriptBlock = {
            param($outputDir, $valueBasedOnOS, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
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
                    Copy-Item -Path $_.FullName -Destination $destinationFile -Force
                }
            }
        }
    },
    @{
        Name = "ChromeData"
        ScriptBlock = {
            param($outputDir, $valueBasedOnOS, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
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
                    Copy-Item -Path $_.FullName -Destination $destinationFile -Force
                }
            }
        }
    },
    @{
        Name = "EdgeData"
        ScriptBlock = {
            param($outputDir, $valueBasedOnOS, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $cePath = Join-Path $outputDir "CE"
            $edgePaths = @(
                "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
                "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks",
                "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
                "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Web Data"
            )
            foreach ($path in $edgePaths) {
                Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $destinationFile = Join-Path $cePath ($_.Name + "_Edge_" + (Get-Random))
                    Copy-Item -Path $_.FullName -Destination $destinationFile -Force
                }
            }
        }
    }
)

foreach ($job in $browserDataJobs) {
    $jobs += Start-Job -Name $job.Name -ScriptBlock $job.ScriptBlock -ArgumentList $outputDir, $valueBasedOnOS, $WriteOutputErrorString
}

# Wait for all jobs to complete
Wait-AndRemoveJobs -JobsArray $jobs

# Browser Extensions Collection
$extensionJobs = @(
    @{
        Name = "FirefoxExtensions"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $firefoxExtensionsPath = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\"
            $firefoxExtensionsPath = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\extensions"
            $firefoxExtensions = Get-ChildItem -Path $firefoxExtensionsPath -Recurse -Directory -ErrorAction SilentlyContinue
            $firefoxExtensions | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path -Path $manifestPath) {
                    $extensionInfo = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                    [PSCustomObject]@{
                        Id = $_.Name
                        Name = $extensionInfo.name
                        Version = $extensionInfo.version
                        Description = $extensionInfo.description
                    } | Out-File -FilePath (Join-Path $outputDir "FirefoxExtensions.txt") -Append
                }
            }
        }
    },
    @{
        Name = "ChromeEdgeExtensions"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $browserPaths = @(
                "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\*\*",
                "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\*\*"
            )
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
                        } | Out-File -FilePath (Join-Path $outputDir "ChromeEdgeExtensions.txt") -Append
                    }
                }
            }
        }
    }
)

foreach ($job in $extensionJobs) {
    $jobs += Start-Job -Name $job.Name -ScriptBlock $job.ScriptBlock -ArgumentList $outputDir, $WriteOutputErrorString
}

# Additional artifact collection jobs
$artifactJobs = @(
    @{
        Name = "PasswordFiles"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $passwordFiles = Get-ChildItem -Path "C:\Users\*\Documents\*password*" -Recurse -ErrorAction SilentlyContinue
            if ($passwordFiles -and $passwordFiles.Count -gt 0) {
                $passwordFiles | Export-Clixml -Path (Join-Path $outputDir "${logName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml")
            } else {
                Write-Output-Error "No Passsword Files found in $logName log"
            }
            $passwordFiles | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination (Join-Path $outputDir "PasswordFiles") -Force
            }
        }
    },
    @{
        Name = "PowerShellHistory"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $powershellHistoryPath = "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            Get-ChildItem -Path $powershellHistoryPath -ErrorAction SilentlyContinue | ForEach-Object {
                $destinationPath = Join-Path $outputDir $_.Directory.Name
                New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
                Copy-Item -Path $_.FullName -Destination $destinationPath -Force
            }
        }
    },
    @{
        Name = "PrefetchFiles"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $prefetchDir = Join-Path $outputDir "PreFetch"
            New-Item -ItemType Directory -Path $prefetchDir -Force | Out-Null
            Get-ChildItem -Path "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | Copy-Item -Destination $prefetchDir -Force
        }
    },
    @{
        Name = "JumpLists"
        ScriptBlock = {
            param($outputDir, $WriteOutputErrorString)
            # Recreate the Write-Output-Error function in the job's context
            $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
            Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock
            $jumpListFiles = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -ErrorAction SilentlyContinue
            $jumpListFiles | Copy-Item -Destination (Join-Path $outputDir "JumpLists") -Force
        }
    }
)

foreach ($job in $artifactJobs) {
    $jobs += Start-Job -Name $job.Name -ScriptBlock $job.ScriptBlock -ArgumentList $outputDir, $WriteOutputErrorString
}

# Wait for all jobs to complete
Wait-AndRemoveJobs -JobsArray $jobs

# Hashing of Collected Files
$hashingJob = Start-Job -ScriptBlock {
    param($outputDir, $GetFileHashSafelyString, $WriteOutputErrorString)

    # Recreate the functions in the job's context
    $GetFileHashSafelyScriptBlock = [ScriptBlock]::Create($GetFileHashSafelyString)
    Set-Item -Path Function:\Get-FileHashSafely -Value $GetFileHashSafelyScriptBlock

    $WriteOutputErrorScriptBlock = [ScriptBlock]::Create($WriteOutputErrorString)
    Set-Item -Path Function:\Write-Output-Error -Value $WriteOutputErrorScriptBlock

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
            Write-Output-Error "No file hashes were generated"
        }
    } catch {
        Write-Output-Error "Error during file hashing: $_"
    }
} -ArgumentList $outputDir, ${function:Get-FileHashSafely}.ToString(), $WriteOutputErrorString

Wait-AndRemoveJobs -JobsArray @($hashingJob)

# Create backup
$parentDirectory = Split-Path -Path $outputDir -Parent
$tempFolderName = "Temp$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$tempFolderPath = Join-Path $parentDirectory $tempFolderName
New-Item -ItemType Directory -Path $tempFolderPath -Force | Out-Null

# Copy files to temporary folder
Copy-ItemWithHierarchy -source $outputDir -destination $tempFolderPath

# Compress the temporary folder
$zipFileName = "IR-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
$zipFilePath = Join-Path $parentDirectory $zipFileName
Compress-Archive -Path $tempFolderPath -DestinationPath $zipFilePath -CompressionLevel Optimal

# Check if the zip file was created successfully
if (Test-Path $zipFilePath) {
    Remove-Item -Recurse -Force -Path $tempFolderPath
    #"Backup created successfully: $zipFilePath" | Add-Content -Path (Join-Path $outputDir "script_log.txt")
} else {
    Write-Output-Error "Zip file was not created."
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
