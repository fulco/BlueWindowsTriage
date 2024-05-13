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

# Compress and Timestamp Output
$zipFile = "$outputDir.zip"
Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force
Remove-Item -Path $outputDir -Recurse -Force
