#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Collects comprehensive information about all Windows registry hives and exports to CSV files.

.DESCRIPTION
    This script discovers and catalogs all registry hive files on a Windows system,
    including system hives, user hives, and backup hives. It collects detailed
    metadata and exports the information to descriptive CSV files.

.NOTES
    - Requires Administrator privileges
    - Creates output directory if it doesn't exist
    - Handles access denied scenarios gracefully
#>

# Set error handling
$ErrorActionPreference = "Continue"

# Define output directory
$OutputDir = "C:\RegistryHiveCollection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Create output directory
try {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
} catch {
    Write-Error "Failed to create output directory: $($_.Exception.Message)"
    exit 1
}

# Initialize collections
$AllHives = @()
$HiveLocations = @()
$UserHives = @()
$SystemHives = @()

Write-Host "Starting Registry Hive Collection..." -ForegroundColor Yellow

# Function to get file hash safely
function Get-SafeFileHash {
    param($FilePath)
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return "Access Denied or Error"
    }
}

# Function to get file details safely
function Get-SafeFileDetails {
    param($FilePath)
    try {
        $file = Get-Item -Path $FilePath -ErrorAction Stop
        return @{
            Exists = $true
            Size = $file.Length
            CreationTime = $file.CreationTime
            LastWriteTime = $file.LastWriteTime
            LastAccessTime = $file.LastAccessTime
            Attributes = $file.Attributes
            IsReadOnly = $file.IsReadOnly
        }
    } catch {
        return @{
            Exists = $false
            Size = 0
            CreationTime = $null
            LastWriteTime = $null
            LastAccessTime = $null
            Attributes = "Access Denied"
            IsReadOnly = $false
        }
    }
}

# Define common registry hive locations
$SystemHiveLocations = @{
    "SYSTEM" = @{
        "Path" = "$env:SystemRoot\System32\config\SYSTEM"
        "Description" = "System configuration and services"
        "HiveKey" = "HKEY_LOCAL_MACHINE\SYSTEM"
    }
    "SOFTWARE" = @{
        "Path" = "$env:SystemRoot\System32\config\SOFTWARE"
        "Description" = "Installed software and system settings"
        "HiveKey" = "HKEY_LOCAL_MACHINE\SOFTWARE"
    }
    "SECURITY" = @{
        "Path" = "$env:SystemRoot\System32\config\SECURITY"
        "Description" = "Security policies and user rights"
        "HiveKey" = "HKEY_LOCAL_MACHINE\SECURITY"
    }
    "SAM" = @{
        "Path" = "$env:SystemRoot\System32\config\SAM"
        "Description" = "Security Accounts Manager database"
        "HiveKey" = "HKEY_LOCAL_MACHINE\SAM"
    }
    "DEFAULT" = @{
        "Path" = "$env:SystemRoot\System32\config\DEFAULT"
        "Description" = "Default user profile settings"
        "HiveKey" = "HKEY_USERS\.DEFAULT"
    }
    "COMPONENTS" = @{
        "Path" = "$env:SystemRoot\System32\config\COMPONENTS"
        "Description" = "Component-based servicing information"
        "HiveKey" = "HKEY_LOCAL_MACHINE\COMPONENTS"
    }
    "DRIVERS" = @{
        "Path" = "$env:SystemRoot\System32\config\DRIVERS"
        "Description" = "Driver configuration information"
        "HiveKey" = "HKEY_LOCAL_MACHINE\DRIVERS"
    }
}

Write-Host "Collecting System Registry Hives..." -ForegroundColor Cyan

# Process system hives
foreach ($hiveName in $SystemHiveLocations.Keys) {
    $hiveInfo = $SystemHiveLocations[$hiveName]
    $filePath = $hiveInfo.Path
    
    Write-Host "Processing: $hiveName" -ForegroundColor Gray
    
    $fileDetails = Get-SafeFileDetails -FilePath $filePath
    $hash = if ($fileDetails.Exists) { Get-SafeFileHash -FilePath $filePath } else { "N/A" }
    
    $hiveObject = [PSCustomObject]@{
        HiveName = $hiveName
        HiveType = "System"
        FilePath = $filePath
        Description = $hiveInfo.Description
        RegistryPath = $hiveInfo.HiveKey
        FileExists = $fileDetails.Exists
        FileSizeBytes = $fileDetails.Size
        FileSizeMB = if ($fileDetails.Size -gt 0) { [math]::Round($fileDetails.Size / 1MB, 2) } else { 0 }
        CreationTime = $fileDetails.CreationTime
        LastWriteTime = $fileDetails.LastWriteTime
        LastAccessTime = $fileDetails.LastAccessTime
        FileAttributes = $fileDetails.Attributes
        IsReadOnly = $fileDetails.IsReadOnly
        SHA256Hash = $hash
        ComputerName = $env:COMPUTERNAME
        CollectionTime = Get-Date
        BackupFiles = @()
    }
    
    # Check for backup files
    $backupExtensions = @(".LOG", ".LOG1", ".LOG2", ".sav", ".bak")
    foreach ($ext in $backupExtensions) {
        $backupPath = $filePath + $ext
        if (Test-Path $backupPath) {
            $backupDetails = Get-SafeFileDetails -FilePath $backupPath
            $hiveObject.BackupFiles += "$ext (Size: $([math]::Round($backupDetails.Size / 1KB, 2)) KB)"
        }
    }
    
    $AllHives += $hiveObject
    $SystemHives += $hiveObject
}

Write-Host "Collecting User Registry Hives..." -ForegroundColor Cyan

# Get all user profiles
try {
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }
    
    foreach ($profile in $userProfiles) {
        $profilePath = $profile.LocalPath
        $userSID = $profile.SID
        
        if (Test-Path $profilePath) {
            $ntUserPath = Join-Path $profilePath "NTUSER.DAT"
            $usrClassPath = Join-Path $profilePath "AppData\Local\Microsoft\Windows\UsrClass.dat"
            
            # Process NTUSER.DAT
            if (Test-Path $ntUserPath) {
                Write-Host "Processing User Hive: $profilePath\NTUSER.DAT" -ForegroundColor Gray
                
                $fileDetails = Get-SafeFileDetails -FilePath $ntUserPath
                $hash = if ($fileDetails.Exists) { Get-SafeFileHash -FilePath $ntUserPath } else { "N/A" }
                
                $userHive = [PSCustomObject]@{
                    HiveName = "NTUSER.DAT"
                    HiveType = "User"
                    FilePath = $ntUserPath
                    Description = "User-specific settings and preferences"
                    RegistryPath = "HKEY_USERS\$userSID"
                    UserProfile = $profilePath
                    UserSID = $userSID
                    FileExists = $fileDetails.Exists
                    FileSizeBytes = $fileDetails.Size
                    FileSizeMB = if ($fileDetails.Size -gt 0) { [math]::Round($fileDetails.Size / 1MB, 2) } else { 0 }
                    CreationTime = $fileDetails.CreationTime
                    LastWriteTime = $fileDetails.LastWriteTime
                    LastAccessTime = $fileDetails.LastAccessTime
                    FileAttributes = $fileDetails.Attributes
                    IsReadOnly = $fileDetails.IsReadOnly
                    SHA256Hash = $hash
                    ComputerName = $env:COMPUTERNAME
                    CollectionTime = Get-Date
                    BackupFiles = @()
                }
                
                # Check for NTUSER backup files
                $backupExtensions = @(".LOG", ".LOG1", ".LOG2", ".bak")
                foreach ($ext in $backupExtensions) {
                    $backupPath = $ntUserPath + $ext
                    if (Test-Path $backupPath) {
                        $backupDetails = Get-SafeFileDetails -FilePath $backupPath
                        $userHive.BackupFiles += "$ext (Size: $([math]::Round($backupDetails.Size / 1KB, 2)) KB)"
                    }
                }
                
                $AllHives += $userHive
                $UserHives += $userHive
            }
            
            # Process UsrClass.dat
            if (Test-Path $usrClassPath) {
                Write-Host "Processing User Classes Hive: $usrClassPath" -ForegroundColor Gray
                
                $fileDetails = Get-SafeFileDetails -FilePath $usrClassPath
                $hash = if ($fileDetails.Exists) { Get-SafeFileHash -FilePath $usrClassPath } else { "N/A" }
                
                $classesHive = [PSCustomObject]@{
                    HiveName = "UsrClass.dat"
                    HiveType = "User Classes"
                    FilePath = $usrClassPath
                    Description = "User-specific file associations and COM objects"
                    RegistryPath = "HKEY_USERS\$userSID_Classes"
                    UserProfile = $profilePath
                    UserSID = $userSID
                    FileExists = $fileDetails.Exists
                    FileSizeBytes = $fileDetails.Size
                    FileSizeMB = if ($fileDetails.Size -gt 0) { [math]::Round($fileDetails.Size / 1MB, 2) } else { 0 }
                    CreationTime = $fileDetails.CreationTime
                    LastWriteTime = $fileDetails.LastWriteTime
                    LastAccessTime = $fileDetails.LastAccessTime
                    FileAttributes = $fileDetails.Attributes
                    IsReadOnly = $fileDetails.IsReadOnly
                    SHA256Hash = $hash
                    ComputerName = $env:COMPUTERNAME
                    CollectionTime = Get-Date
                    BackupFiles = @()
                }
                
                # Check for UsrClass backup files
                $backupExtensions = @(".LOG", ".LOG1", ".LOG2", ".bak")
                foreach ($ext in $backupExtensions) {
                    $backupPath = $usrClassPath + $ext
                    if (Test-Path $backupPath) {
                        $backupDetails = Get-SafeFileDetails -FilePath $backupPath
                        $classesHive.BackupFiles += "$ext (Size: $([math]::Round($backupDetails.Size / 1KB, 2)) KB)"
                    }
                }
                
                $AllHives += $classesHive
                $UserHives += $classesHive
            }
        }
    }
} catch {
    Write-Warning "Error collecting user profiles: $($_.Exception.Message)"
}

# Look for additional hive files in common locations
Write-Host "Scanning for additional hive files..." -ForegroundColor Cyan

$additionalLocations = @(
    "$env:SystemRoot\System32\config\RegBack",
    "$env:SystemRoot\System32\config\TxR",
    "$env:SystemRoot\ServiceProfiles\LocalService",
    "$env:SystemRoot\ServiceProfiles\NetworkService"
)

foreach ($location in $additionalLocations) {
    if (Test-Path $location) {
        try {
            $files = Get-ChildItem -Path $location -File -ErrorAction Stop
            foreach ($file in $files) {
                if ($file.Extension -eq "" -or $file.Extension -eq ".dat") {
                    Write-Host "Found additional hive file: $($file.FullName)" -ForegroundColor Gray
                    
                    $fileDetails = Get-SafeFileDetails -FilePath $file.FullName
                    $hash = if ($fileDetails.Exists) { Get-SafeFileHash -FilePath $file.FullName } else { "N/A" }
                    
                    $additionalHive = [PSCustomObject]@{
                        HiveName = $file.Name
                        HiveType = "Additional/Backup"
                        FilePath = $file.FullName
                        Description = "Additional or backup registry hive file"
                        RegistryPath = "Unknown"
                        FileExists = $fileDetails.Exists
                        FileSizeBytes = $fileDetails.Size
                        FileSizeMB = if ($fileDetails.Size -gt 0) { [math]::Round($fileDetails.Size / 1MB, 2) } else { 0 }
                        CreationTime = $fileDetails.CreationTime
                        LastWriteTime = $fileDetails.LastWriteTime
                        LastAccessTime = $fileDetails.LastAccessTime
                        FileAttributes = $fileDetails.Attributes
                        IsReadOnly = $fileDetails.IsReadOnly
                        SHA256Hash = $hash
                        ComputerName = $env:COMPUTERNAME
                        CollectionTime = Get-Date
                        BackupFiles = @()
                    }
                    
                    $AllHives += $additionalHive
                }
            }
        } catch {
            Write-Warning "Cannot access location: $location - $($_.Exception.Message)"
        }
    }
}

# Create summary statistics
$summary = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    CollectionTime = Get-Date
    TotalHivesFound = $AllHives.Count
    SystemHives = ($AllHives | Where-Object { $_.HiveType -eq "System" }).Count
    UserHives = ($AllHives | Where-Object { $_.HiveType -eq "User" }).Count
    UserClassesHives = ($AllHives | Where-Object { $_.HiveType -eq "User Classes" }).Count
    AdditionalHives = ($AllHives | Where-Object { $_.HiveType -eq "Additional/Backup" }).Count
    TotalSizeMB = [math]::Round(($AllHives | Measure-Object FileSizeBytes -Sum).Sum / 1MB, 2)
    LargestHiveFile = ($AllHives | Sort-Object FileSizeBytes -Descending | Select-Object -First 1).FilePath
    LargestHiveSizeMB = [math]::Round(($AllHives | Sort-Object FileSizeBytes -Descending | Select-Object -First 1).FileSizeBytes / 1MB, 2)
    OldestHiveFile = ($AllHives | Sort-Object CreationTime | Select-Object -First 1).FilePath
    OldestHiveCreated = ($AllHives | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    NewestHiveFile = ($AllHives | Sort-Object CreationTime -Descending | Select-Object -First 1).FilePath
    NewestHiveCreated = ($AllHives | Sort-Object CreationTime -Descending | Select-Object -First 1).CreationTime
    ScriptVersion = "1.0"
    OSVersion = [System.Environment]::OSVersion.VersionString
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
}

Write-Host "Exporting results to CSV files..." -ForegroundColor Yellow

# Export all data to CSV files
try {
    # All hives
    $AllHives | Export-Csv -Path "$OutputDir\AllRegistryHives.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported: AllRegistryHives.csv ($($AllHives.Count) records)" -ForegroundColor Green
    
    # System hives only
    if ($SystemHives.Count -gt 0) {
        $SystemHives | Export-Csv -Path "$OutputDir\SystemRegistryHives.csv" -NoTypeInformation -Encoding UTF8
        Write-Host "Exported: SystemRegistryHives.csv ($($SystemHives.Count) records)" -ForegroundColor Green
    }
    
    # User hives only
    if ($UserHives.Count -gt 0) {
        $UserHives | Export-Csv -Path "$OutputDir\UserRegistryHives.csv" -NoTypeInformation -Encoding UTF8
        Write-Host "Exported: UserRegistryHives.csv ($($UserHives.Count) records)" -ForegroundColor Green
    }
    
    # Summary report
    $summary | Export-Csv -Path "$OutputDir\RegistryHivesSummary.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported: RegistryHivesSummary.csv" -ForegroundColor Green
    
    # Create a detailed text report
    $textReport = @"
Registry Hive Collection Report
===============================
Computer: $($env:COMPUTERNAME)
Collection Date: $(Get-Date)
Total Hives Found: $($AllHives.Count)

System Hives: $($summary.SystemHives)
User Hives: $($summary.UserHives)
User Classes Hives: $($summary.UserClassesHives)
Additional/Backup Hives: $($summary.AdditionalHives)

Total Size: $($summary.TotalSizeMB) MB
Largest Hive: $($summary.LargestHiveFile) ($($summary.LargestHiveSizeMB) MB)

Files Generated:
- AllRegistryHives.csv: Complete inventory of all registry hives
- SystemRegistryHives.csv: System-level registry hives only
- UserRegistryHives.csv: User-specific registry hives only
- RegistryHivesSummary.csv: Summary statistics
- RegistryHivesReport.txt: This detailed report

Script completed successfully at $(Get-Date)
"@
    
    $textReport | Out-File -FilePath "$OutputDir\RegistryHivesReport.txt" -Encoding UTF8
    Write-Host "Exported: RegistryHivesReport.txt" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

Write-Host "`nRegistry Hive Collection Complete!" -ForegroundColor Green
Write-Host "Results saved to: $OutputDir" -ForegroundColor Yellow
Write-Host "Total hives found: $($AllHives.Count)" -ForegroundColor White
Write-Host "Total size: $($summary.TotalSizeMB) MB" -ForegroundColor White

# Display summary to console
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
$summary | Format-List
