# Enhanced Windows Forensic Artifact Collector Script with CSV Export
# Collects comprehensive forensic artifacts and exports to CSV files
# No user input required - runs standalone in current directory

#Requires -RunAsAdministrator

# Initialize script
$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
$script:ComputerName = $env:COMPUTERNAME
$script:Username = $env:USERNAME
$script:CurrentDir = Get-Location
$script:OutputDir = Join-Path $script:CurrentDir "ForensicCollection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$script:CSVDir = Join-Path $script:OutputDir "CSV_Artifacts"
$script:DBDir = Join-Path $script:OutputDir "Databases"
$script:LogFile = Join-Path $script:OutputDir "ForensicCollection.log"

# Create output directories
New-Item -ItemType Directory -Path $script:OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $script:CSVDir -Force | Out-Null
New-Item -ItemType Directory -Path $script:DBDir -Force | Out-Null

# Function to write to log file
function Write-ForensicLog {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $script:LogFile -Append
    Write-Host $Message -ForegroundColor $Color
}

# Function to export to CSV
function Export-ForensicCSV {
    param(
        [object]$Data,
        [string]$FileName,
        [string]$Description
    )
    try {
        if ($Data) {
            $csvPath = Join-Path $script:CSVDir "$FileName.csv"
            $Data | Export-Csv -Path $csvPath -NoTypeInformation -Force
            Write-ForensicLog "Exported: $Description to $FileName.csv" -Color Green
        } else {
            Write-ForensicLog "No data to export for: $Description" -Color Yellow
        }
    } catch {
        Write-ForensicLog "Error exporting $Description : $_" -Color Red
    }
}

# Function to copy database files
function Copy-DatabaseFile {
    param(
        [string]$SourcePath,
        [string]$DestinationName,
        [string]$Description
    )
    try {
        if (Test-Path $SourcePath) {
            $destPath = Join-Path $script:DBDir $DestinationName
            
            # Try to copy using shadow copy if file is locked
            try {
                Copy-Item -Path $SourcePath -Destination $destPath -Force
                Write-ForensicLog "Copied database: $Description" -Color Green
            } catch {
                # Attempt Volume Shadow Copy method
                $shadow = (gwmi -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
                $shadowPath = $SourcePath.Replace("C:\", "$($shadow.ShadowID)\")
                Copy-Item -Path $shadowPath -Destination $destPath -Force
                Write-ForensicLog "Copied database via VSS: $Description" -Color Green
            }
        } else {
            Write-ForensicLog "Database not found: $Description at $SourcePath" -Color Yellow
        }
    } catch {
        Write-ForensicLog "Error copying database $Description : $_" -Color Red
    }
}

# Initialize log
Write-ForensicLog "========================================="
Write-ForensicLog "Enhanced Windows Forensic Collection Started"
Write-ForensicLog "========================================="
Write-ForensicLog "Computer: $script:ComputerName"
Write-ForensicLog "User: $script:Username"
Write-ForensicLog "Output Directory: $script:OutputDir"
Write-ForensicLog ""

# ==============================================================================
# SYSTEM INFORMATION
# ==============================================================================
Write-ForensicLog "`n[COLLECTING SYSTEM INFORMATION]" -Color Cyan

$systemInfo = Get-CimInstance Win32_OperatingSystem | Select-Object @{
    Name='ComputerName'; Expression={$_.CSName}},
    Caption, Version, BuildNumber, OSArchitecture, 
    @{Name='InstallDate'; Expression={$_.InstallDate.ToString()}},
    @{Name='LastBootTime'; Expression={$_.LastBootUpTime.ToString()}},
    SystemDirectory, WindowsDirectory
Export-ForensicCSV -Data $systemInfo -FileName "System_Information" -Description "System Information"

$computerSystem = Get-CimInstance Win32_ComputerSystem | Select-Object 
    Manufacturer, Model, Domain, DomainRole, 
    @{Name='TotalPhysicalMemoryGB'; Expression={[math]::Round($_.TotalPhysicalMemory/1GB,2)}},
    NumberOfProcessors, NumberOfLogicalProcessors, SystemType
Export-ForensicCSV -Data $computerSystem -FileName "Computer_System" -Description "Computer System Info"

$timeZone = Get-TimeZone | Select-Object Id, DisplayName, StandardName, DaylightName, BaseUtcOffset
Export-ForensicCSV -Data $timeZone -FileName "TimeZone_Info" -Description "Time Zone Information"

# Control Set Information
$controlSet = Get-ItemProperty "HKLM:\SYSTEM\Select" | Select-Object Current, Default, Failed, LastKnownGood
Export-ForensicCSV -Data $controlSet -FileName "Control_Set" -Description "Control Set Configuration"

# ==============================================================================
# USER ACCOUNTS AND SECURITY
# ==============================================================================
Write-ForensicLog "`n[COLLECTING USER ACCOUNTS AND SECURITY]" -Color Cyan

$localUsers = Get-LocalUser | Select-Object Name, SID, Enabled, 
    @{Name='LastLogon'; Expression={if($_.LastLogon){$_.LastLogon.ToString()}else{"Never"}}},
    @{Name='PasswordLastSet'; Expression={if($_.PasswordLastSet){$_.PasswordLastSet.ToString()}else{"Never"}}},
    @{Name='PasswordExpires'; Expression={if($_.PasswordExpires){$_.PasswordExpires.ToString()}else{"Never"}}},
    PasswordRequired, UserMayChangePassword, Description
Export-ForensicCSV -Data $localUsers -FileName "Local_Users" -Description "Local User Accounts"

$localGroups = Get-LocalGroup | Select-Object Name, SID, Description
Export-ForensicCSV -Data $localGroups -FileName "Local_Groups" -Description "Local Groups"

# Group Memberships
$groupMemberships = @()
Get-LocalGroup | ForEach-Object {
    $groupName = $_.Name
    try {
        Get-LocalGroupMember -Group $groupName | ForEach-Object {
            $groupMemberships += [PSCustomObject]@{
                GroupName = $groupName
                MemberName = $_.Name
                MemberSID = $_.SID
                ObjectClass = $_.ObjectClass
            }
        }
    } catch {}
}
Export-ForensicCSV -Data $groupMemberships -FileName "Group_Memberships" -Description "Group Memberships"

# Failed Login Attempts from Security Log
$failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 2>$null | 
    Select-Object @{Name='Time'; Expression={$_.TimeCreated}},
    @{Name='Account'; Expression={$_.Properties[5].Value}},
    @{Name='Domain'; Expression={$_.Properties[6].Value}},
    @{Name='LogonType'; Expression={$_.Properties[10].Value}},
    @{Name='SourceIP'; Expression={$_.Properties[19].Value}}
Export-ForensicCSV -Data $failedLogins -FileName "Failed_Logins" -Description "Failed Login Attempts"

# Successful Logins
$successLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 100 2>$null |
    Select-Object @{Name='Time'; Expression={$_.TimeCreated}},
    @{Name='Account'; Expression={$_.Properties[5].Value}},
    @{Name='Domain'; Expression={$_.Properties[6].Value}},
    @{Name='LogonType'; Expression={$_.Properties[8].Value}},
    @{Name='ProcessName'; Expression={$_.Properties[9].Value}}
Export-ForensicCSV -Data $successLogins -FileName "Successful_Logins" -Description "Successful Login Events"

# ==============================================================================
# NETWORK CONFIGURATION
# ==============================================================================
Write-ForensicLog "`n[COLLECTING NETWORK CONFIGURATION]" -Color Cyan

$networkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, `
    MacAddress, LinkSpeed, MediaType, PhysicalMediaType, `
    @{Name='CreationTime'; Expression={$_.CreationTime.ToString()}}
Export-ForensicCSV -Data $networkAdapters -FileName "Network_Adapters" -Description "Network Adapters"

$ipConfig = Get-NetIPConfiguration | ForEach-Object {
    [PSCustomObject]@{
        InterfaceAlias = $_.InterfaceAlias
        InterfaceIndex = $_.InterfaceIndex
        IPv4Address = ($_.IPv4Address.IPAddress -join ", ")
        IPv6Address = ($_.IPv6Address.IPAddress -join ", ")
        IPv4Gateway = ($_.IPv4DefaultGateway.NextHop -join ", ")
        IPv6Gateway = ($_.IPv6DefaultGateway.NextHop -join ", ")
        DNSServer = ($_.DNSServer.ServerAddresses -join ", ")
    }
}
Export-ForensicCSV -Data $ipConfig -FileName "IP_Configuration" -Description "IP Configuration"

# WiFi Profiles with passwords (if available)
$wifiProfiles = @()
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $profileName = ($_ -split ":")[1].Trim()
    $profileDetails = netsh wlan show profile name="$profileName" key=clear
    $password = ($profileDetails | Select-String "Key Content" | Out-String).Split(":")[1].Trim()
    $wifiProfiles += [PSCustomObject]@{
        ProfileName = $profileName
        Password = if($password){"[STORED]"}else{"None"}
        Authentication = ($profileDetails | Select-String "Authentication" | Out-String).Split(":")[1].Trim()
    }
}
Export-ForensicCSV -Data $wifiProfiles -FileName "WiFi_Profiles" -Description "WiFi Profiles"

# Network Connections
$netConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, 
    RemoteAddress, RemotePort, State, OwningProcess,
    @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
    @{Name='CreationTime'; Expression={$_.CreationTime}}
Export-ForensicCSV -Data $netConnections -FileName "Network_Connections" -Description "Network Connections"

# DNS Cache
$dnsCache = Get-DnsClientCache | Select-Object Entry, Name, Type, 
    TimeToLive, DataLength, Data, Status
Export-ForensicCSV -Data $dnsCache -FileName "DNS_Cache" -Description "DNS Cache"

# ==============================================================================
# INSTALLED SOFTWARE
# ==============================================================================
Write-ForensicLog "`n[COLLECTING INSTALLED SOFTWARE]" -Color Cyan

$installedSoftware = @()
# Registry paths for installed software
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.DisplayName) {
            $installedSoftware += [PSCustomObject]@{
                DisplayName = $_.DisplayName
                DisplayVersion = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
                RegistryPath = $path.Replace("*","")
            }
        }
    }
}
Export-ForensicCSV -Data $installedSoftware -FileName "Installed_Software" -Description "Installed Software"

# Windows Store Apps
$storeApps = Get-AppxPackage | Select-Object Name, Publisher, Architecture, 
    Version, PackageFullName, InstallLocation, 
    @{Name='InstallTime'; Expression={$_.InstallTime.ToString()}}
Export-ForensicCSV -Data $storeApps -FileName "Windows_Store_Apps" -Description "Windows Store Apps"

# ==============================================================================
# USB DEVICE HISTORY
# ==============================================================================
Write-ForensicLog "`n[COLLECTING USB DEVICE HISTORY]" -Color Cyan

$usbDevices = @()
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | ForEach-Object {
    $usbDevices += [PSCustomObject]@{
        DeviceName = $_.FriendlyName
        SerialNumber = $_.PSChildName
        Manufacturer = $_.Mfg
        Service = $_.Service
        Class = $_.Class
        ClassGUID = $_.ClassGUID
        Driver = $_.Driver
        ContainerID = $_.ContainerID
        FirstInstallDate = if($_.FirstInstallDate){$_.FirstInstallDate}else{"Unknown"}
        LastArrivalDate = if($_.LastArrivalDate){$_.LastArrivalDate}else{"Unknown"}
        LastRemovalDate = if($_.LastRemovalDate){$_.LastRemovalDate}else{"Unknown"}
    }
}
Export-ForensicCSV -Data $usbDevices -FileName "USB_Devices" -Description "USB Device History"

# USB Device Setup Log
$setupApiLog = @()
$setupLogPath = "C:\Windows\INF\setupapi.dev.log"
if (Test-Path $setupLogPath) {
    Get-Content $setupLogPath | Select-String "USB" -Context 2,2 | ForEach-Object {
        $setupApiLog += [PSCustomObject]@{
            LineNumber = $_.LineNumber
            Line = $_.Line
            Context = ($_.Context.PreContext + $_.Context.PostContext) -join " "
        }
    }
}
Export-ForensicCSV -Data $setupApiLog -FileName "USB_Setup_Log" -Description "USB Setup API Log"

# MountPoints2 - Mapped drives per user
$mountPoints = @()
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*" -ErrorAction SilentlyContinue | ForEach-Object {
    $mountPoints += [PSCustomObject]@{
        MountPoint = $_.PSChildName
        Type = if($_.PSChildName -like "##*"){"Network Share"}else{"Local/USB"}
        User = $env:USERNAME
    }
}
Export-ForensicCSV -Data $mountPoints -FileName "Mount_Points" -Description "Mount Points"

# ==============================================================================
# APPLICATION EXECUTION HISTORY
# ==============================================================================
Write-ForensicLog "`n[COLLECTING APPLICATION EXECUTION HISTORY]" -Color Cyan

# Prefetch Files
$prefetchFiles = Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue | 
    Select-Object Name, 
    @{Name='CreationTime'; Expression={$_.CreationTime.ToString()}},
    @{Name='LastWriteTime'; Expression={$_.LastWriteTime.ToString()}},
    @{Name='LastAccessTime'; Expression={$_.LastAccessTime.ToString()}},
    Length
Export-ForensicCSV -Data $prefetchFiles -FileName "Prefetch_Files" -Description "Prefetch Files"

# UserAssist Registry
$userAssist = @()
$userAssistPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
Get-ChildItem $userAssistPath -ErrorAction SilentlyContinue | ForEach-Object {
    $guidPath = $_.PSPath
    Get-ItemProperty "$guidPath\Count" -ErrorAction SilentlyContinue | ForEach-Object {
        $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
            # Decode ROT13 encoded program names
            $encodedName = $_.Name
            $decodedName = ""
            for ($i = 0; $i -lt $encodedName.Length; $i++) {
                $char = [char]$encodedName[$i]
                if ($char -ge 'A' -and $char -le 'Z') {
                    $decodedChar = [char](((([int]$char - 65) + 13) % 26) + 65)
                } elseif ($char -ge 'a' -and $char -le 'z') {
                    $decodedChar = [char](((([int]$char - 97) + 13) % 26) + 97)
                } else {
                    $decodedChar = $char
                }
                $decodedName += $decodedChar
            }
            
            $userAssist += [PSCustomObject]@{
                EncodedPath = $encodedName
                DecodedPath = $decodedName
                RunCount = if($_.Value -and $_.Value.Length -ge 8){[BitConverter]::ToInt32($_.Value[4..7],0)}else{0}
                GUID = Split-Path $guidPath -Leaf
            }
        }
    }
}
Export-ForensicCSV -Data $userAssist -FileName "UserAssist" -Description "UserAssist Execution History"

# BAM/DAM (Background Activity Monitor)
$bamData = @()
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*"
Get-ChildItem $bamPath -ErrorAction SilentlyContinue | ForEach-Object {
    $userSID = Split-Path $_.PSPath -Leaf
    Get-ItemProperty $_.PSPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*" -and $_.Name -ne "Version"} | ForEach-Object {
            $bamData += [PSCustomObject]@{
                UserSID = $userSID
                ExecutablePath = $_.Name
                LastExecutionTime = if($_.Value){[DateTime]::FromFileTime([BitConverter]::ToInt64($_.Value,0)).ToString()}else{"Unknown"}
            }
        }
    }
}
Export-ForensicCSV -Data $bamData -FileName "BAM_Activity" -Description "Background Activity Monitor"

# System Resource Usage Monitor (SRUM)
$srumDb = "C:\Windows\System32\sru\SRUDB.dat"
Copy-DatabaseFile -SourcePath $srumDb -DestinationName "SRUDB.dat" -Description "SRUM Database"

# Recent Documents
$recentDocs = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
    Select-Object Name, 
    @{Name='Target'; Expression={if($_.Extension -eq ".lnk"){
        $sh = New-Object -ComObject WScript.Shell
        $sh.CreateShortcut($_.FullName).TargetPath
    }else{$_.FullName}}},
    @{Name='CreationTime'; Expression={$_.CreationTime.ToString()}},
    @{Name='LastAccessTime'; Expression={$_.LastAccessTime.ToString()}}
Export-ForensicCSV -Data $recentDocs -FileName "Recent_Documents" -Description "Recent Documents"

# Jump Lists
$jumpLists = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" -ErrorAction SilentlyContinue |
    Select-Object Name, Length, 
    @{Name='LastWriteTime'; Expression={$_.LastWriteTime.ToString()}}
Export-ForensicCSV -Data $jumpLists -FileName "Jump_Lists" -Description "Jump Lists"

# ==============================================================================
# BROWSER FORENSICS - CHROME
# ==============================================================================
Write-ForensicLog "`n[COLLECTING CHROME BROWSER ARTIFACTS]" -Color Cyan

$chromeProfiles = @()
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
if (Test-Path $chromePath) {
    Get-ChildItem $chromePath -Directory | Where-Object {$_.Name -like "Profile*" -or $_.Name -eq "Default"} | ForEach-Object {
        $profilePath = $_.FullName
        $profileName = $_.Name
        
        # Copy Chrome databases
        Copy-DatabaseFile -SourcePath "$profilePath\History" -DestinationName "Chrome_${profileName}_History.db" -Description "Chrome History ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Web Data" -DestinationName "Chrome_${profileName}_WebData.db" -Description "Chrome Web Data ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Cookies" -DestinationName "Chrome_${profileName}_Cookies.db" -Description "Chrome Cookies ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Login Data" -DestinationName "Chrome_${profileName}_LoginData.db" -Description "Chrome Login Data ($profileName)"
        
        # Parse Preferences file
        $prefsFile = "$profilePath\Preferences"
        if (Test-Path $prefsFile) {
            $prefs = Get-Content $prefsFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            $chromeProfiles += [PSCustomObject]@{
                ProfileName = $profileName
                ProfilePath = $profilePath
                AccountEmail = $prefs.account_info.email
                LastActiveTime = (Get-Item $prefsFile).LastWriteTime.ToString()
            }
        }
    }
}
Export-ForensicCSV -Data $chromeProfiles -FileName "Chrome_Profiles" -Description "Chrome Profiles"

# Chrome Extensions
$chromeExtensions = @()
if (Test-Path $chromePath) {
    Get-ChildItem "$chromePath\Default\Extensions" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extId = $_.Name
        $versions = Get-ChildItem $_.FullName -Directory
        foreach ($version in $versions) {
            $manifestPath = Join-Path $version.FullName "manifest.json"
            if (Test-Path $manifestPath) {
                $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                $chromeExtensions += [PSCustomObject]@{
                    ExtensionID = $extId
                    Name = $manifest.name
                    Version = $manifest.version
                    Description = $manifest.description
                    Permissions = ($manifest.permissions -join ", ")
                }
            }
        }
    }
}
Export-ForensicCSV -Data $chromeExtensions -FileName "Chrome_Extensions" -Description "Chrome Extensions"

# ==============================================================================
# BROWSER FORENSICS - EDGE
# ==============================================================================
Write-ForensicLog "`n[COLLECTING EDGE BROWSER ARTIFACTS]" -Color Cyan

$edgeProfiles = @()
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
if (Test-Path $edgePath) {
    Get-ChildItem $edgePath -Directory | Where-Object {$_.Name -like "Profile*" -or $_.Name -eq "Default"} | ForEach-Object {
        $profilePath = $_.FullName
        $profileName = $_.Name
        
        # Copy Edge databases
        Copy-DatabaseFile -SourcePath "$profilePath\History" -DestinationName "Edge_${profileName}_History.db" -Description "Edge History ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Web Data" -DestinationName "Edge_${profileName}_WebData.db" -Description "Edge Web Data ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Cookies" -DestinationName "Edge_${profileName}_Cookies.db" -Description "Edge Cookies ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\Collections\collectionsSQLite" -DestinationName "Edge_${profileName}_Collections.db" -Description "Edge Collections ($profileName)"
        
        $edgeProfiles += [PSCustomObject]@{
            ProfileName = $profileName
            ProfilePath = $profilePath
            LastActiveTime = (Get-Item $profilePath).LastWriteTime.ToString()
        }
    }
}
Export-ForensicCSV -Data $edgeProfiles -FileName "Edge_Profiles" -Description "Edge Profiles"

# ==============================================================================
# BROWSER FORENSICS - FIREFOX
# ==============================================================================
Write-ForensicLog "`n[COLLECTING FIREFOX BROWSER ARTIFACTS]" -Color Cyan

$firefoxProfiles = @()
$firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $firefoxPath) {
    Get-ChildItem $firefoxPath -Directory | ForEach-Object {
        $profilePath = $_.FullName
        $profileName = $_.Name
        
        # Copy Firefox databases
        Copy-DatabaseFile -SourcePath "$profilePath\places.sqlite" -DestinationName "Firefox_${profileName}_places.db" -Description "Firefox Places ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\cookies.sqlite" -DestinationName "Firefox_${profileName}_cookies.db" -Description "Firefox Cookies ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\formhistory.sqlite" -DestinationName "Firefox_${profileName}_formhistory.db" -Description "Firefox Form History ($profileName)"
        Copy-DatabaseFile -SourcePath "$profilePath\downloads.sqlite" -DestinationName "Firefox_${profileName}_downloads.db" -Description "Firefox Downloads ($profileName)"
        
        $firefoxProfiles += [PSCustomObject]@{
            ProfileName = $profileName
            ProfilePath = $profilePath
            LastActiveTime = (Get-Item $profilePath).LastWriteTime.ToString()
        }
    }
}
Export-ForensicCSV -Data $firefoxProfiles -FileName "Firefox_Profiles" -Description "Firefox Profiles"

# ==============================================================================
# BROWSER FORENSICS - INTERNET EXPLORER
# ==============================================================================
Write-ForensicLog "`n[COLLECTING INTERNET EXPLORER ARTIFACTS]" -Color Cyan

# IE Typed URLs
$ieTypedURLs = @()
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSObject.Properties | Where-Object {$_.Name -like "url*"} | ForEach-Object {
        $ieTypedURLs += [PSCustomObject]@{
            URLIndex = $_.Name
            URL = $_.Value
            User = $env:USERNAME
        }
    }
}
Export-ForensicCSV -Data $ieTypedURLs -FileName "IE_TypedURLs" -Description "Internet Explorer Typed URLs"

# WebCache.dat
$webCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\WebCacheV01.dat"
Copy-DatabaseFile -SourcePath $webCachePath -DestinationName "WebCacheV01.dat" -Description "IE/Edge WebCache Database"

# ==============================================================================
# EMAIL ARTIFACTS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING EMAIL ARTIFACTS]" -Color Cyan

# Outlook Profiles
$outlookProfiles = @()
$outlookVersions = @("16.0", "15.0", "14.0") # Office 2016+, 2013, 2010
foreach ($version in $outlookVersions) {
    $profilePath = "HKCU:\SOFTWARE\Microsoft\Office\$version\Outlook\Profiles"
    if (Test-Path $profilePath) {
        Get-ChildItem $profilePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Property -contains "Email") {
                $outlookProfiles += [PSCustomObject]@{
                    ProfileName = Split-Path $_.PSPath -Leaf
                    Email = (Get-ItemProperty $_.PSPath -Name "Email" -ErrorAction SilentlyContinue).Email
                    AccountName = (Get-ItemProperty $_.PSPath -Name "Account Name" -ErrorAction SilentlyContinue)."Account Name"
                    DisplayName = (Get-ItemProperty $_.PSPath -Name "Display Name" -ErrorAction SilentlyContinue)."Display Name"
                    SMTPServer = (Get-ItemProperty $_.PSPath -Name "SMTP Server" -ErrorAction SilentlyContinue)."SMTP Server"
                    OfficeVersion = $version
                }
            }
        }
    }
}
Export-ForensicCSV -Data $outlookProfiles -FileName "Outlook_Profiles" -Description "Outlook Email Profiles"

# PST/OST Files
$emailFiles = Get-ChildItem -Path $env:USERPROFILE -Include *.pst,*.ost -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, 
    @{Name='SizeMB'; Expression={[math]::Round($_.Length/1MB,2)}},
    @{Name='CreationTime'; Expression={$_.CreationTime.ToString()}},
    @{Name='LastWriteTime'; Expression={$_.LastWriteTime.ToString()}}
Export-ForensicCSV -Data $emailFiles -FileName "Email_PST_OST_Files" -Description "PST/OST Files"

# ==============================================================================
# CLOUD STORAGE
# ==============================================================================
Write-ForensicLog "`n[COLLECTING CLOUD STORAGE ARTIFACTS]" -Color Cyan

# OneDrive
$onedriveInfo = @()
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\*" -ErrorAction SilentlyContinue | ForEach-Object {
    $onedriveInfo += [PSCustomObject]@{
        AccountType = if($_.PSChildName -eq "Personal"){"Personal"}else{"Business"}
        UserEmail = $_.UserEmail
        UserFolder = $_.UserFolder
        CID = $_.cid
        LastSync = if($_.LastSyncTime){[DateTime]::FromFileTime($_.LastSyncTime).ToString()}else{"Unknown"}
    }
}
Export-ForensicCSV -Data $onedriveInfo -FileName "OneDrive_Accounts" -Description "OneDrive Configuration"

# OneDrive Sync Log
$onedriveLogs = @()
$onedriveLogPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs"
if (Test-Path $onedriveLogPath) {
    Get-ChildItem $onedriveLogPath -Filter "*.odl" -ErrorAction SilentlyContinue | 
        Select-Object -First 10 | ForEach-Object {
        $onedriveLogs += [PSCustomObject]@{
            LogFile = $_.Name
            Size = $_.Length
            LastWriteTime = $_.LastWriteTime.ToString()
        }
    }
}
Export-ForensicCSV -Data $onedriveLogs -FileName "OneDrive_Logs" -Description "OneDrive Log Files"

# Google Drive
$gdrivePath = "$env:LOCALAPPDATA\Google\Drive"
if (Test-Path $gdrivePath) {
    Copy-DatabaseFile -SourcePath "$gdrivePath\user_default\sync_config.db" -DestinationName "GoogleDrive_sync_config.db" -Description "Google Drive Sync Config"
    Copy-DatabaseFile -SourcePath "$gdrivePath\user_default\snapshot.db" -DestinationName "GoogleDrive_snapshot.db" -Description "Google Drive Snapshot"
}

# Dropbox
$dropboxPath = "$env:APPDATA\Dropbox"
if (Test-Path $dropboxPath) {
    Copy-DatabaseFile -SourcePath "$dropboxPath\instance1\config.dbx" -DestinationName "Dropbox_config.dbx" -Description "Dropbox Config"
    
    $dropboxInfo = @()
    $dropboxInfo += [PSCustomObject]@{
        ConfigPath = $dropboxPath
        HostID = if(Test-Path "$dropboxPath\host.db"){Get-Content "$dropboxPath\host.db" -Raw}else{"Not found"}
    }
    Export-ForensicCSV -Data $dropboxInfo -FileName "Dropbox_Info" -Description "Dropbox Information"
}

# ==============================================================================
# WINDOWS EVENT LOGS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING WINDOWS EVENT LOGS]" -Color Cyan

# Security Events
$securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634,4648,4672,4720,4722,4723,4724,4725,4726,4738,4740,4767} -MaxEvents 500 2>$null |
    Select-Object TimeCreated, Id, 
    @{Name='EventType'; Expression={
        switch($_.Id) {
            4624 {"Successful Logon"}
            4625 {"Failed Logon"}
            4634 {"Logoff"}
            4648 {"Explicit Credentials Logon"}
            4672 {"Special Privileges Assigned"}
            4720 {"User Account Created"}
            4722 {"User Account Enabled"}
            4723 {"Password Change Attempt"}
            4724 {"Password Reset Attempt"}
            4725 {"User Account Disabled"}
            4726 {"User Account Deleted"}
            4738 {"User Account Changed"}
            4740 {"User Account Locked"}
            4767 {"User Account Unlocked"}
            default {"Security Event"}
        }
    }},
    MachineName, Message
Export-ForensicCSV -Data $securityEvents -FileName "Security_Events" -Description "Security Event Log"

# RDP Events
$rdpEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 100 2>$null |
    Select-Object TimeCreated, Id, 
    @{Name='EventType'; Expression={
        switch($_.Id) {
            21 {"RDP Logon"}
            23 {"RDP Logoff"}
            24 {"RDP Disconnected"}
            25 {"RDP Reconnection"}
            default {"RDP Event"}
        }
    }},
    Message
Export-ForensicCSV -Data $rdpEvents -FileName "RDP_Events" -Description "RDP Connection Events"

# Application Events
$appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2,3} -MaxEvents 200 2>$null |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
Export-ForensicCSV -Data $appEvents -FileName "Application_Events" -Description "Application Event Log"

# System Events
$systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} -MaxEvents 200 2>$null |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
Export-ForensicCSV -Data $systemEvents -FileName "System_Events" -Description "System Event Log"

# PowerShell Events
$psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103,4104} -MaxEvents 100 2>$null |
    Select-Object TimeCreated, Id, Message
Export-ForensicCSV -Data $psEvents -FileName "PowerShell_Events" -Description "PowerShell Script Block Events"

# ==============================================================================
# REGISTRY FORENSICS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING REGISTRY ARTIFACTS]" -Color Cyan

# MRU Lists
$mruLists = @()

# Run MRU
$runMRU = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
if ($runMRU) {
    $runMRU.PSObject.Properties | Where-Object {$_.Name -match "^[a-z]$"} | ForEach-Object {
        $mruLists += [PSCustomObject]@{
            Type = "RunMRU"
            Index = $_.Name
            Value = $_.Value
        }
    }
}

# ComDlg32 OpenSave MRU
$openSaveMRU = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -ErrorAction SilentlyContinue
if ($openSaveMRU) {
    $openSaveMRU | ForEach-Object {
        $mruLists += [PSCustomObject]@{
            Type = "OpenSaveMRU"
            Extension = Split-Path $_.PSPath -Leaf
            Value = if($_.MRUListEx){[System.Text.Encoding]::Unicode.GetString($_.MRUListEx)}else{""}
        }
    }
}

Export-ForensicCSV -Data $mruLists -FileName "MRU_Lists" -Description "MRU Lists"

# Typed Paths
$typedPaths = @()
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSObject.Properties | Where-Object {$_.Name -like "url*"} | ForEach-Object {
        $typedPaths += [PSCustomObject]@{
            Index = $_.Name
            Path = $_.Value
        }
    }
}
Export-ForensicCSV -Data $typedPaths -FileName "Typed_Paths" -Description "Typed Paths"

# ShellBags
$shellBags = @()
function Get-ShellBags {
    param($Path, $Depth = 0)
    if ($Depth -gt 5) { return }
    
    Get-ChildItem $Path -ErrorAction SilentlyContinue | ForEach-Object {
        $shellBags += [PSCustomObject]@{
            Path = $_.PSPath
            Name = $_.PSChildName
            Depth = $Depth
        }
        Get-ShellBags -Path $_.PSPath -Depth ($Depth + 1)
    }
}
Get-ShellBags -Path "HKCU:\SOFTWARE\Microsoft\Windows\Shell\BagMRU"
Export-ForensicCSV -Data $shellBags -FileName "ShellBags" -Description "ShellBag Analysis"

# Startup Locations
$startupItems = @()
$startupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
)

foreach ($path in $startupPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
        $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
            $startupItems += [PSCustomObject]@{
                Location = $path
                Name = $_.Name
                Value = $_.Value
            }
        }
    }
}
Export-ForensicCSV -Data $startupItems -FileName "Startup_Registry" -Description "Registry Startup Items"

# ==============================================================================
# WINDOWS SEARCH INDEX
# ==============================================================================
Write-ForensicLog "`n[COLLECTING WINDOWS SEARCH INDEX]" -Color Cyan

$searchDb = "$env:PROGRAMDATA\Microsoft\Search\Data\Applications\Windows\Windows.edb"
Copy-DatabaseFile -SourcePath $searchDb -DestinationName "Windows_Search.edb" -Description "Windows Search Index Database"

# ==============================================================================
# RECYCLE BIN
# ==============================================================================
Write-ForensicLog "`n[COLLECTING RECYCLE BIN]" -Color Cyan

$recycleBin = @()
Get-ChildItem "C:\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -like "`$I*") {
        $infoFile = $_
        $dataFile = $_.FullName.Replace("`$I", "`$R")
        
        $recycleBin += [PSCustomObject]@{
            InfoFile = $infoFile.Name
            OriginalPath = "Parse from $I file"
            DeletedTime = $infoFile.CreationTime.ToString()
            Size = if(Test-Path $dataFile){(Get-Item $dataFile).Length}else{0}
            User = Split-Path (Split-Path $infoFile.FullName -Parent) -Leaf
        }
    }
}
Export-ForensicCSV -Data $recycleBin -FileName "Recycle_Bin" -Description "Recycle Bin Contents"

# ==============================================================================
# THUMBNAIL CACHE
# ==============================================================================
Write-ForensicLog "`n[COLLECTING THUMBNAIL CACHE]" -Color Cyan

$thumbcache = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache*.db" -ErrorAction SilentlyContinue |
    Select-Object Name, 
    @{Name='SizeMB'; Expression={[math]::Round($_.Length/1MB,2)}},
    @{Name='LastWriteTime'; Expression={$_.LastWriteTime.ToString()}}
Export-ForensicCSV -Data $thumbcache -FileName "Thumbcache_Files" -Description "Thumbnail Cache Files"

# Copy thumbcache files
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache*.db" -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-DatabaseFile -SourcePath $_.FullName -DestinationName $_.Name -Description "Thumbcache: $($_.Name)"
}

# ==============================================================================
# WINDOWS DEFENDER
# ==============================================================================
Write-ForensicLog "`n[COLLECTING WINDOWS DEFENDER DATA]" -Color Cyan

$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object *
Export-ForensicCSV -Data $defenderStatus -FileName "Defender_Status" -Description "Windows Defender Status"

$defenderThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue | 
    Select-Object DetectionID, ThreatName, ThreatID, 
    @{Name='DetectionTime'; Expression={$_.DetectionTime.ToString()}},
    @{Name='RemediationTime'; Expression={if($_.RemediationTime){$_.RemediationTime.ToString()}else{"Not Remediated"}}},
    ProcessName, Resources
Export-ForensicCSV -Data $defenderThreats -FileName "Defender_Threats" -Description "Windows Defender Threat History"

# ==============================================================================
# PROCESSES AND SERVICES
# ==============================================================================
Write-ForensicLog "`n[COLLECTING PROCESSES AND SERVICES]" -Color Cyan

$processes = Get-Process | Select-Object ProcessName, Id, 
    @{Name='StartTime'; Expression={if($_.StartTime){$_.StartTime.ToString()}else{"N/A"}}},
    @{Name='CPU'; Expression={$_.CPU}},
    @{Name='MemoryMB'; Expression={[math]::Round($_.WorkingSet64/1MB,2)}},
    Path, Company, ProductVersion, Description
Export-ForensicCSV -Data $processes -FileName "Running_Processes" -Description "Running Processes"

$services = Get-Service | Select-Object Name, DisplayName, Status, StartType,
    @{Name='Path'; Expression={(Get-WmiObject win32_service | Where-Object {$_.Name -eq $_.Name}).PathName}}
Export-ForensicCSV -Data $services -FileName "Windows_Services" -Description "Windows Services"

# ==============================================================================
# SCHEDULED TASKS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING SCHEDULED TASKS]" -Color Cyan

$scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, 
    @{Name='LastRunTime'; Expression={if($_.LastRunTime){$_.LastRunTime.ToString()}else{"Never"}}},
    @{Name='NextRunTime'; Expression={if($_.NextRunTime){$_.NextRunTime.ToString()}else{"N/A"}}},
    Author, Description,
    @{Name='Actions'; Expression={($_.Actions | ForEach-Object {$_.Execute}) -join ", "}}
Export-ForensicCSV -Data $scheduledTasks -FileName "Scheduled_Tasks" -Description "Scheduled Tasks"

# ==============================================================================
# WEBCAM AND MICROPHONE
# ==============================================================================
Write-ForensicLog "`n[COLLECTING WEBCAM AND MICROPHONE DATA]" -Color Cyan

$cameraDevices = Get-PnpDevice -Class Camera -ErrorAction SilentlyContinue | 
    Select-Object FriendlyName, Status, InstanceId, 
    @{Name='InstallDate'; Expression={(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.InstanceId)" -Name InstallDate -ErrorAction SilentlyContinue).InstallDate}}
Export-ForensicCSV -Data $cameraDevices -FileName "Camera_Devices" -Description "Camera Devices"

$audioDevices = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue | 
    Select-Object FriendlyName, Status, InstanceId
Export-ForensicCSV -Data $audioDevices -FileName "Audio_Devices" -Description "Audio Devices"

# Privacy Settings
$privacySettings = @()
$capabilityPaths = @("webcam", "microphone", "location")
foreach ($capability in $capabilityPaths) {
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$capability\*" -ErrorAction SilentlyContinue | ForEach-Object {
        $privacySettings += [PSCustomObject]@{
            Capability = $capability
            App = Split-Path $_.PSPath -Leaf
            Value = $_.Value
            LastUsedTime = if($_.LastUsedTimeStart){[DateTime]::FromFileTime($_.LastUsedTimeStart).ToString()}else{"Never"}
        }
    }
}
Export-ForensicCSV -Data $privacySettings -FileName "Privacy_Settings" -Description "App Privacy Settings"

# ==============================================================================
# FIREWALL CONFIGURATION
# ==============================================================================
Write-ForensicLog "`n[COLLECTING FIREWALL CONFIGURATION]" -Color Cyan

$firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, 
    DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules
Export-ForensicCSV -Data $firewallProfiles -FileName "Firewall_Profiles" -Description "Firewall Profiles"

$firewallRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | 
    Select-Object DisplayName, Name, Direction, Action, Protocol, LocalPort, RemotePort, Program
Export-ForensicCSV -Data $firewallRules -FileName "Firewall_Rules" -Description "Active Firewall Rules"

# ==============================================================================
# POWERSHELL HISTORY
# ==============================================================================
Write-ForensicLog "`n[COLLECTING POWERSHELL HISTORY]" -Color Cyan

$psHistory = @()
$psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistoryPath) {
    $historyContent = Get-Content $psHistoryPath
    $lineNumber = 1
    foreach ($line in $historyContent) {
        $psHistory += [PSCustomObject]@{
            LineNumber = $lineNumber
            Command = $line
            HistoryFile = $psHistoryPath
        }
        $lineNumber++
    }
}
Export-ForensicCSV -Data $psHistory -FileName "PowerShell_History" -Description "PowerShell Command History"

# ==============================================================================
# ALTERNATE DATA STREAMS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING ALTERNATE DATA STREAMS]" -Color Cyan

$adsFiles = @()
$searchPaths = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        Get-ChildItem $searchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'} | ForEach-Object {
                $adsFiles += [PSCustomObject]@{
                    FilePath = $_.FileName
                    Stream = $_.Stream
                    Length = $_.Length
                    Location = $searchPath
                }
            }
        }
    }
}
Export-ForensicCSV -Data $adsFiles -FileName "Alternate_Data_Streams" -Description "Files with Alternate Data Streams"

# ==============================================================================
# LNK FILES (SHORTCUTS)
# ==============================================================================
Write-ForensicLog "`n[COLLECTING LNK FILES]" -Color Cyan

$lnkFiles = @()
$shell = New-Object -ComObject WScript.Shell
Get-ChildItem "$env:USERPROFILE\Desktop\*.lnk", "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
    $shortcut = $shell.CreateShortcut($_.FullName)
    $lnkFiles += [PSCustomObject]@{
        LinkFile = $_.Name
        TargetPath = $shortcut.TargetPath
        Arguments = $shortcut.Arguments
        WorkingDirectory = $shortcut.WorkingDirectory
        IconLocation = $shortcut.IconLocation
        CreationTime = $_.CreationTime.ToString()
        LastAccessTime = $_.LastAccessTime.ToString()
    }
}
Export-ForensicCSV -Data $lnkFiles -FileName "LNK_Shortcuts" -Description "Shortcut Files Analysis"

# ==============================================================================
# BITLOCKER STATUS
# ==============================================================================
Write-ForensicLog "`n[COLLECTING BITLOCKER STATUS]" -Color Cyan

$bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | 
    Select-Object MountPoint, VolumeType, EncryptionMethod, VolumeStatus, 
    ProtectionStatus, LockStatus, EncryptionPercentage, KeyProtector
Export-ForensicCSV -Data $bitlockerVolumes -FileName "BitLocker_Status" -Description "BitLocker Encryption Status"

# ==============================================================================
# WINDOWS UPDATES
# ==============================================================================
Write-ForensicLog "`n[COLLECTING WINDOWS UPDATES]" -Color Cyan

$windowsUpdates = Get-HotFix | Select-Object Description, HotFixID, InstalledBy,
    @{Name='InstalledOn'; Expression={if($_.InstalledOn){$_.InstalledOn.ToString()}else{"Unknown"}}}
Export-ForensicCSV -Data $windowsUpdates -FileName "Windows_Updates" -Description "Installed Windows Updates"

# ==============================================================================
# OFFICE FILES HISTORY
# ==============================================================================
Write-ForensicLog "`n[COLLECTING OFFICE FILES HISTORY]" -Color Cyan

$officeHistory = @()
$officeVersions = @("16.0", "15.0", "14.0")
foreach ($version in $officeVersions) {
    $officePaths = @(
        "HKCU:\SOFTWARE\Microsoft\Office\$version\Word\File MRU",
        "HKCU:\SOFTWARE\Microsoft\Office\$version\Excel\File MRU",
        "HKCU:\SOFTWARE\Microsoft\Office\$version\PowerPoint\File MRU"
    )
    
    foreach ($path in $officePaths) {
        if (Test-Path $path) {
            $app = Split-Path $path -Leaf | ForEach-Object {$_.Replace("File MRU", "").Trim()}
            Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object {$_.Name -like "Item*"} | ForEach-Object {
                    $officeHistory += [PSCustomObject]@{
                        Application = $app
                        Version = $version
                        FilePath = $_.Value
                    }
                }
            }
        }
    }
}
Export-ForensicCSV -Data $officeHistory -FileName "Office_File_History" -Description "Microsoft Office Recent Files"

# ==============================================================================
# GENERATE SUMMARY REPORT
# ==============================================================================
Write-ForensicLog "`n[GENERATING SUMMARY REPORT]" -Color Cyan

$EndTime = Get-Date
$Duration = $EndTime - $script:StartTime

# Count artifacts collected
$csvCount = (Get-ChildItem $script:CSVDir -Filter "*.csv").Count
$dbCount = (Get-ChildItem $script:DBDir -Filter "*.*").Count

$summaryReport = @"
================================================================================
WINDOWS FORENSIC ARTIFACT COLLECTION REPORT
================================================================================
Collection Started: $($script:StartTime.ToString())
Collection Completed: $($EndTime.ToString())
Total Duration: $([math]::Round($Duration.TotalMinutes, 2)) minutes

Computer Name: $script:ComputerName
User Account: $script:Username
Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)
OS Version: $((Get-CimInstance Win32_OperatingSystem).Version)

Output Directory: $script:OutputDir
CSV Files Generated: $csvCount
Database Files Collected: $dbCount

================================================================================
ARTIFACTS COLLECTED
================================================================================
SYSTEM & CONFIGURATION:
- System Information
- User Accounts and Groups
- Password Policy and Security Settings
- Network Configuration and Connections
- Installed Software and Applications

USB & DEVICES:
- USB Device History (USBSTOR)
- Mount Points and Drive Mappings
- Plug-and-Play Devices
- Camera and Microphone Devices

APPLICATION EXECUTION:
- Prefetch Files
- UserAssist Registry
- BAM/DAM Activity Monitor
- Recent Documents
- Jump Lists
- LNK Shortcut Files

BROWSER FORENSICS:
- Chrome Profiles and Databases
- Edge Profiles and Databases
- Firefox Profiles and Databases
- Internet Explorer TypedURLs
- Browser Extensions

EMAIL & CLOUD:
- Outlook Profiles
- PST/OST Files
- OneDrive Configuration
- Google Drive Databases
- Dropbox Configuration

REGISTRY ARTIFACTS:
- MRU Lists
- Typed Paths
- ShellBags
- Startup Locations

EVENT LOGS:
- Security Events (Logon/Logoff)
- RDP Connection Events
- Application Events
- System Events
- PowerShell Script Block Events

WINDOWS ARTIFACTS:
- Windows Search Index
- Recycle Bin Contents
- Thumbnail Cache
- Alternate Data Streams
- SRUM Database

SECURITY:
- Windows Defender Status
- Firewall Configuration
- BitLocker Encryption
- Privacy Settings

================================================================================
NOTES
================================================================================
- All timestamps are in local system time
- Database files may require specialized tools for analysis
- CSV files can be imported into Excel or analysis tools
- Some artifacts may be missing due to permissions or system configuration

================================================================================
"@

$summaryReport | Out-File -FilePath (Join-Path $script:OutputDir "FORENSIC_SUMMARY.txt")

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "  FORENSIC COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output Directory: $script:OutputDir" -ForegroundColor Yellow
Write-Host "CSV Files: $csvCount" -ForegroundColor Yellow
Write-Host "Database Files: $dbCount" -ForegroundColor Yellow
Write-Host "Duration: $([math]::Round($Duration.TotalMinutes, 2)) minutes" -ForegroundColor Yellow
Write-Host ""
Write-Host "Review FORENSIC_SUMMARY.txt for detailed report" -ForegroundColor Cyan
