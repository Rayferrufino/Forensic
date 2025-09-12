# Forensic
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File "path\to\your\ForensicCollector.ps1" -Timeout="6000"
```

### Fully functional Windows artifact collector.
| Artifacts | 
| -------- | 
NTFS File System Overview 
Document and File Metadata 
Volume Shadow Copies 
File and Stream Carving 
Principles of Data Carving 
Recovering File System Metadata logs
File and Stream Carving logs
Memory, Pagefile, and Unallocated Space Analysis 
Chat Application logs
Extract sqlite databases for Internet Explorer, Edge, Firefox, Chrome
Email and Webmail Outlook logs
Hives, Keys, and Values logs
Registry Last Write Time logs
MRU Lists logs
Deleted Registry Key Recovery logs
Profile Users and Groups 
Discover Usernames and Relevant Security Identifiers 
Last Login 
Last Failed Login
Login Count
Password Policy 
Local versus Domain Account Profiling 
Core System Information 
Identify the Current Control Set 
System Name and Version 
Document the System Time Zone 
Installed Applications logs
Wireless, Wired, VPN, and Broadband Network logs
Perform Device Geolocation via Network Profiling logs
Identify System Updates and Last Shutdown Time 
Registry-Based Malware Persistence Mechanisms 
Identify Webcam and Microphone devices logs
Identify plug in devices 
File Downloads logs
Office and Microsoft 365 File History logs
Windows 7, Windows 8/8.1, Windows 10/11 Search History logs
Typed Paths and Directories logs
Recent Documents logs
Open Save/Run Dialog logs
Application Execution History via UserAssist logs
Prefetch logs
System Resource Usage Monitor (SRUM)logs
BAM/DAM logs
Universal Windows Platform (UWP) and MSIX registry hives logs
Microsoft OneDrive logs
OneDrive Unified Audit Logs 
Synchronization and Timestamps logs
User Activity Enumeration
Automating SQLite Database Parsing
Shell Item Forensics
Shortcut Files (LNK) logs
Windows 7-10 Jump Lists logs
ShellBag Analysis logs 
USB USBTOR logs
Vendor/Make/Version logs 
Unique Serial Number logs 
Last Drive Letter logs 
MountPoints2 and Drive Mapping Per User (Including Mapped Shares) logs 
Volume Name and Serial Number logs 
Username that Used the USB Device logs 
Time of First USB Device Connection logs 
Time of Last USB Device Connection logs 
Time of Last USB Device Removal logs 
Drive Capacity logs 
Auditing BYOD Devices at Scale logs 
Identify Malicious HID USB Devices logs 
Windows Search Index Database Forensics logs 
Extensible Storage Engine (ESE) Database Recovery and Repair logs 
Windows Thumbcache Analysis logs 
Windows Recycle Bin Analysis (XP, Windows 7-10) logs 
Connected Networks, Duration, and Bandwidth Usage logs 
Application Push Notifications logs 
Windows Event Log Analysis logs 
EVTX and EVT Log Files 
RDP logs
Geo-locate a Device via Event Logs
Browser Forensics 
History 
Cache 
Searches 
Downloads 
Chrome 
Chrome File Locations 
Correlating URLs and Visits Tables for Historical Context 
History and Page Transition Types 
Chrome Preferences File 
Web Data, Shortcuts, and Network Action Predictor Databases 
Chrome Timestamps 
Cache Examinations 
Download History 
Web Storage: IndexedDB, Local Storage, Session Storage, and Origin Private File System 
Chrome Session Recovery 
Chrome Profiles Feature 
Chromium Snapshots folder 
Identifying Cross-Device Chrome Synchronization 
Edge 
Chromium Edge vs. Google Chrome 
History, Cache, Web Storage, Cookies, Download History, and Session Recovery
Microsoft Edge Collections
Edge Internet Explorer Mode
Chrome and Edge Extensions
Edge Artifact Synchronization and Tracking Multiple Profiles
Internet Explorer
Internet Explorer Essentials and the Browser That Will Not Die 
WebCache.dat Database Examination 
Internet Explorer and Local File Access 
Electron and WebView2 Applications and Chat Client Forensics 
Electron Application Structure 
Electron Chromium Cache 
LevelDB Structure and Tools 
Manual Parsing of LevelDB 
Specialized LevelDB parsers and tools 
Firefox
Firefox Artifact Locations
SQLite Files and Firefox Quantum Updates 
Download History 
Firefox Cache2 Examinations 
Detailed Visit Type Data 
Form History 
Session Recovery 
Firefox Extensions 
Firefox Cross-Device Synchronization 
Private Browsing and Browser Artifact Recovery 
Chrome, Edge, and Firefox Private Browsing 
SQLite and ESE Database Carving and Examination of Additional Browser Artifacts 
