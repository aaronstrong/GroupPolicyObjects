# Website with all the registry values
# https://getadmx.com
#
# Purpose of this is to create a good baseline GPO

$gpoName = "Base Users"
$rdsLicenseServer = "rdslicense.domain.local"
$LogPath = "D:\EventsLogs"
$upmUserStore = "\\SMBShare\sharename\#SAMAccountName#\!CTX_OSNAME!!CTX_PROFILEVER!"
$CitrixXenApp = 'Y' # Change to N if not required
$CitrixUPM = 'Y' # Change to N if not required

new-gpo -Name $gpoName

#--------------------------#
#    Computer Policies     #
#--------------------------#

# --- RDS Settings --- #
# Loopback Policy
# value 2 = Replace Mode, value 1 = Merge
Set-GPRegistryValue -Name $gpoName -key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName UserPolicyMode -Type DWORD -Value 2

# RDS Licenses
Set-GPRegistryValue -Name $gpoName -key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName LicenseServers -Value $rdsLicenseServer -Type String

# RDS License Mode
# value 2 = Per Device, value 4 = Per User
Set-GPRegistryValue -Name $gpoName -key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName LicensingMode -Value 2 -Type DWord

# RDS Session Time Limits
#  Active but Idle Session. Will automatically disconnect active but idle sessions
#  Value 0 = Never
#  Value 1800000 = 30 Minutes
#  Value 3600000 = 60 Minutes
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName MaxIdleTime -Value 1800000 -Type DWord

# --- Timeouts for IDLE and Disconnected Sessions --- #

#  Time limit for disconnected sessions
#  Value 0 = Never
#  Value 300000 = 5 Minutes
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName MaxDisconnectionTime -Value 300000 -Type DWord

# Disable Windows Update Notification
#  1 = Enabled, 0 = Disabled
Set-GPRegistryValue -Name $gpoName -key "HKLM\Software\Policies\Microsoft\Windows\Windows Update" -ValueName ElevateNonAdmins -Value 0 -Type DWord

# Preview for Windows Builds
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName DeferFeatureUpdates -Value 1 -Type DWord # 0 disable, 1 enable
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName BranchReadinessLevel -Value 16 -Type DWord
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName DeferFeatureUpdatesPeriodInDays -Value 365 -Type DWord

# --- Redirect Logs --- #

# Redirect Logs
#  Event Log
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" -ValueName File -Value "$LogPath\Application.evtx" -Type String
#  Security Log
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName File -Value "$LogPath\Security.evtx" -Type String
#  System Log
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" -ValueName File -Value "$LogPath\System.evtx" -Type String
#  Make Folder

# Add Administrators security Group to Roaming User Profiles
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName AddAdminGroupToRUP -Value 1 -Type DWord # 0 disable, 1 enable

# Set Maximum wait time for Network if roaming profile
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName WaitForNetwork -Value 0 -Type DWord # max value 300

# Configure Group Policy Cache
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName EnableLogonOptimization -Value 0 -Type DWord # 0 disable, 1 enable

# Configure Login Script delay
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName EnableLogonScriptDelay -Value 1 -Type DWord # 0 to disable, 1 enable
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName AsyncScriptDelay -Value 0 -Type DWord

# Disable Windows 10 "we're happy" message
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName EnableFirstLogonAnimation -Value 0 -Type DWord

# Disable Cortana
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\Windows Search" -ValueName AllowCortana -Value 0 -Type DWord # 0 disable, 1 enable

# Don't search the web or display web results in search
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\Windows Search" -ValueName ConnectedSearchUseWeb -Value 0 -Type DWord

# Don't allow web search
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\Windows Search" -ValueName DisableWebSearch -Value 0 -Type DWord

# Always wait for Network
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName SyncForeGroundPolicy -Value 0 -Type DWord

# --- Citrix UPM --- #
if($CitrixUPM -eq 'Y')
{
    # Enable Profile Management
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager" -ValueName ServiceActive -Value 1 -Type DWord

    # process logons of local administrators
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager" -ValueName ProcessAdmins -Value 1 -Type DWord

    # Path to user store
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager" -ValueName PathToUserStore -Value $upmUserStore -Type String

    # Active Write back
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager" -ValueName PSMidSessionWriteBack -Value 1 -Type DWord

    # Process internet cookie files on logoff
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager" -ValueName ProcessCookieFiles -Value 1 -Type DWord

    # Enable Default Exclusion List - Directories
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir" -ValueName Enabled -Value 1 -Type DWord
    #  List of Directories to exclude:
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir\List" -ValueName 1 -Value "AppData\Local\Microsoft\Windows\INetCache" -Type String
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir\List" -ValueName 2 -Value "AppData\Local\Microsoft\Internet Explorer\DOMStore" -Type String
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir\List" -ValueName 3 -Value "AppData\Local\Google\Chrome\User Data\Default\Media Cache" -Type String
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir\List" -ValueName 4 -Value "AppData\Local\Google\Software Reporter Tool" -Type String

}

# --- Citrix XenApp Specific --- #
if($CitrixXenApp -eq 'Y')
{
    # Allow asynchronous user Group Policy processing when logging on through RDS
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName ProcessTSUserLogonAsnc -Value 1 -Type DWord
}

#--------------------------#
#    User Policies         #
#--------------------------#
