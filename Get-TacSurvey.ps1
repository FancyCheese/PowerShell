#FancyCheese 20180213
#This script runs some basic host enumeration and outputs the results into text files within a directory on the users desktop
#You must run this script from the directory that includes the 'Tools' Directory for the Sysinternals to function properly
#Ensure you run with Admin Priv
#This script accepts the -ComputerName paramter, if none provided the default is localhost
#==============================================================================================================================

#Parameterize the script
param(
    [string]$ComputerName = 'localhost'
)

#Create dir to store tact survey results
$Path = "$ENV:USERPROFILE\Desktop\$ComputerName TacSurvey"

#Test to see if path already exists
If(!(Test-Path $Path)) {
    New-Item -ItemType Directory -Force -Path $Path
}

#move into the dir
#Set-Location $Path

#Get the Date and convert to UTC
#========================================================================================

$DateTime = (Get-Date).ToUniversalTime()
$DateTime | Out-File $Path\DateTime.txt

#Get the current logged on users
#========================================================================================
$LoggedOnUsers = Get-WmiObject win32_loggedonuser -computername $ComputerName | Select-Object Antecedent -Unique 
$LoggedOnUsers | Out-File $Path\LoggedOnUsers.txt

#Pull a list of remote sessions
#========================================================================================

$NetSessions = net sessions 
$NetSessions | Out-File $Path\NetSessions.txt

#Verify Sysinternals tools are available then run them
#========================================================================================

$ToolsPath = Test-Path .\Tools
if ($ToolsPath -eq $true) {
    $LogonSessions = .\Tools\logonsessions.exe -accepteula -p 
    $LogonSessions | Out-File $Path\LogonSessions.txt
    $RemoteFiles = .\Tools\psfile.exe -accepteula
    $RemoteFiles | Out-File $Path\RemoteFiles.txt 
    #sigcheck.exe 
} else {
    Write-Host 'Required Tools directory not located, unable to leverage Sysinternals'
}

#list all shares
#========================================================================================

$FileShare = Get-WmiObject Win32_Share 
$FileShare | Out-File $Path\FileShare.txt

#List all current network connections
#Netstat -ano | out-file NetStat.txt 
#========================================================================================

$NetStatus = Get-NetTCPConnection | Sort-Object -Property state | Format-Table -AutoSize
$NetStatus | Out-File $Path\NetStatus.txt

#Grab a list of running processes
#========================================================================================

$Process = Get-WmiObject win32_process | Select-Object -Property Name, ProcessId, Path | Format-Table -AutoSize 
$Process | Out-File $Path\Process.txt 

#Pull Network Interface Info
#========================================================================================

$IpConfig = ipconfig.exe /all 
$IpConfig | Out-File $Path\IpConfig.txt

#Determine if any adapters are in promiscious mode
#========================================================================================

$Promisc = Get-NetAdapter | Select-Object -Property Name,PromiscuousMode 
$Promisc | Out-File $Path\Promiscous.txt

#Pull a list of running services 
#========================================================================================

$Services = Get-Service | Where-Object {$_.Status -eq "Running"}
$Services | Out-File $Path\Services.txt 

#Check the registry for programs set to start on boot 
#=======================================================================================
$HKLMRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$HKCURUnPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

$HKLMRun = Get-Item $HKLMRunPath | Format-Table -Autosize
$HKLMRun | out-file $Path\HKLMRun.txt

$HKCURun = Get-Item $HKCURUnPath | Format-Table -AutoSize
$HKCURUn | Out-File $Path\HKCURun.txt

#Pull Security Event Logs with EventID 4688 (New process creation)
#=======================================================================================
$Today = Get-Date                            
$Yesterday = $Today.AddDays(-1) 
$EventID = '4688'
$EventLog = 'Security'

$EventData = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{Logname="$EventLog";id="$EventID";starttime=$Yesterday;endtime=$Today} `
-ErrorAction SilentlyContinue
$EventData | Select-Object -Property timecreated, containerlog, id, taskdisplayname, keywordsdisplaynames, message | Out-File $Path\EventData.txt 

#Enumerate all members of the domain admin group
#=======================================================================================
$DomainAdmins = Get-ADGroupMember 'domain admins' -Recursive | Select-Object name,SamAccountName,SID | Format-Table -Wrap
$DomainAdmins | Out-File $Path\DomainAdmins.txt

#Enumerate DNS Cache
$DNSCache = ipconfig.exe /displaydns | Select-String 'Record Space'
$DNSCache | Out-File $Path\DNSCache.txt

#Clean-up Tools
#======================================================================================
<#
if ($ToolsPath -eq $true) {

    Remove-Item -Path .\Tools -Recurse -Force

}
#>

Write-Warning "Script Complete, the results are located in $Path" 