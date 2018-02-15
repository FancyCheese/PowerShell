#===============================================================================================================================
#FancyCheese 
#updated 20180214
#DCO FINAL LAB
#===============================================================================================================================

#Assign the output directory to a variable to be reused.
$Path = "$ENV:USERPROFILE\Desktop\Final_Lab"

#Create the output directory 
New-Item -ItemType Directory -Path "$Path" -Force
New-Item -ItemType Directory -Path "$Path\ProcessResults\" -Force
New-Item -ItemType Directory -Path "$Path\Dead\" -Force
New-Item -ItemType Directory -Path "$Path\Alive\" -Force

#Generate a list of 26 ips into a textfile
1..26 | foreach {echo 214.15.6.$_ | out-file "$ENV:USERPROFILE\Desktop\Final_Lab\iplist.txt" -Append}

#Assign list of IPs into a variable
$IPs = Get-Content "$Path\iplist.txt" 

#Foreach loop to ping each IP address in the variable and ouput results into a live or dead textfile 
foreach ($IP in $IPs) { 
    $A = Test-Connection -ComputerName $IP -Count 1 -ErrorAction SilentlyContinue
    #If the Ping returns alive, put IP of host into live.txt
    if ($A.StatusCode -eq "0") {
        Write-Output "Computer: $IP is alive"; $IP | Out-File "$Path\Alive\live.txt" -Append
    }
    #If the ping doesnt return successful, output IP of host to dead.txt
    else {
        Write-Warning "Computer: $IP is not responding to Ping"; $IP | Out-File "$Path\Dead\dead.txt" -Append
    }
}

#Assign live IP addresses to Computer variable
$Computers = Get-Content "$Path\Alive\live.txt"
#Create a counter variable 
$Count = 0

#Get WMI Process from each of the live computers
foreach ($Computer in $Computers) {
    $GetWMI = Get-WmiObject Win32_Process | Select-Object ProcessName, ProcessID, ParentProcessID, CommandLine, ExecutablePath
    $GetWMI | out-file "$Path\ProcessResults\$Computer Process.txt"
   
    #For each loop to pull each processname and look for svchost and increase the counter each time one is found
    foreach ($WMI in $GetWMI) {  
        #If the WMI variable contains a process with the name of svchost, increase the counter by 1
        if ($WMI.ProcessName -eq 'svchost.exe') {
            $count++ 
            Write-Host "Found svchost.exe"
        }
    }   
    #Write a warning if the counter has increased to more than 4
    if ($count -ge 4) {
        Write-Warning "You found MALWARE on $Computer , you Win!"
    }    
}


