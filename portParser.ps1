<#
.SYNOPSIS
    Sometimes an administrator wants to know which application is opening a specific port.
    In that case he could execute netstat -b.
    Unfortunately some applications open ports in an unforeseeable manner.
    Therefore it would be helpfull to execute a script which listens for that specific port and writes a logfile of it occurence in the netstat output.
    This script does exactly that!
.DESCRIPTION
    Currently the script is kept as simple as possible. In the future it should be modularized, configured via parameters and written following the Powershell standards. The user must have administrator rights for the execution (this should be the case if he is able to install software which opens some unknown ports..).
    Installation Steps:
    1.Modify the portList in the TcpPortMon.ps1 file.
    2.Create Directory C:\TcpPortMon.
    3.Copy TcpPortMon.ps1 and TcpPortMon_TaskScheduler.xmlinto this directory.
    4.Start the Windows TaskScheduler and import the XML file as new task.
    5.Change the User of the task to your own user.
    6.Hit OK twice and insert your passwort.

    Now the script should log something into the file C:\TcpPortMon\PortReport_YEAR-MONTH-DAY.txt on every minute.

.PARAMETER outDir
    The path to the file (does not need to exist) where the results of a positive scan are stored.
    This file should be kept and sent to your demanding ISO.
.PARAMETER p
    If You want to parse your open ports for a single port set this parameter.
    (Only possible to be set if range is not set.)
.PARAMETER range
    If You want to parse for a range of ports, set this parameter in this syntax-style:
    -range pLower,pUpper
    e.g.: -range 10000,32000
    (Only possible to be set if port is not set.)
.EXAMPLE
    .\scan.ps1 -range 20,250
    <Scans for given 231 Ports wether they are listed in output of netstat.exe or not.>
.NOTES
    Author: Lars Richter
    Date:   September 23, 2016    
#>

param(
    [Parameter(ParameterSetName='One',Position=0)][int[]]$range = @(),
    [Parameter(ParameterSetName='One',Position=0)][int]$p,
    [Parameter(Mandatory=$false,Position=2)][string]$outDir = "C:\TcpPortMon\"
)
Write-Host "Type: 'get-help .\scan.ps1 -detailed' for detailled information"
#first thing to do ... determine admin rights
Write-Host "Running as Admin?"
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`

    [Security.Principal.WindowsBuiltInRole] “Administrator”))

{
    Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
    Write-Warning "If You are not certain about this script's origin, please contact Your local InfoSec Officer!"
    exit 1
}else{
    Write-Host "Checked..."
}

If (($range.Length -gt 2) -Or ($range[0] -gt $range[1]))
    {
        Write-Host "Wrong usage of parameter range."
        Write-Host "Only two comma seperated values allowed."
        Write-Host "First number has to be <= 2nd number."
        Write-Host "e.g.: -range 1,300"
        exit 1
    }        
if ($range -And $p){
    Write-Host "Only one parameter allowed!"
    Write-Host "[-p OR -range]"
    exit 2
    }
#determining enverionmental variables....
$userName = [Environment]::UserName
$userDomainName  = [Environment]::UserDomainName
$machineName = [Environment]::MachineName
$dataWritten = $false
# Get Stringbuilder and dates
$info = new-object system.text.stringbuilder
$currentTime = get-date -uformat '%Y-%m-%dT%H:%M:%S'
$currentDate = get-date -uformat '%Y-%m-%d'
# Create file and write info
$outFile = $outDir + "PortReport_" + $currentTime.Replace(":","_") +"_"+ $userName + "_" + $machineName + ".txt"
# Create directory if it doesn’t exist and setup file for output
if((Test-Path $outDir) -eq $FALSE)
    {
      New-Item $outDir -type directory
    }
#Execute netstat
Write-Host "Trying to execute Netstat.exe -no"
If($data = netstat -no){
    Write-Host "Netstat.exe -no command successfully executed"
    }else{
        Write-Warning "netstat.exe could not be executed: Please contact Your ISO."
        exit 1
    }
if((Test-Path $outDir) -eq $FALSE)
    {
      New-Item $outDir -type directory
    }

if ($p){
    $range += $p
}
# Script can start...
    $rangeTranslated = @();
    $buffer = 0;
    if($range.Length -gt 1){        
        for($i = $range[0]; $i -lt $range[1]+1; $i++){
            $rangeTranslated += [int32]$i;
        }
    }else{
        $rangeTranslated = $range
    }
    Write-Host "Parsing results of netstat-cmd for"$rangeTranslated.Length"port(s)..."
    #some "make the output-lines cleaner"-stuff to do...
    #Keep only the line with the data (remove the first lines with header data of netstat output)
    $data = $data[4..$data.count]
    $switch = false
    #parse through every entry (line) of netstat output
    for($i = 0; $i -lt $data.Length; $i++){
        #Write-Host $i + ". " + $data[$i];
        $line = $data[$i];
        # Get rid of the first whitespaces, at the beginning of the line
        $line = $line -replace '^\s+', ''
        
        # Split each property on whitespaces block
        $line = $line -split '\s+'
        
        if($line[4] -gt 0){
            $proc = (get-process -id $line[4]) -split '\s+'
            $proc = $proc -replace "`n",""
            $line += $proc[1]
        }else{
            $line += "-"
        }
        
        # Define the properties
        $properties = @{
            Protocole = $line[0]
            LocalAddressIP = ($line[1] -split ":")[0]
            LocalAddressPort = [int]($line[1] -split ":")[1]
            ForeignAddressIP = ($line[2] -split ":")[0]
            ForeignAddressPort = [int]($line[2] -split ":")[1]
            State = $line[3]
            PID = $line[4]
            Process = $line[5]
        }
        if($rangeTranslated -contains $properties["LocalAddressPort"]){
            New-Object -TypeName PSObject -Property $properties | out-file $outFile -append -noclobber
            $dataWritten = $true
        }
    }

if($dataWritten){
    "The script has found processes matching the given ports by the user."
    "Data has been written to file: " + $outFile
    "Appending additional user data to file..."
    ("Machine: " + $machineName +"`nUsername: " + $userName + "`nUser Domain Name: " + $userDomainName + "`nScanned Port-No's: " + $range + " [" + $rangeTranslated.Length + " port(s)]")  | Out-File $outFile -Append -NoClobber
}else{
    "Nothing matched to the given arguments.`nNothing stored."
}
