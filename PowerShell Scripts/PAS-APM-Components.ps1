Function GetServiceInfo {
	param($MonitorType, $svcName, $HostName, $ScriptVersion, $DateTime, $LogServer, $logPort)
	
	$doRegSrch = $false
	$isPSM = $false
	
	$ServiceName = Get-Service $svcName -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders Name | Out-String
	if ($ServiceName.length -gt 0) {
		$ServiceStatus = Get-Service $svcName | Format-Table -HideTableHeaders Status | Out-String
		If ($ServiceStatus -like "*Running*") { $ServiceStatusNumeric = 1 } else { $ServiceStatusNumeric = 0 }
		if ($svcName -eq "Cyberark Password Manager") {
			$regSrch = "*Central Policy Manager*"
			$doRegSrch = $true
		} elseif ($svcName -eq "Cyber-Ark Privileged Session Manager") {
			$regSrch = "*Privileged Session Manager*"
			$doRegSrch = $true
			$isPSM = $true
		} elseif ($svcName -eq "W3SVC") {
			$regSrch = "*Password Vault Web Access*"
			$doRegSrch = $true
		}
		if ($doRegSrch) {
			$SoftwareName = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like $regSrch | Select-Object DisplayName | Select -first 1 | Format-Table -HideTableHeaders | Out-String
			$SoftwareVersion = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like $regSrch | Select-Object DisplayVersion | Select -first 1 | Format-Table -HideTableHeaders | Out-String
			$syslogoutput = "<5>1 $DateTime $HostName CEF:0|CyberArk|$MonitorType|$ScriptVersion|$HostName|$ServiceName|$ServiceStatus|$ServiceStatusNumeric|$SoftwareName|$SoftwareVersion"
		} else {
			$syslogoutput = "<5>1 $DateTime $HostName CEF:0|CyberArk|$MonitorType|$ScriptVersion|$HostName|$ServiceName|$ServiceStatus|$ServiceStatusNumeric"
		}
		SendSyslog -syslogMsg $syslogoutput -syslogSrv $LogServer -syslogPort $logPort
		if ($isPSM) {
            #
            # this needs the remotedesktop module to be loaded.
            # check to see if it's loaded, if not load the remotedesktop module
            if (Get-Module -ListAvailable -Name "RemoteDesktop") {
                $rdsmod = Get-Module -Name "RemoteDesktop"
                if ($rdsmod -eq $Null) {
                    Import-Module "RemoteDesktop"
                }
            }
			$PSMSessionCount = Get-RDUserSession | Measure-Object | Format-Table -HideTableHeaders Count | Out-String
			$syslogoutput = "<5>1 $DateTime $HostName CEF:0|CyberArk|$MonitorType|$Version|$HostName|Remote Desktop User Sessions|$PSMSessionCount"
			SendSyslog -syslogMsg $syslogoutput -syslogSrv $LogServer -syslogPort $logPort
		}
	}
}

Function SendSyslog {
	param($syslogMsg, $syslogSrv, $syslogPort)
	
	#cleanup command to remove new lines and carriage returns
	$syslogoutputclean = $syslogMsg -replace "`n|`r"
	$syslogoutputclean | ConvertTo-Json
	#send syslog to SIEM
	$UDPCLient = New-Object System.Net.Sockets.UdpClient
	$UDPCLient.Connect($SYSLOGSERVER, $PORT)
	$Encoding = [System.Text.Encoding]::ASCII
	$ByteSyslogMessage = $Encoding.GetBytes(''+$syslogoutputclean+'')
	$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length)
}

#Service Status Check for Component Server
$Version = "1.0.0001"
$compName = "$env:computername"
$Date = Get-Date
$Date_Time = $DATE.ToString("yyyy-MM-ddTHH:mm:ssZ")

# syslog server/SIEM info
$PORT = 51444
# chage SYSLOGSERVER to the IP Address of your SIEM
$SYSLOGSERVER="192.168.232.4"

# Service array for the different component servers, add services as required
$svcArray = @("Cyberark Password Manager", "Cyberark Central Policy Manager Scanner", "CyberArk Vault-Conjur Synchronizer", "Cyber-Ark Privileged Session Manager", "W3SVC", "TermService")

foreach($svc in $svcArray) {
	GetServiceInfo -MonitorType "ApplicationMonitor" -SvcName $svc -HostName $compName -ScriptVersion $Version -DateTime $Date_Time -LogServer $SYSLOGSERVER -logPort $PORT
}

##Hardware Performance Checks
$MonitorType = "HardwareMonitor"
$CPU = Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average | Format-Table -HideTableHeaders Average | Out-String
$os = Get-Ciminstance Win32_OperatingSystem
$FreePhysicalMemory = $os.FreePhysicalMemory
$FreePhysicalMemoryMB = $FreePhysicalMemory / 1024
$TotalPhysicalMemoryMB = Get-WMIObject Win32_PhysicalMemory | Measure -Property capacity -Sum | %{$_.sum/1Mb}
$PercentageUsedPhysicalMemory = ($TotalPhysicalMemoryMB - $FreePhysicalMemoryMB) / $TotalPhysicalMemoryMB * 100
$MemoryDecimal = $PercentageUsedPhysicalMemory
$Memory = [math]::Round($MemoryDecimal,1)
#$TotalSpace = get-WmiObject win32_logicaldisk | Where-Object{$_.DeviceID -like "*C*"} | Format-Table -HideTableHeaders Size | Out-String
#$FreeSpace = get-WmiObject win32_logicaldisk | Where-Object{$_.DeviceID -like "*C*"} | Format-Table -HideTableHeaders FreeSpace | Out-String
#$TotalSpaceGBDecimal = $TotalSpace / 1073741824
#$FreeSpaceGBDecimal = $FreeSpace / 1073741824
#$TotalSpaceGB = [math]::Round($TotalSpaceGBDecimal,1)
#$FreeSpaceGB = [math]::Round($FreeSpaceGBDecimal,1)
#$syslogoutput = "<5>1 $Date_Time $compName CEF:0|CyberArk|$MonitorType|$Version|$compName|$CPU|$Memory|$TotalSpaceGB|$FreeSpaceGB"
#SendSyslog -syslogMsg $syslogoutput -syslogSrv $LogServer -syslogPort $logPort
#
# check to see if there are other drives attached to this computer and generate syslog messages about it's capaity and freespace
#foreach ($disk in $(Get-WmiObject  -Class Win32_LogicalDisk -Filter "DriveType = 3 And DeviceID <> 'C:'" | Select-Object -Property DeviceID,
foreach ($disk in $(Get-WmiObject  -Class Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object -Property DeviceID,
    @{L='FreeSpaceGB';E={{"{0:N0}"} -f ($_.FreeSpace/1GB)}},  @{L='CapacityGB';E={{"{0:N0}"} -f ($_.Size/1GB)}}))
{
    $FS = $disk.FreeSpaceGB.REplace('"','')
    $SZ = $disk.CapacityGB.REplace('"','')
    $DRV = $disk.DeviceID
    $syslogoutput = "<5>1 $Date_Time $compName CEF:0|CyberArk|$MonitorType|$Version|$compName|$CPU|$Memory|$SZ|$FS|$DRV"
    SendSyslog -syslogMsg $syslogoutput -syslogSrv $SYSLOGSERVER -syslogPort $PORT
}

#OS System Information
$MonitorType = "OSMonitor"
$OSName = (Get-WmiObject Win32_OperatingSystem).Caption | Out-String
$OSVersion = (Get-WmiObject Win32_OperatingSystem).Version | Out-String
$OSServPack = (Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion | Out-String
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture | Out-String
$syslogoutput = "<5>1 $Date_Time $compName CEF:0|CyberArk|$MonitorType|$Version|$compName|$OSName|$OSVersion|$OSServPack|$OSArchitecture"
SendSyslog -syslogMsg $syslogoutput -syslogSrv $LogServer -syslogPort $logPort
