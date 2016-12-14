function Get-WMIEventLogins
{
<#
.DESCRIPTION
Will get remote login details from event log on remote hosts.
This can be used to find out where people are logging in from or
to find jump boxes.

.PARAMETER Target
List of targets. Will accept value from pipe.

.PARAMETER User
Username to connect to remote host

.PARAMETER Pass
Password to connect to remote host

.PARAMETER FileName
Path to save output to

.PARAMETER Read
If present, will display results to the console
#>
    
    Param
    (
        # Parameter Assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
		[Parameter(Mandatory = $False)]
        [string]$Pass,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$FileName,
        [Parameter(Mandatory = $False)]
        [boolean]$Read
    )

    Process {

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        Write-Verbose "Connecting to $Target"

        if($User)
        {
			$secpasswd = ConvertTo-SecureString $Pass -AsPlainText -Force
			$mycreds = New-Object System.Management.Automation.PSCredential ($User, $secpasswd)

            $temp = Get-WmiObject -computername $Target -Credential $mycreds -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"} | Out-File -Encoding ASCII -FilePath $FileName
            
            if($Read)
            {
                gc $temp | Select-String -pattern '(Workstation Name:)|(Account Name:)'
            }
        }

        else
        {
            $temp = Get-WmiObject -computername $Target -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"} | Out-File -Encoding ASCII -FilePath $FileName
            
            if($Read)
            {
                gc $temp | Select-String -pattern '(Workstation Name:)|(Account Name:)'
            }
        }
    }
}