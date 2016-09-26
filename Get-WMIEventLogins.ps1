function Get-WMIEventLogins
{
<#
.DESCRIPTION
Will get remote login details from event log on remote hosts.
This can be used to find out where people are logging in from or
to find jump boxes.

.PARAMETER Targets
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
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$FileName,
        [Parameter(Mandatory = $False)]
        [string]$Read
    )

    Process {

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$FileName)
        {
            $FileName = Read-Host "Where would you like the output saved to? >"
        }

        if(!$Read)
        {
            $Read = Read-Host "Would you like the output displayed to the console? [y/n] >"
            $Read = $Read.Trim().ToLower()
        }

        Write-Verbose "Connecting to $Target"

        if($Creds)
        {
            $temp = Get-WmiObject -computername $Target -Credential $Creds -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"} | Out-File -Encoding ASCII -FilePath $FileName
            
            if(($Read -eq "yes") -or ($Read -eq "y"))
            {
                gc $FileName | Select-String -pattern '(Workstation Name:)|(Account Name:)'
            }
        }

        else
        {
            $temp = Get-WmiObject -computername $Target -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"} | Out-File -Encoding ASCII -FilePath $FileName
            
            if(($Read -eq "yes") -or ($Read -eq "y"))
            {
                gc $FileName | Select-String -pattern '(Workstation Name:)|(Account Name:)'
            }
        }
    }
}