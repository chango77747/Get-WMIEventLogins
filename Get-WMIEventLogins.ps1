# Command to reconstruct on the backend if ChunkSize was specified
# Assumes that $FileName on backend system is the same as the $FileName specified on the target system where the rest of this script was run

#$ReconstructedResultFile = $FileName + ".RECONSTRUCTED.txt"
#If(Test-Path $ReconstructedResultFile) {Remove-Item $ReconstructedResultFile}
#Get-ChildItem $FileName* | ForEach-Object {(Get-Content $_ | Where-Object {$_.Length -gt 0}) >> $ReconstructedResultFile}
#Notepad $ReconstructedResultFile


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

.PARAMETER ChunkSize
Size (in bytes) of output file chunks if FileName is selected

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
        [int]$ChunkSize,
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

            # Memory-only version
            $Results = @()
            Get-WmiObject -computername $Target -Credential $mycreds -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | ForEach-Object {
                If($_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp")
                {
                    $Results += $_.Message.Split("`n") | Select-String -Pattern "`tAccount Name:|`tWorkstation Name:"
                }
            }
        }

        else
        {
            # Memory-only version
            $Results = @()
            Get-WmiObject -computername $Target -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | ForEach-Object {
                If($_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp")
                {
                    $Results += $_.Message.Split("`n") | Select-String -Pattern "`tAccount Name:|`tWorkstation Name:"
                }
            }
        }

        # Output to disk if selected
        if($FileName)
        {
            # Chunk output if ChunkSize is selected
            if($ChunkSize)
            {
                $Counter = 0
                $Results | ForEach-Object {
                    If((Test-Path $FileName) -AND ((Get-Item $FileName).Length -gt $ChunkSize))
                    {
                        $Counter++
                        If($FileName.EndsWith('.'+($Counter-1))) {$FileName = $FileName.SubString(0,$FileName.LastIndexOf('.'))}
                        $FileName = "$FileName.$Counter"
                    }
                    Write-Output $_ >> $FileName
                }
            }
            Else
            {
                Write-Output $Results > $FileName
            }
        }
        if($Read)
        {
            Write-Output $Results
        }

    }
}