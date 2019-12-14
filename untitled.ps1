<#----------------------------------------------------------------------------
LEGAL DISCLAIMER 
This Sample Code is provided for the purpose of illustration only and is not 
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY 
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER 
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a 
nonexclusive, royalty-free right to use and modify the Sample Code and to 
reproduce and distribute the object code form of the Sample Code, provided 
that You agree: (i) to not use Our name, logo, or trademarks to market Your 
software product in which the Sample Code is embedded; (ii) to include a valid 
copyright notice on Your software product in which the Sample Code is embedded; 
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and 
against any claims or lawsuits, including attorneys’ fees, that arise or result 
from the use or distribution of the Sample Code. 
  
This posting is provided "AS IS" with no warranties, and confers no rights. Use 
of included script samples are subject to the terms specified 
at http://www.microsoft.com/info/cpyright.htm. 
Written by Moti Bani - mobani@microsoft.com - (http://blogs.technet.com/b/motiba/) 
With script portions copied from http://psvirustotal.codeplex.com
Reviewed and edited by Martin Schvartzman 
#>


Add-Type -assembly System.Security

function Get-Hash() {

    param([string] $FilePath)
    
    $fileStream = [System.IO.File]::OpenRead($FilePath)
    $hash = ([System.Security.Cryptography.HashAlgorithm]::Create('SHA256')).ComputeHash($fileStream)
    $fileStream.Close()
    $fileStream.Dispose()
    [System.Bitconverter]::tostring($hash).replace('-','')
}


function Query-VirusTotal {

    param([string]$Hash)
    
    $body = @{ resource = $hash; apikey = $VTApiKey }
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    $AVScanFound = @()

    if ($VTReport.positives -gt 0) {
        foreach($scan in ($VTReport.scans | Get-Member -type NoteProperty)) {
            if($scan.Definition -match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})") {
                if($Matches.detected -eq "True") {
                    $AVScanFound += "{0}({1}) - {2}" -f $scan.Name, $Matches.version, $Matches.result
                }
            }
        }
    }

    New-Object –TypeName PSObject -Property ([ordered]@{
        MD5       = $VTReport.MD5
        SHA1      = $VTReport.SHA1
        SHA256    = $VTReport.SHA256
        VTLink    = $VTReport.permalink
        VTReport  = "$($VTReport.positives)/$($VTReport.total)"
        VTMessage = $VTReport.verbose_msg
        Engines   = $AVScanFound
    })
}


function Get-VirusTotalReport {
    
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$VTApiKey,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true, ParameterSetName='byHash')]
        [String[]] $Hash,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='byPath')]
        [Alias('Path', 'FullName')]
        [String[]] $FilePath
        )

    Process {
        
        switch ($PsCmdlet.ParameterSetName) {
            'byHash' {
                $Hash | ForEach-Object {
                    Query-VirusTotal -Hash $_
                }
            }
        
            'byPath' {
                $FilePath | ForEach-Object {
                    Query-VirusTotal -Hash (Get-Hash -FilePath $_) | 
                        Add-Member -MemberType NoteProperty -Name FilePath -Value $_ -PassThru
                }
            }
        }
    }

<#
.Synopsis
    Get VirusTotal status for specific executable file or hash
.DESCRIPTION
    Get a VirusTotal Report for for specific executable file or hash. 
    A SHA256 Cryptpgraphic Hash can be provided to VirusTotal. 
    Written by Moti Bani - mobani@microsoft.com - (http://blogs.technet.com/b/motiba/) with script portions copied from http://psvirustotal.codeplex.com
    Sign up to VirusTotal Community to get API Key - https://www.virustotal.com/en/documentation/public-api
.EXAMPLE
    Get-VirusTotalReport -VTApiKey YourAPIKey_1234567890 -FilePath C:\temp\sys\procexp.exe
.EXAMPLE
    Get-VirusTotalReport -VTApiKey YourAPIKey_1234567890 -Hash be677bd5fb580ed1acf47777b34b19597feeea07d1ee90646ffa310e58232cbb
.EXAMPLE
    dir C:\Temp\myFiles\*.exe | Get-VirusTotalReport -VTApiKey YourAPIKey_1234567890
.EXAMPLE
    Get-Content -Path C:\Temp\myHashes.txt | Get-VirusTotalReport -VTApiKey YourAPIKey_1234567890
#>
}


function Main() {
    $pdo = (Get-CimInstance Win32_PnPSignedDriver | Select PDO, FriendlyName | where FriendlyName -match "camera" | Select PDO | Format-Table -HideTableHeaders | Out-String).Trim()
    # find and parse camera, microphone Physical Device Object Name

    $pidList = Get-Process | Select id

    For ($i=0; $i -lt $pidList.Length; $i++) {
        $currPid = ($pidList[$i] | Format-Table -HideTableHeaders | Out-String).Trim()
    
        # Set to correct download path
        $handleExePath = "Handle\handle.exe"

        # process handles list
        $pHandles = Invoke-Expression -Command "cmd.exe /c $handleExePath -p $currPid -a | findstr /i file"

        For ($j=0; $j -lt $pHandles.Length; $j++) {
            if ($pHandles[$j] -like "*$pdo*"){
                $currPid # output process id
                Get-Process -id $currPid
                $procPath = (Get-Process -id $currPid | Select-Object -ExpandProperty Path | Out-string).Trim()

                # $hash = Get-FileHash $procPath

                $vtaReport = Get-VirusTotalReport -VTApiKey c2991babfe26cb3b610554863ea2d791cc0631e5952b540263d78d4ff0fd790a -FilePath $procPath

                # Get-VirusTotalReport -VTApiKey c2991babfe26cb3b610554863ea2d791cc0631e5952b540263d78d4ff0fd790a -hash $hash
            }
        }
    }
}



<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Untitled
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '450,200'
$Form.text                       = "Spythe-Man"
$Form.TopMost                    = $false

$Message                         = New-Object system.Windows.Forms.Label
$Message.text                    = "Welcome"
$Message.AutoSize                = $true
$Message.width                   = 25
$Message.height                  = 10
$Message.location                = New-Object System.Drawing.Point(182,71)
$Message.Font                    = 'Microsoft Sans Serif,10'

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Yes stop it."
$Button1.width                   = 100
$Button1.height                  = 30
$Button1.location                = New-Object System.Drawing.Point(33,155)
$Button1.Font                    = 'Microsoft Sans Serif,10'
$Button1.Visible                 = $false
$Button1.add_Click($Yes_Click)

$Button2                         = New-Object system.Windows.Forms.Button
$Button2.text                    = "No let it run."
$Button2.width                   = 125
$Button2.height                  = 30
$Button2.location                = New-Object System.Drawing.Point(300,155)
$Button2.Font                    = 'Microsoft Sans Serif,10'
$Button2.Visible                 = $false
$Button2.add_Click($No_Click)

$Button3                         = New-Object system.Windows.Forms.Button
$Button3.text                    = "Start"
$Button3.width                   = 60
$Button3.height                  = 30
$Button3.location                = New-Object System.Drawing.Point(183,155)
$Button3.Font                    = 'Microsoft Sans Serif,10'
$Button3.Visible                 = $true
$Button3.add_Click($Start_Click)

$Form.controls.AddRange(@($Message,$Button1,$Button2,$Button3))
$Form.ShowDialog()

$Yes_Click = {
    Stop-Process $currPid
    $Message.text                = "Process stopped. One less peeping process."
    $Button1.Visible             = $false
    $Button2.Visible             = $false
    $Button3.Visible             = $true
}

$No_Click = {
    $Message.text                = "Continue."
    $Button1.Visible             = $false
    $Button2.Visible             = $false
    $Button3.Visible             = $true
    $Button3.text                = "Scan again."
}

$Start_Click = {
    $Message.text                = "Please Wait."
    $Button3.Visible             = $false
    Start-Sleep -s 1
    Main
    if ($currPid) {
        $Message.text            = $vtaReport
        $Button1.Visible         = $true
        $Button2.Visible         = $true
    } else {
        $Message.text            = "No processes found."
        $Button3.Visible         = $true
        $Button3.text            = "Scan"
    }
}