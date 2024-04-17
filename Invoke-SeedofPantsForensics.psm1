####usage: use on fresh installed windows box on enterprise network w/ provided credentials 

#$cred = get-credential
#Invoke-SeedofPantsForensics -ComputerName 10.0.5.15 -HostName "SupremeHampsterWin10ABCDEFG" -Cred $cred

####advisory: once initial tool installations are completed, you may not want to rerun the choco / vol / python installations

<#
#troubleshooting winrm

#below is for private/public net profile fix
$indx = (Get-NetConnectionProfile).InterfaceIndex
foreach ($i in $indx) {
Set-NetConnectionProfile -InterfaceIndex $i -NetworkCategory Private
}

#>


function Invoke-SeedofPantsForensics {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [string]$HostName,

        [Parameter(Mandatory=$true)]
        [PSCredential]$Cred
    )

    # Enable PSRemoting on the host (analyst) computer

    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
    Set-ExecutionPolicy Unrestricted -Force

    # Open a PSSession on the remote computer
    $session = New-PSSession -ComputerName $ComputerName -Credential $cred

    #better remote cmd
    Invoke-Command -Session $session -ScriptBlock { mkdir c:\Analystpublic }
    mkdir c:\AnalystTools
    Invoke-WebRequest -Uri "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe" -OutFile "c:\AnalystTools\winpmem_mini_x64_rc2.exe"
    Copy-Item -ToSession $session -Path "c:\AnalystTools\winpmem_mini_x64_rc2.exe" -Destination "c:\Analystpublic"

    Invoke-Command -Session $session -ScriptBlock { 
    cd c:\Analystpublic
    .\winpmem_mini_x64_rc2.exe IRdump.raw 
    }

    mkdir c:\AnalystIR
    mkdir C:\AnalystIR\$HostName
    Copy-Item -FromSession $session -Path "C:\Analystpublic\IRdump.raw" -Destination "C:\AnalystIR\$HostName\IRdump.raw"

    # Install forensics tools
        
    mkdir c:\AnalystTools\volatility
    $volDir = "c:\AnalystTools\volatility"
    cd $volDir

    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    $env:Path += ";%ALLUSERSPROFILE%\chocolatey\bin"

    choco install -y python3
    choco install git -y

    Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1
    refreshenv

    #python -V to test it at this point
    git clone https://github.com/volatilityfoundation/volatility3.git
    cd $volDir\volatility3
    pip3 install -r .\requirements.txt
    #$deviceName = hostname

    Write-Host "chocolatey, volatility, and python installed on analyst machine, processing raw memory dump with Volatility, please wait ..."
    
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.malfind.Malfind | Out-File c:\AnalystIR\$HostName\malfind.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.pstree.PsTree | Out-File c:\AnalystIR\$HostName\pstree.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.pstree.PsScan | Out-File c:\AnalystIR\$HostName\psscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.registry.hivescan.HiveScan | Out-File c:\AnalystIR\$HostName\hivescan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.netscan.NetScan | Out-File c:\AnalystIR\$HostName\netscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.dlllist.DllList | Out-File c:\AnalystIR\$HostName\dlllist.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.handles.Handles | Out-File c:\AnalystIR\$HostName\handles.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.driverscan.DriverScan | Out-File c:\AnalystIR\$HostName\driverscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.cmdline.CmdLine | Out-File c:\AnalystIR\$HostName\cmdline.csv

    #complex yara stuff
    mkdir rules
    cd .\rules
    git clone https://github.com/Yara-Rules/rules.git
    #add more gitlab rule repo's later

    $volRuleDir = "$volDir\volatility3\rules"

    # Remove all files without .yar file extension
    Get-ChildItem -Path $volRuleDir -File | Where-Object { $_.Extension -ne ".yar" } | Remove-Item -Force -ErrorAction SilentlyContinue

    # Get all .yar files
    $yarFiles = Get-ChildItem -Path ".\rules" -Filter "*.yar" -File -Recurse -ErrorAction SilentlyContinue

    # Create a new file to store the combined Yara rules
    $combinedFile = "$volRuleDir\test.yar"
    if (Test-Path $combinedFile) {
    Remove-Item $combinedFile -Force -ErrorAction SilentlyContinue
    }

    # Iterate over each .yar file, read its content, and append it to the combined file
    foreach ($yarFile in $yarFiles) {
    $content = Get-Content $yarFile.FullName -Raw
    Add-Content -Path $combinedFile -Value $content -ErrorAction SilentlyContinue
    Add-Content -Path $combinedFile -Value "`n" -ErrorAction SilentlyContinue
    }

    cd $volDir\Volatility3

    python vol.py -f "c:\Analystpublic\IRdump.raw" yarascan.YaraScan --yara-file .\rules\test.yar | Out-File c:\AnalystIR\$HostName\yarascan.csv
    
    Remove-PSSession $session
}


#once everything is installed initially we can revert back to this function and rerun vol.py

function Invoke-WinpmemDump {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [string]$HostName,

        [Parameter(Mandatory=$true)]
        [PSCredential]$Cred
    )

    # Open a PSSession on the remote computer
    $session = New-PSSession -ComputerName $ComputerName -Credential $cred

    Invoke-Command -Session $session -ScriptBlock { mkdir c:\Analystpublic }


    # Push the winpmem file to the remote computer
    Copy-Item -ToSession $session -Path "C:\AnalystTools\winpmem_mini_x64_rc2.exe" -Destination "C:\Analystpublic"

    # Execute winpmem on the remote computer
    Invoke-Command -Session $session -ScriptBlock { 
        cd C:\Analystpublic
        .\winpmem_mini_x64_rc2.exe IRdump.raw 
    }

    # Pull back the raw file
    mkdir C:\AnalystIR\$HostName
    Copy-Item -FromSession $session -Path "C:\Analystpublic\IRdump.raw" -Destination "C:\AnalystIR\$HostName\IRdump.raw"

    $volDir = "c:\AnalystTools\volatility"
    cd $volDir\volatility3

    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.malfind.Malfind | Out-File c:\AnalystIR\$HostName\malfind.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.pstree.PsTree | Out-File c:\AnalystIR\$HostName\pstree.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.pstree.PsScan | Out-File c:\AnalystIR\$HostName\psscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.registry.hivescan.HiveScan | Out-File c:\AnalystIR\$HostName\hivescan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.netscan.NetScan | Out-File c:\AnalystIR\$HostName\netscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.dlllist.DllList | Out-File c:\AnalystIR\$HostName\dlllist.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.handles.Handles | Out-File c:\AnalystIR\$HostName\handles.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.driverscan.DriverScan | Out-File c:\AnalystIR\$HostName\driverscan.csv
    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" windows.cmdline.CmdLine | Out-File c:\AnalystIR\$HostName\cmdline.csv

    $volRuleDir = "$volDir\volatility3\rules"
    $combinedFile = "$volRuleDir\test.yar"

    python vol.py -f "C:\AnalystIR\$HostName\IRdump.raw" yarascan.YaraScan --yara-file .\rules\test.yar | Out-File c:\AnalystIR\$HostName\yarascan.csv

    Remove-PSSession $session
}
