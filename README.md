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


#once the first function runs, use the second one for ez pz raw memory captures on remote hosts, with a little directory organization + volatility plugin usage
