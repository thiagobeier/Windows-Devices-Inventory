<#PSScriptInfo
.VERSION 0.0.1
.AUTHOR Thiago Beier
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS ADDS AzureAD Intune WindowsAutopilotDevices
.LICENSEURI https://github.com/thiagobeier/Windows-Devices-Inventory/blob/main/LICENSE
.PROJECTURI https://github.com/thiagobeier/Windows-Devices-Inventory
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
v0.0.1 - Initial version
#>

<#
.SYNOPSIS
Retrieves Windows Device from Hybrid Azure AD joined Windows Autopilot Deployment profile and checks its object status in Azure AD, Intune and Windows AutoPilot devices - Community Version
GPL LICENSE
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.DESCRIPTION
This script uses Get-ADComputer from ActiveDirectory powershell modules and MSGraph to retrieve AzureAD, Intune and Windows AutoPilot devices using Azure AD registered application with secret key as parameters.
.PARAMETER Hybrid
Default on this version to look for each Synced Device objects to Azure AD that could be on a broken state (in AzureAD not in Intune or in Intune but the Azure AD joined device object not the Hybrid Azure AD joined one)
.PARAMETER -TenantId
Required "Directory (tenant) ID" from the Azure AD application created for this purpose from https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/
.PARAMETER -AppId
Required "Application (client) ID" from the Azure AD application created for this purpose from https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/
.PARAMETER -AppSecret
Required "Client Secret Value" from the Azure AD application created for this purpose from https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/
.PARAMETER -Tenantname
Required "Primary domain" from the Azure AD Overview.- https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView
.EXAMPLE
.\Windows-Devices-Inventory.ps1 -Hybrid -TenantId YOUR-TENANTID -AppId YOUR-AZURE-AD-APP-CLIENT-ID -AppSecret YOUR-AZURE-AD-APP-CLIENT-ID-SECRET -Tenantname CONTOSO.onmicrosoft.com
.NOTES
Version:        0.0.1
Author:         Thiago Beier
WWW:            https://thebeier.com
Creation Date:  07/07/2023
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
	[Parameter(Mandatory = $True, ParameterSetName = 'Hybrid')] [Switch] $Hybrid = $false,
	[Parameter(Mandatory = $False, ParameterSetName = 'Hybrid')] [String] $TenantId = "",
	[Parameter(Mandatory = $False, ParameterSetName = 'Hybrid')] [String] $AppId = "",
	[Parameter(Mandatory = $False, ParameterSetName = 'Hybrid')] [String] $AppSecret = "",
	[Parameter(Mandatory = $False, ParameterSetName = 'Hybrid')] [String] $Tenantname = ""
)


#region App-based authentication
Function Connect-MSGraphApp {
	<#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Intune module using app-based authentication.
 
.DESCRIPTION
The Connect-MSGraphApp cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Intune module. It leverages an Azure AD app ID and app secret for authentication. See https://oofhours.com/2019/11/29/app-based-authentication-with-intune/ for more information.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
 
.EXAMPLE
Connect-MSGraphApp -TenantId $tenantID -AppId $AppId -AppSecret $secret -Tenantname $Tenantname
 
-#>
	[cmdletbinding()]
	param
	(
		[Parameter(Mandatory = $false)] [string]$TenantId,
		[Parameter(Mandatory = $false)] [string]$AppId,
		[Parameter(Mandatory = $false)] [string]$AppSecret,
		[Parameter(Mandatory = $false)] [string]$Tenantname
	)

	Process {
		Import-Module Microsoft.Graph.Authentication
		$retokenbody = @{
			Grant_type    = "client_credentials"
			Scope         = "https://graph.microsoft.com/.default"
			client_id     = $AppId
			client_secret = $AppSecret
		}
		$tokenresponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenantname/oauth2/v2.0/token" -Method Post -Body $retokenbody
		#$tokenresponse
		
		# Connect All MSGraph & MGGraph
		try {
			
			Write-host -ForegroundColor Cyan "Connecting to MSGraph"
			Import-Module Microsoft.Graph.Intune
			Import-Module Microsoft.Graph.Users
			Import-Module Microsoft.Graph.DeviceManagement
			Import-Module Microsoft.Graph.Groups
			Import-Module Microsoft.Graph.Identity.DirectoryManagement
			Import-Module -Name MSAL.PS -Force
			Import-Module WindowsAutopilotIntune
			$authority = "https://login.windows.net/$tenantname"
			Update-MSGraphEnvironment -AppId $AppId -Quiet
			Update-MSGraphEnvironment -AuthUrl $authority -Quiet
			Connect-MSGraph -ClientSecret $AppSecret -Quiet
			$accesstokenfinal = ConvertTo-SecureString -String $tokenresponse.access_token -AsPlainText -Force
			Connect-MgGraph -AccessToken $accesstokenfinal
			
		}
		catch {
			Write-host "ERROR: Could not connect to MSGraph - exiting!" -ForegroundColor Red
			write-host $_.Exception.Message -ForegroundColor Red
			#exit;
		}
	}
}

#region Helper methods

Function BoolToString() {
	param
	(
		[Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $True)] [bool] $value
	)

	Process {
		return $value.ToString().ToLower()
	}
}

#endregion

#region : Functions

function Get-ADDSDevicesList {
	$strDomainController = (Get-ADDomainController -Discover -ForceDiscover -ErrorAction SilentlyContinue).HostName.Value
	Write-Host "$($(Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")): Domain Controller Selected ($strDomainController)"

	if ($strDomainController) {
		$global:AllADDScomputers = ""
		"Connected to Domain Controller"
		# List AD computers
		$strAllADcomputers = Get-ADComputer -Server $strDomainController -Filter 'operatingsystem -ne "*server*" -and enabled -eq "true"' -ErrorAction SilentlyContinue
		#$strAllADcomputers.count
		#$strAllADcomputersResultStatus = $true
		$global:AllADDScomputers = $strAllADcomputers
	}
 else {
		"Could not contact Domain Controller"
		#$strAllADcomputersResultStatus = $false
		break
	}


}

function Install-Modules () {
	write-host -ForegroundColor Cyan "Installing Modules"
	# Modules
	$Modules = @(
		"Microsoft.Graph.Users"
		"Microsoft.Graph.Groups"
		"Microsoft.Graph.Intune"
		"Microsoft.Graph.DeviceManagement"
		"Microsoft.Graph.Authentication"
		"Microsoft.Graph.Identity.DirectoryManagement"
		"MSAL.PS"
		"WindowsAutoPilotIntune"
	)

	foreach ($Module in $Modules) {
		if (Get-InstalledModule $Module -ErrorAction SilentlyContinue) {
			Write-Host "$Module Module Present" -ForegroundColor Green
		}
		else {
			Write-Host "Installing $Module Module" -ForegroundColor Yellow
			Install-Module $Module -Confirm:$false -Force:$true
		}
	}
	$Provider = "NuGet"
	$ProviderVersion = "2.8.5.201"
	if (Get-PackageProvider -Name $Provider -ErrorAction SilentlyContinue ) {
		Write-Host "$Provider Present" -ForegroundColor Green
	}
	else {
		Write-Host "Installing $Provider Module" -ForegroundColor Yellow
		Install-PackageProvider -Name $Provider -MinimumVersion $ProviderVersion -Confirm:$false -Force:$true
	}

	Start-Sleep -Seconds 5
	Clear-Host

}
#
#endregion


# If online, make sure we are able to authenticate
if ($Hybrid) {

	Clear-Host

	Write-Host -ForegroundColor Green "### Executing Hybrid ###"

	Install-Modules

	#Region : Connecting MSGraph
	# Connect
	if ($AppId -ne "") {
 
		try {

			
			write-host "Connecting MSGraph" -ForegroundColor Green
			Connect-MSGraphApp -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret -Tenantname $Tenantname
			
		}
		catch {
			Write-host "ERROR: Could not connect to MSGraph (for Intune) - exiting!" -ForegroundColor Red
			write-host $_.Exception.Message -ForegroundColor Red
			#exit;
		}

		#Select-MgProfile -Name Beta
		#$graph = Connect-MgGraph -AccessToken $accessToken
		#Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
	}
	else {
		#$graph = Connect-MgGraph -scopes Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All
		#Write-Host "Connected to Intune tenant $($graph.TenantId)"
		#if ($AddToGroup) {
		#$aadId = Connect-MgGraph -scopes Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All
		#Write-Host "Connected to Azure AD tenant $($aadId.TenantId)"
		#}
	}

	# Load Lists
	Write-Host -ForegroundColor Cyan "Loading Lists"
	Get-ADDSDevicesList
	
	# Clear all variables
	#$global:AllAADUsersList = "" #Future Version (Registered Users Owned Devices)
	$global:AllAADDevicesList = ""
	#$global:AllAADGroupsList = "" #Future Version (Registered Users Owned Devices / Membership)
	$global:AllIntuneDevicesList = ""
	$global:AllWinAutopilotDevicesList = ""

	#$global:AllAADUsersList = (Get-MgUser -All | Get-MSGraphAllPages) #Future Version (Registered Users Owned Devices)
	$global:AllAADDevicesList = (Get-MgDevice -All | Get-MSGraphAllPages)
	#$global:AllAADGroupsList = (Get-MgGroup -All | Get-MSGraphAllPages) #Future Version (Registered Users Owned Devices / Membership)
	$global:AllIntuneDevicesList = (Get-MgDeviceManagementManagedDevice -All)
	$global:AllWinAutopilotDevicesList = (Get-AutopilotDevice)

	#Region : Azure AD Check and Update Extension Attribute 15 in Azure

	#Region : Set CLI to the Workgin Dir and Log
	$FullDate = Get-Date -Format "yyyy-MM-dd"
	#$FullDate.Split("-")

	# Create Log File as well
	$LogFile = "Windows_Devices_Inventory_$FullDate.log"
	#Endregion

	# Get All Azure AD Devices
	$FormattedDevice = $null
	#Initiate Empty Array to Hold Formatted Devices
	$global:FormattedNonServerPremDevices = ""
	$global:FormattedNonServerPremDevices = $null
	$global:FormattedNonServerPremDevices = @()
	Foreach ($Device in $global:AllADDScomputers) {

		try {

			# Create Custom Object with Formatted Columns and Names
			$FormattedDevice = [PSCustomObject]@{
				DeviceName               = $Device.Name
				OnPremID                 = $Device.ObjectGUID
				BULC                     = $BULC
				DN                       = $Device.DistinguishedName
				OS                       = ""
				Enabled                  = $Device.Enabled
				NamingError              = ""
				AzureADStatus            = ""
				AzureADID                = ""
				IntuneStatus             = ""
				IntuneSerialNumber       = ""
				WinAutopilotSerialNumber = ""
			}
		}
		catch {
			"Could not get BULC for $Device.DeviceName" | Out-File -FilePath $LogFile -Append
		}
    
		# Add Formatted Device to Array
		$global:FormattedNonServerPremDevices += $FormattedDevice
	
	}
	#$global:FormattedNonServerPremDevices.count

	#Endregion

	foreach ($FormattedDevice in $global:FormattedNonServerPremDevices) {
		if ($null -ne $FormattedDevice.DeviceName -and $FormattedDevice.DeviceName.ToUpper().StartsWith($FormattedDevice.BULC)) {
			$FormattedDevice.NamingError = "False"
		}
		else {
			if ($null -ne $FormattedDevice) {
				$FormattedDevice.NamingError = "True"
			}
		}
	}

	#Endregion
	#$global:FormattedNonServerPremDevices.count

	#EndRegion

	#Region : Azure AD Check

	# Get All Azure AD Devices

	# To be used for progress bar
	$AzureADProgressCount = 0
	$global:FormattedNonServerPremDevices = $global:FormattedNonServerPremDevices

	# Loop through each Formatted Device and find its matching machine in Azure AD
	foreach ($FormattedDevice in $global:FormattedNonServerPremDevices) {
		#$FormattedDevice 
		# Progress Bar, because this step takes a while.
		$AzureADProgressPercent = [math]::Round(($AzureADProgressCount / $global:FormattedNonServerPremDevices.Count) * 100)
		Write-Progress -Activity "Checking Azure AD" -Status "$AzureADProgressPercent% Complete" -PercentComplete $AzureADProgressPercent

		# Look for a match based on DeviceName and OnPremID
		$AzureADDevice = $global:AllAADDevicesList | Where-Object { $_.DisplayName -eq $FormattedDevice.DeviceName -and $_.DeviceID -eq $FormattedDevice.OnPremID }
		# Check if a match was found and update entry
		if ($null -ne $AzureADDevice) {
			#write-host "Host found $($FormattedDevice.DeviceName)"
			#$AADDevice = $global:AllIntuneDevicesList | Where-Object { $_.azureADDeviceId -eq $FormattedDevice.OnPremID }
			#$AADDevice
			$FormattedDevice.AzureADStatus = "Found"
			$FormattedDevice.AzureADID = $AzureADDevice.Id
			$FormattedDevice.OS = $AzureADDevice.OperatingSystem
		}
		else {
			#write-host "Host not found $($FormattedDevice.DeviceName)"
			$FormattedDevice.AzureADStatus = "Not Found"
		}

		# Increment Progress Bar Count 1
		$AzureADProgressCount += 1
	}
	#EndRegion
	#$global:FormattedNonServerPremDevices.count

	#Region : Intune Status Check
	# Loop through each device and check if its found in intune
	foreach ($FormattedDevice in $global:FormattedNonServerPremDevices) {

		# Look for a match based on DeviceName and OnPremID
		# Match devices based on Intune ID (AzureAADDeviceId), with OnPremID
		if ($null -ne $FormattedDevice -and $global:AllIntuneDevicesList.azureADDeviceId -contains $FormattedDevice.OnPremID) {
			# Update FormattedDevice Entry
			$FormattedDevice.IntuneStatus = "Found"
			$IntuneDevice = $global:AllIntuneDevicesList | Where-Object { $_.azureADDeviceId -eq $FormattedDevice.OnPremID }
			$FormattedDevice.IntuneSerialNumber = $IntuneDevice.SerialNumber
		}
		else {
			$FormattedDevice.IntuneStatus = "Not Found"
		}
	}
	#$global:FormattedNonServerPremDevices.count
	#EndRegion

	#Region : Windows Autopilot Devices Status Check
	# Loop through each device and check if its found in windows autopilot devices (hash/serial)
	foreach ($FormattedDevice in $global:FormattedNonServerPremDevices) {
    
		# Match devices based on Intune ID (AzureAADDeviceId), with OnPremID
		if ($null -ne $FormattedDevice -and $global:AllWinAutopilotDevicesList.SerialNumber -contains $FormattedDevice.IntuneSerialNumber) {
			# Update FormattedDevice Entry
			$FormattedDevice.WinAutopilotSerialNumber = "Found"
		}
		else {
			$FormattedDevice.WinAutopilotSerialNumber = "Not Found"
		}
	}
	#$global:FormattedNonServerPremDevices.count
	#EndRegion

	#Region : Export Data
	$global:FormattedNonServerPremDevices | Export-Csv Report_Windows_Devices_$FullDate.csv -NoTypeInformation
	#EndRegion

	#export to HTML
	# Install the PScribo module (if not already installed)
	#Install-Module -Name PScribo
	# Import the PScribo module
	#Import-Module -Name PScribo	
	# Convert the data to HTML
	#$HTMLContent = $global:FormattedNonServerPremDevices | ConvertTo-Html
	# Save the HTML to a file
	#$HTMLContent | Out-File -FilePath "output.html" -Encoding UTF8 -Force

	# Convert the data to an HTML table
	$htmlTable = $global:FormattedNonServerPremDevices | ConvertTo-Html -As Table -Fragment

	# Save the HTML table to a file
	$htmlTable | Out-File -FilePath "output1.html"

}


<#
gcm Get-MgUser
gcm Get-MgGroup
gcm Get-MgDevice
gcm Get-MgDeviceManagementManagedDevice
gcm Get-AutopilotDevice
#>


