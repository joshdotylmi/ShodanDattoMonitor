# Input bindings are passed in via param block.
param($Timer)


function Retry-Command {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)] 
        [ValidateNotNullOrEmpty()]
        [scriptblock] $ScriptBlock,
        [int] $RetryCount = 1,
        [int] $TimeoutInSecs = (Get-Random -Maximum 60),
        [string] $SuccessMessage = "Command executed successfuly!",
        [string] $FailureMessage = "Failed to execute the command"
        )
        
    process {
        $Attempt = 1
        $Flag = $true
        
        do {
            try {
                $PreviousPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Stop'
                Invoke-Command -ScriptBlock $ScriptBlock -OutVariable Result              
                $ErrorActionPreference = $PreviousPreference

                # flow control will execute the next line only if the command in the scriptblock executed without any errors
                # if an error is thrown, flow control will go to the 'catch' block
                Write-Verbose "$SuccessMessage `n"
                $Flag = $false
            }
            catch {
                if ($Attempt -gt $RetryCount) {
                    Write-Verbose "$FailureMessage! Total retry attempts: $RetryCount"
                    Write-Verbose "[Error Message] $($_.exception.message) `n"
                    $Flag = $false
                }
                else {
                    Write-Verbose "[$Attempt/$RetryCount] $FailureMessage. Retrying in $TimeoutInSecs seconds..."
                    Start-Sleep -Seconds $TimeoutInSecs
                    $Attempt = $Attempt + 1
                }
            }
        }
        While ($Flag)
        
    }
}
function New-ApiAccessToken {

    <#
    .SYNOPSIS
    Fetches the the API token.
 
    .DESCRIPTION
    Returns the API token.
 
    .INPUTS
    $apiUrl = The API URL
    $apiKey = The API Key
    $apiKeySecret = The API Secret Key
 
    .OUTPUTS
    API Token
 
    #>

    # Check API Parameters
    if (!$apiUrl -or !$apiKey -or !$apiSecretKey) {
        Write-Host "API Parameters missing, please run Set-DrmmApiParameters first!"
        return
    }

    # Specify security protocols
    # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls11,Tls12'

    # Convert password to secure string
    $securePassword = ConvertTo-SecureString -String 'public' -AsPlainText -Force

    # Define parameters for Invoke-WebRequest cmdlet
    $params = @{
        Credential  = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('public-client', $securePassword)
        Uri         = '{0}/auth/oauth/token' -f $apiUrl
        Method      = 'POST'
        ContentType = 'application/x-www-form-urlencoded'
        Body        = 'grant_type=password&username={0}&password={1}' -f $apiKey, $apiSecretKey
        UseBasicParsing = $True
    }
    
    # Request access token
    (Invoke-WebRequest @params | ConvertFrom-Json).access_token

}
function Set-DrmmApiParameters {
	<#
	.SYNOPSIS
	Sets the API Parameters used throughout the module.

	.PARAMETER Url
	Provide Datto RMM API Url. See Datto RMM API help files for more information.

	.PARAMETER Key
	Provide Dattto RMM API Key. Obtained when creating a API user in Datto RMM.

	.PARAMETER SecretKey
	Provide Datto RMM API ScretKey. Obtained when creating a API user in Datto RMM.
	
	#>
	
	Param(
	[Parameter(Mandatory=$True)]
	$Url,
    
	[Parameter(Mandatory=$True)]
	$Key,

	[Parameter(Mandatory=$True)]
	$SecretKey
	
	)

	New-Variable -Name apiUrl -Value $Url -Scope Script -Force
	New-Variable -Name apiKey -Value $Key -Scope Script -Force
	New-Variable -Name apiSecretKey -Value $SecretKey -Scope Script -Force
	
	$accessToken = New-ApiAccessToken
	New-Variable -Name apiAccessToken -value $accessToken -Scope Script -Force
}
function Get-DrmmAccountDevices {

	<#
	.SYNOPSIS
	Fetches the devices of the authenticated user's account.

	.DESCRIPTION
	Returns device data, including patch status, anti-virus status and user defined fields.

	#>

    # Declare Variables
    $apiMethod = 'GET'
    $maxPage = 250
    $nextPageUrl = $null
    $page = 0
    $Results = @()

    do {
	    $Response = New-ApiRequest -apiMethod $apiMethod -apiRequest "/v2/account/devices?max=$maxPage&page=$page" | ConvertFrom-Json
	    if ($Response) {
		    $nextPageUrl = $Response.pageDetails.nextPageUrl
		    $Results += $Response.devices
		    $page++
	    }
    }
    until ($nextPageUrl -eq $null)

    # Return all account devices
    return $Results
}
function New-ApiRequest {

	<#
	.SYNOPSIS
	Makes a API request.

	.DESCRIPTION
	Returns the API response.

	.PARAMETER ApiMethod
	Provide API Method GET, PUT or POST

	.PARAMETER ApiRequest 
	See Datto RMM API swagger UI

	.PARAMETER ApiRequestBody 
	Only used with PUT and POST request

    .INPUTS
	$apiUrl = The API URL
	$apiKey = The API Key
	$apiKeySecret = The API Secret Key

	.OUTPUTS
	API response

	#>
    
	Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('GET','PUT','POST')]
		[string]$apiMethod,

        [Parameter(Mandatory=$True)]
		[string]$apiRequest,
    
        [Parameter(Mandatory=$False)]
		[string]$apiRequestBody
	)

	# Check API Parameters
	if (!$apiUrl -or !$apiKey -or !$apiSecretKey) {
		Write-Host "API Parameters missing, please run Set-DrmmApiParameters first!"
		return
	}

	# Define parameters for Invoke-WebRequest cmdlet
	$params = [ordered] @{
		Uri         = '{0}/api{1}' -f $apiUrl, $apiRequest
		Method      = $apiMethod
		ContentType = 'application/json'
		Headers     = @{'Authorization' = 'Bearer {0}' -f $apiAccessToken}
		UseBasicParsing = $True
	}

	# Add body to parameters if present
	If ($apiRequestBody) {$params.Add('Body',$apiRequestBody)}

	# Make request
	try 
	{
		(Invoke-WebRequest @params).Content
	}
	catch
	{
		
		$exceptionError = $_.Exception.Message
		
		switch ($exceptionError)
		{
	
			'The remote server returned an error: (429).' 
			{
				Start-Sleep -Seconds 60
			}

			'The remote server returned an error: (403) Forbidden.'
			{
				Start-Sleep -Seconds 300
			}

		}

		throw
	}
}
function Get-DrmmDevice {

	<#
	.SYNOPSIS
	Fetches data of the device identified by the given device Uid

	.DESCRIPTION
	Returns device settings, device type, device anti-virus status, device patch Status and UDF's.

	.PARAMETER DeviceUid
	Provide device uid which will be used to return device data.
	
	#>
    
	# Function Parameters
    Param (
        [Parameter(Mandatory=$True)] 
        $deviceUid
    )
	
    # Declare Variables
    $apiMethod = 'GET'
    
	# Return device data
    return New-ApiRequest -apiMethod $apiMethod -apiRequest "/v2/device/$deviceUid" | ConvertFrom-Json

}
#This is the api server that Datto RMM uses for your datto tenant, you'll need to update it to fit your tenant. 
#Refer to this document to pull the Datto API server https://rmm.datto.com/help/en/Content/2SETUP/APIv2.htm
$apiUrl = "https://api.centrastage.net"
#This key is the one mentioned in the datto rmm api generation ui.
$apiKey = "SKJDfaklsdjflk23j4kljJFFJFJ"
#This secret is shown once when generating it from the datto rmm UI. Be sure you copy it somewhere smart.
$apiKeySecret = "i23u4kjklsjdklfajkldsf"
#This is the api key generated from your shodan paid tenant. 
$APIShodanKEY = "klsjdfalkjlk234jlk23j4lk23j4lksdfadf"
Set-DrmmApiParameters -Url $apiUrl -Key $apiKey -SecretKey $apiKeySecret -Verbose
$accessToken = (New-ApiAccessToken -apiKeySecret $apiKeySecret -apiKey $apiKey -apiUrl $apiUrl)
$devices = $(Get-DrmmAccountDevices|Group-Object extIpAddress )

$listexistingalerts = (Retry-Command -ScriptBlock { Invoke-RestMethod -uri "https://api.shodan.io/shodan/alert/info?key=$APIShodanKEY"})

#Creates monitoring objects within shodan referencing datto rmm device's hostname and site.
$Shodan = foreach ($devices in $devices) {
    $Alertname = (($devices.Group.siteName)|select -First 1)+(" ") +(($devices.Group.hostname)|select -First 1) 
    $WorkingIP = ($devices.Name) 
    write-host "$Alertname $WorkingIP"
$CreateMonitorBody = @"
{
 "name": "$Alertname",
 "filters": {
  "ip": "$WorkingIP/32"
 }
}
"@

$StartScanBody = @"
{
 
  "ip": "$WorkingIP/32"
}
"@
    try { if ($listexistingalerts.SyncRoot.Name | where-object {$_ -like $Alertname})
    {
        Write-Host "$AlertName already is monitored"
    }
    
    
    else {


        Write-Host "Creating monitor for $AlertName"
        Invoke-RestMethod -Uri "https://api.shodan.io/shodan/alert?key=$APIShodanKEY" -Body $CreateMonitorBody -Method Post -Verbose
        Start-Sleep -Seconds 1
        Write-Host "Successfully Created Monitor for $AlertName"
        $listnewalerts = (Invoke-RestMethod -uri "https://api.shodan.io/shodan/alert/info?key=$APIShodanKEY" -Verbose)
        Start-Sleep -Seconds 1
        write-host "Pulling ID monitoring Asset by inventorying all shodan alerts"
        $myid = $listnewalerts.SyncRoot | where-object {$_.name -like "$AlertName"} |Select-Object -ExpandProperty ID
        write-host $myid
        Invoke-RestMethod -Uri "https://api.shodan.io/shodan/alert/$myid/trigger/malware,open_database,iot,internet_scanner,industrial_control_system,vulnerable,ssl_expired,new_service,uncommon,uncommon_plus?key=$APIShodanKEY" -Method Put -Verbose
        Start-Sleep -Seconds 1
        write-host "Adding malware,open_database,iot,internet_scanner,industrial_control_system,vulnerable,ssl_expired,new_service,uncommon trigger for alert $AlertName  $myid"
		
        write-host "Adding notifer for created alert to post to teams"
		
		
		#You'll want to update this value with the notifier you wish to use within shodan to submit alerts to your company team
		#You can find the ID with the following command 
		#(Invoke-RestMethod -uri "https://api.shodan.io/notifier?key=$APIShodanKEY" -method Get -Verbose).matches |fl
		
        Invoke-RestMethod -uri "https://api.shodan.io/shodan/alert/$myid/notifier/[INSERT YOUR ID HERE]?key=$APIShodanKEY" -Method Put -Verbose
        Start-Sleep -Seconds 1
        write-host "Adding notifer for created alert to post to shared mailbox"
        #Write-Host "Get Information for newly created alert"
        #Invoke-RestMethod -Uri "https://api.shodan.io/shodan/alert/$myid/info?key=$APIShodanKEY" -Method Get -Verbose
        Start-Sleep -Seconds 1
		#Uncomment the next line if you wish to submit a new scan for each new shodan scan 
        #Invoke-RestMethod -uri "https://api.shodan.io/shodan/scan?key=$APIShodanKEY" -Method Post -Body $StartScanBody -Verbose

        
        
    }    
    
}
 
    catch {
        write-host "($_.Exception.Message)" 
        continue
    }
   
    
}

