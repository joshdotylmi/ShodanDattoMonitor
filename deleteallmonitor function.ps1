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




#This is the api key generated from your shodan paid tenant. 
$APIShodanKEY = "klsjdfalkjlk234jlk23j4lk23j4lksdfadf"


$shodanmonitors = ((Invoke-RestMethod -uri "https://api.shodan.io/shodan/alert/info?key=$APIShodanKEY")|Select-Object -ExpandProperty id)
$shodanmonitors| ForEach-Object -Process {
    $myid = $_
    $keyformat = "?key=$APIShodanKEY"
    $combined =$myid+$keyformat
 write-host $combined
    
    Invoke-RestMethod -Uri "https://api.shodan.io/shodan/alert/$combined" -Method Delete -Verbose
    Write-Host "deleting ID" ($_|Out-String)
    Start-Sleep -Seconds 1


        
        
    }    
    

 

    
#useful commmands
#list id's of notifiers to be used within shodan
#(Invoke-RestMethod -uri "https://api.shodan.io/notifier?key=$APIShodanKEY" -method Get -Verbose).matches |fl