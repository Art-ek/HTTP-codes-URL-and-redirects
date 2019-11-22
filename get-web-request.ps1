
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][string]$list,
    [Parameter(Mandatory=$false)][bool]$local_proxy=$false
)



$proxy_burp="http://127.0.0.1:8080"

$path=Test-Path $list;
if($list -eq ''-or $list -eq $null){

   Write-Host '@
   To send GET request via local burp proxy
   Usage: ./get-web-request.ps1 -list your_file_list.txt -local_proxy $true 
   example: /get-web-request.ps1 -list ./test.txt -local_proxy $true
   
   To send GET request directly
   Usage: ./get-web-request.ps1 -list your_file_list.txt -local_proxy $false
   Example: /get-web-request.ps1 -list ./test.txt -local_proxy $false

   You can change your burp port in the this file. vatiable name proxy_burp
   By default proxy listens on port 8080

   @'
   break

}
if(!$path -or $path -eq $null) {
    Write-Output "[*] Unable to locate the spcified input file";
    break;
} 
$lista=get-Content $list
$ie=([Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer)
$opera=([Microsoft.PowerShell.Commands.PSUserAgent]::Opera)
$chrome=([Microsoft.PowerShell.Commands.PSUserAgent]::Chrome)
$safari=([Microsoft.PowerShell.Commands.PSUserAgent]::Safari)
$firefox=([Microsoft.PowerShell.Commands.PSUserAgent]::FireFox)

$agents=@($ie,$opera,$chrome,$safari,$firefox) 

# 1xx informational response – the request was received, continuing process
# 2xx successful – the request was successfully received, understood and accepted
# 3xx redirection – further action needs to be taken in order to complete the request
# 4xx client error – the request contains bad syntax or cannot be fulfilled
# 5xx server error – the server failed to fulfill an apparently valid request

$array=@()

foreach($a in $lista){

   $array+=$a
   $array+="https://$a"
}

 foreach($i in $array){
     $resp=$null
     $resp=try
     {
         
         if($local_proxy -eq $true){
            
            $agent=$agents | Get-Random
            Invoke-WebRequest -uri $i -UserAgent $agent -Proxy $proxy_burp -TimeoutSec 3 -SkipCertificateCheck
         }else{
            $agent=$agents | Get-Random
            Invoke-WebRequest -uri $i -UserAgent $agent -TimeoutSec 3 

         }

     }
     catch
     {
        $_.exception.response
     }

     
     if($i -match "https"){
        
        $temp=$i.substring(8,$i.Length-8)
        
        $var= host $temp
     } else {
         $var=host $i
     }          
                                                                
     #$var | select-string "NXDOMAIN" | Out-File -FilePath NXDOMAIN.txt -Append
     $r=$resp | Select-Object  -ExpandProperty statuscode
     if (($r -match '^(1|2|3|4|5)0\d$' -or $r -eq "Unauthorized" -or $r -eq "Forbidden" -or $r -eq "MethodNotAllowed") -and $resp -notmatch "burp")
     {
        $i | Out-File -FilePath valid_address.txt -Append
        
        Write-host "response = $r [+] Can be scanned with Burp" -BackgroundColor Green -ForegroundColor Black
       
        
     } else {
      $i | Out-File -FilePath invalid_address.txt -Append
      
      Write-host "response = $r [-] web server cannot be reached " -BackgroundColor Red -ForegroundColor Black

     

      }
      if ( $var -match "NXDOMAIN" -or $var -match "SERVFAIL") {
      
         $i | Out-File -FilePath NXDOMAIN.txt -Append  
   
         Write-host "response = $r [-] Non existent domain" -BackgroundColor Red -ForegroundColor Black          
   
     } else {
        $i | Out-File -FilePath valid_address.txt -Append
     }
             
     Write-host "server = $i"     
     Write-host "$var"       
     write-host "Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" 
     write-host "Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)"     
     Write-host "=====================================" 
     Write-Output $(Get-Date) | Out-File -FilePath SCAN.LOG -Append
     if ($r -match '^(1|2|3|4|5)0\d$'){
        Write-Output "HTTP status code: $r " | Out-File -FilePath SCAN.LOG -Append
     }
     Write-Output "server = $i" | Out-File -FilePath SCAN.LOG -Append  
     write-Output "Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" |Out-File -FilePath SCAN.LOG -Append
     write-Output "Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)"   | Out-File -FilePath SCAN.LOG -Append     
     #   Write-Output $var | Out-File -FilePath SCAN.LOG -Append
     Write-Output $resp.BaseResponse.Headers | Out-File -FilePath SCAN.LOG -Append
     Write-Output "-----------------------------------" | Out-File -FilePath SCAN.LOG -Append

   
 }
    
    
 $duplicat=Get-Content ./valid_address.txt
 $unikat=@()
 foreach($d in $duplicat){
     if($d -match "https"){
 
         $unikat+=$d.substring(8,$d.length-8)
 
     } else {
 
         $unikat+=$d
     }
 
 
 
 }
 $unikat | select -Unique | Out-File -FilePath VALID_DOMAINS.txt -Append
