
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][string]$list,
    [Parameter(Mandatory=$false)][bool]$local_proxy=$false
)

$dns_host=0;
$sorted_valid_dom=@()
$sorted_nx_dom=@()
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

# importing domain list froma a file/variable and asigning to the domain_list variable
$domain_list=get-Content $list

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

# creating an array containing both HTTP and HTTPS adressess
$domain_array=@()
foreach($a in $domain_list){

   $domain_array+=$a
   $domain_array+="https://$a"
}

 foreach($i in $domain_array){
     $resp=$null
     $resp=try
     {
         
         if($local_proxy -eq $true){
            
            $agent=$agents | Get-Random
            Invoke-WebRequest -uri $i -UserAgent $agent -Proxy $proxy_burp -TimeoutSec 3 -SkipCertificateCheck
         }else{
            $agent=$agents | Get-Random
            Invoke-WebRequest -uri $i -UserAgent $agent -TimeoutSec 3 -SkipCertificateCheck

         }

     }
     catch
     {
        $_.exception.response
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
      #removing "https://" to use host command
      if($i -match "https"){
        
         $temp=$i.substring(8,$i.Length-8)
         
         $dns_host= host $temp
      
      } else {
          $dns_host=host $i
      }        
   
      
      if ( $dns_host -match "NXDOMAIN" -or $dns_host -match "SERVFAIL") {

        $parsed_i=switch -wildcard ($i){

            "https://*" {  $i.substring(8,$i.Length-8)}
             Default    {$i}
        }        
        $sorted_nx_dom+=$parsed_i 
   
         Write-host "response = $r [-] Non existent domain" -BackgroundColor Red -ForegroundColor Black          
        
     } else {
        
        $parsed_i=switch -wildcard ($i){

            "https://*" {  $i.substring(8,$i.length-8)}

             Default    {$i}
        }   
        $sorted_valid_dom+=$parsed_i 
               
     }
             
     Write-host "server = $i"     
     Write-host "$dns_host"       
     write-host "Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" 
     write-host "Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)"     
     Write-host "=====================================" 
     Write-Output $(Get-Date) | Out-File -FilePath SCAN.LOG -Append
     if ($r -match '^(1|2|3|4|5)0\d$'){
        Write-Output "HTTP status code: $r " | Out-File -FilePath SCAN.LOG -Append
     } 
     Write-Output "$dns_host" | Out-File -FilePath SCAN.LOG -Append 
     Write-Output "server = $i" | Out-File -FilePath SCAN.LOG -Append  
     write-Output "Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" |Out-File -FilePath SCAN.LOG -Append
     write-Output "Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)"   | Out-File -FilePath SCAN.LOG -Append     
     #   Write-Output $var | Out-File -FilePath SCAN.LOG -Append
     Write-Output $resp.BaseResponse.Headers | Out-File -FilePath SCAN.LOG -Append
     Write-Output "-----------------------------------" | Out-File -FilePath SCAN.LOG -Append

   
 }

 $sorted_valid_dom |Select-Object -Unique | Out-File -FilePath VALID_DOMAINS.txt -Append
 $sorted_nx_dom | Select-Object -Unique | Out-File -FilePath NXDOMAIN.txt -Append 


#  $duplicat=Get-Content ./valid_address.txt
#  $unikat=@()
#  foreach($d in $duplicat){
#      if($d -match "https"){
 
#          $unikat+=$d.substring(8,$d.length-8)
 
#      } else {
 
#          $unikat+=$d
#      }
#  }
#  $unikat | select -Unique | Out-File -FilePath VALID_DOMAINS_LIST.txt -Append