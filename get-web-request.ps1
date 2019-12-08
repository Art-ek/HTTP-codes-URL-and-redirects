
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][string]$list,
    [Parameter(Mandatory=$false)][bool]$local_proxy=$false
)
$OutputEncoding = [ System.Text.Encoding]::UTF8
$dns_host=0;
$domain_dict=@{}
$sorted_valid_dom=@()
$sorted_nx_dom=@()
$proxy_burp="http://127.0.0.1:8080"
# API token for ipinfo.io
$token='API token'
# AbuseIP API address and key
$abuseIPurl = 'https://api.abuseipdb.com/api/v2/check'
$headers = @{
    Accept= "application/json"
    Key= "API key"
}



$path=Test-Path $list;
if($list -eq ''-or $list -eq $null)
{

   Write-Host '@
   To send GET request via local burp proxy
   Usage: ./get-web-request.ps1 -list your_file_list.txt -local_proxy $true 
   example: /get-web-request.ps1 -list ./test.txt -local_proxy $true
   
   To send GET request directly
   Usage: ./get-web-request.ps1 -list your_file_list.txt -local_proxy $false
   Example: /get-web-request.ps1 -list ./test.txt -local_proxy $false

   You can change your burp port in the this file. variable name is: proxy_burp
   By default proxy listens on port 8080

   @'
   break
}

if(!$path -or $path -eq $null)
{
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

# creating an array containing both HTTP and HTTPS addresses

#creating an array inside hashtable {domain_name:(http_address,https_address)}
foreach ($a in $domain_list)
{
   $domain_dict.Add($a,@("http://$a","https://$a"))
}

foreach($key in $domain_dict.Keys)
{
        $abuse=$null
        $no_dns=$false
        $errorrequest="N/A"
        $errorstatus="N/A"
        $resp=$null
        $city="N/A"
        $country="N/A"
        $region="N/A"
        $hostingname="N/A"
        $hostingcompany="N/A"
        $IP=$false


        for($x=0;$x -lt 2;$x++)
            {
            $errorrequest=$null
            $errorstatus=$null
            
            $resp=try
            {
                if($local_proxy -eq $true)
                {    
                    $agent=$agents | Get-Random
                    Invoke-WebRequest -uri $domain_dict[$key][$x] -UserAgent $agent -Proxy $proxy_burp -TimeoutSec 3 -SkipCertificateCheck 
                }
                else
                {
                    $agent=$agents | Get-Random
                    Invoke-WebRequest -uri $domain_dict[$key][$x] -UserAgent $agent -TimeoutSec 3 -SkipCertificateCheck  

                }

            }
            catch
            {
                $errorrequest=$_.exception.response.Headers.Location.AbsoluteUri
                $errorstatus=$_.exception.response.statuscode
            }
    

        $dns_host=host $key
        if ( $dns_host -match "NXDOMAIN" -or $dns_host -match "SERVFAIL" -or $dns_host -eq $null)
        {
            $no_dns=$true
             
            $sorted_nx_dom+=$key

            Write-host "[-] Non existent domain" -BackgroundColor Red -ForegroundColor Black          
     
        } 
        else 
        {
     
            if($IP -ne $false){
                $IP=([system.net.dns]::GetHostByName($key)).AddressList | Select-Object -ExpandProperty ipaddresstostring -First 1
            }
            else
            {   
                $IP=([system.net.dns]::GetHostByName($key)).AddressList | Select-Object -ExpandProperty ipaddresstostring -First 1  
                $geo="ipinfo.io/$IP/geo?token=$token"
                $hosting="ipinfo.io/$IP/json?org?token=$token"
                $body = @{
                    ipAddress= $IP
                    maxAgeInDays= "365"
                    verbose=""
                }
                $abuse=Invoke-RestMethod -uri $abuseIPurl -Headers $headers -Body $body -Method get 
                $geoinfo=Invoke-RestMethod -uri $geo 
                $hostingInfo=Invoke-RestMethod -uri $hosting
            }   
           
        

        $sorted_valid_dom+=$key
        $city=$geoinfo.City
        $country=$geoinfo.Country
        $region=$geoinfo.Region
        $hostingname=$hostingInfo.hostname
        $hostingcompany=$hostingInfo.org  
                                                               
     #$var | select-string "NXDOMAIN" | Out-File -FilePath NXDOMAIN.txt -Append
     $r=$resp | Select-Object  -ExpandProperty statuscode

     if (($r -match '^(1|2|3|4|5)0\d$' -or $r -eq "Unauthorized" -or $r -eq "Forbidden" -or $r -eq "MethodNotAllowed") -and $resp -notmatch "burp")
     {
        $domain_dict[$key][$x] | Out-File -FilePath valid_address.txt -Append
        
        Write-host "response = $r [+] Web Server is reachable" -BackgroundColor Green -ForegroundColor Black
     } 
     else 
     {
        $domain_dict[$key][$x] | Out-File -FilePath invalid_address.txt -Append
      
        Write-host "response = $r [$errorstatus] Web Address cannot be reached " -BackgroundColor Red -ForegroundColor Black
     }
    }
     # Later on will use the tee-object         
     Write-host "■ Web Server = $($domain_dict[$key][$x])" 
     if($no_dns)
     {
         Write-host "■ $dns_host"  
     }
     else
     {
        Write-host "■ $dns_host"
        Write-Host "■ Location -> Country: $country, Region: $region, City: $city"  
        Write-Host "■ Hosting Server = $hostingname, Hosting Company = $hostingcompany"   
        write-host "■ Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" 
     if($resp.BaseResponse.RequestMessage.RequestUri.Originalstring -match "http://")
     {
        write-host "■ Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)  ¯\_(ツ)_/¯ ekhem no tls?"    
     }
     else
     {
        write-host "■ Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring) "   
 
     }
        write-host "■ Error Status code = $errorstatus, Redirected to: $errorrequest "
        Write-host "=====================================" 
     }
     Write-Output $(Get-Date) | Out-File -FilePath SCAN.LOG -Append
     if ($r -match '^(1|2|3|4|5)0\d$')
     {
        Write-Output "HTTP status code: $r " | Out-File -FilePath SCAN.LOG -Append
     } 
     Write-Output "$dns_host" | Out-File -FilePath SCAN.LOG -Append 
     Write-Output "Web Server = $($domain_dict[$key][$x])" | Out-File -FilePath SCAN.LOG -Append 
     Write-Output "Location -> Country: $country, Region: $region, City: $city" | Out-File -FilePath SCAN.LOG -Append   
     Write-Output "Hosting Server = $hostingname, Hosting Company = $hostingcompany" |  Out-File -FilePath SCAN.LOG -Append   
     write-Output "Original domain = $($resp.BaseResponse.RequestMessage.RequestUri.Host)" |Out-File -FilePath SCAN.LOG -Append
     write-Output "Destination page = $($resp.BaseResponse.RequestMessage.RequestUri.Originalstring)"   | Out-File -FilePath SCAN.LOG -Append     
     #   Write-Output $var | Out-File -FilePath SCAN.LOG -Append
     Write-Output $resp.BaseResponse.Headers | Out-File -FilePath SCAN.LOG -Append
     Write-Output "Error Status code = $errorstatus, Redirected to: $errorrequest " | Out-File -FilePath SCAN.LOG -Append
     Write-Output "-----------------------------------" | Out-File -FilePath SCAN.LOG -Append

   
    }
    Write-host "Abuse IP summary from AbuseIPdb.com "
    $abuse.data | select totalreports,numDistinctUsers,abuseConfidenceScore,lastReportedAt,ipAddress,Countryname | fl
    write-host "Categories : $($abuse.data.reports |
    ForEach-Object{ switch($_.categories)
        {
            
            
            3 {"Fraud Orders, "}
            4 {"DDos, "}
            5 {"FTP Brute-Force, "}
            6 {"Ping of Death, "}
            7 {"Phishing, "}
            8 {"Fraud VoIP, "}
            9 {"Open Proxy, "}
            10 {"Web Spam, "}
            11 {"Email Spam, "}
            12 {"Blog Spam, "}
            13 {"VPN IP, "}
            14 {"Port Scan, "}
            15 {"Hacking, "}
            16 {"SQL Injection, "}
            17 {"Spoofing, "}
            18 {"Brute-ForceBad, "}
            19 {"Bad Web BOT, "}
            20 {"Exploited Host, "}
            21 {"Web App Attack, "}
            22 {"SSH, "}
            23 {"IOT Attack, "}
        }
        } | Select-Object -Unique) "
    Write-Host "https://www.abuseipdb.com/check/$IP"
    write-host "+++++++++++++++++++++++++++++++++++++++++++++"

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
