# bulk-get-request

Disclaimer, This is a very early beta version and has been created using .NET core and will only run on *NIX* like systems.
It uses the "host" command which is not on Windows. Soon, probably will add a .NET function to replace it.

Shortly it's a simple powershell script to perform a get request using invoke-webrequest cmdlet.
It has been created to perfom bulk checks for multiple domains. To use it against a simple domain, you might also just use your browser ;)
Script has been optimised and now it will take few minutes not hours, depends how long is your list.
What is this script for anyway?
Well you can use it to check if a specific domain exists, check for a web server presence , diagnostics, OSINT, redirections and more...?
Simply put If you have a list of different domains/subdomains/servers and you would like to check if they host a web server on standard 80 and 443 ports then this script will really speed up your searches.

++ features ++
- added burp as a proxy so you can see all the GET requests in burp for further scans....
- script follows redirections (5 by default - can be changed if needed)
- and most important the user-agent header will not show powershell as the agent but it will randomly use one of the following (chrome,firefox/safari,IE,opera)
- results will be saved it 4 different files ()

Script has 2 parameters.
- list (Argument for the list parameter will be your previously created file with all domains you want to check)

- local_proxy (Arguments for the local_proxy are $true or $false.)

Usage:
start powershell on linux/mac
To send GET request via local burp proxy
   Usage: ./get-domain.ps1 -list your_file_list.txt -local_proxy $true 
   example: /get-domain.ps1 -list ./test.txt -local_proxy $true
   
   To send GET request directly
   Usage: ./get-domain.ps1 -list your_file_list.txt -local_proxy $false
   Example: /get-domain.ps1 -list ./test.txt -local_proxy $false

   You can change your burp port in the script file. vatiable name proxy_burp
   By default proxy listens on port 8080, you can also use any other proxy, does not have to be local proxy ;)
  
++ Currently working on a function that will show us all redirection steps with full details and HTTP codes.

