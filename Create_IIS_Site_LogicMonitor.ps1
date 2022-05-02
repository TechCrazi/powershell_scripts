#Change LogicMonitorSiteName with the site name you are working with
$LogicMonitorSiteName		= "LogicMonitorTestSite"

#Do not change anthing bellow this
$SiteFolderPath = "C:\inetpub\wwwroot\" + $LogicMonitorSiteName # Website Folder
$SiteAppPool 	= $LogicMonitorSiteName # Application Pool Name
$SiteName 		= $LogicMonitorSiteName # IIS Site Name
$SiteHostName 	= $LogicMonitorSiteName # Host Header


$bindings = @(
   @{protocol="http";bindingInformation="*:80:"+$SiteName;SslFlags=0},
   @{protocol="https";bindingInformation="*:443:"+$SiteName;SslFlags=0}
)

# Import IIS module
Import-Module WebAdministration

# Checking is IIS folder exist, if not then create a new one
#New-Item $SiteFolderPath -type Directory
     if(Test-path $SiteFolderPath) {
         Write-Host "The folder $SiteFolderPath already exists, moving on to to create the site and app pool." -ForegroundColor Yellow
         }
     else{
         New-Item $SiteFolderPath -type Directory
        }

New-Item IIS:\AppPools\$SiteAppPool #Creating main application pool
New-Item IIS:\Sites\$SiteName -physicalPath $SiteFolderPath -bindings $bindings #Adding binding to the site
Set-ItemProperty IIS:\Sites\$SiteName -name applicationPool -value $SiteAppPool #Setting up site app pool


# Get Site Binding Info
Get-WebBinding $SiteName



# Complete