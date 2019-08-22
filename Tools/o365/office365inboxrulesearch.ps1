
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$password,

[Parameter(Mandatory=$True)]
[string]$email,

[Parameter(Mandatory=$False)]
[string]$timeout = 30
)

$searchName = "InboxRule-" + $email

# Create Credential object
$secpasswd = ConvertTo-SecureString $password -asSecureString -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)


# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
if (!$session)
{
    "Failed to create remote PS session"
    return
}

Import-PSSession $session -AllowClobber -DisableNameChecking

# Creates the search
Get-InboxRule -mailbox $email | export-csv .\$searchName.csv
