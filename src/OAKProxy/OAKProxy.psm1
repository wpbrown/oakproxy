function Install-OAKProxy {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCredential]$Credential     
    )

    New-EventLog -LogName "Application" -Source "OAKProxy"

    
    if ($Credential.Password.Length) {
        $args = @( "password=", $Credential.GetNetworkCredential().Password )
    } else {
        $args = @{}
    }

    # sc used for compatbility with gMSA. New-Service fails without a password.
    sc.exe create "OAKProxy" start= "auto" depend= "NetLogon" DisplayName= "OAKProxy Server" `
        binPath= "$PSScriptRoot\OAKProxy.exe -service" obj= $Credential.UserName @args
    Start-Service -Name "OAKProxy"

    "Installed OAKProxy service."
}

function Uninstall-OAKProxy {
    param (
    )

    Stop-Service -Name "OAKProxy" -Force
    sc.exe delete "OAKProxy"
    Remove-EventLog -Source "OAKProxy"

    "Uninstalled OAKProxy service."
}