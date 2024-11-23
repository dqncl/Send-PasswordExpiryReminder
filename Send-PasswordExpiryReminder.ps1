param (
    [Parameter(Mandatory = $true)]
    [string]$Filter,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [byte[]]$IfDaysEq,

    [Parameter(Mandatory = $false)]
    [byte[]]$IfDayslt,

    [Parameter(Mandatory = $false)]
    [byte[]]$IfDaysle,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SenderAddress,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ContentFile,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$LogPath
)

function Get-PrimarySmtpAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )
    try {
        # Retrieve the user object with email addresses
        $ADUser = Get-ADUser -Identity $Identity -Property ProxyAddresses

        if ($null -eq $ADUser) {
            Write-Log -Level ERROR -Message "User with Identity '$Identity' not found in Active Directory."
        }

        # Extract the primary SMTP address (starts with "SMTP:")
        # must be cmatch because with match all proxyaddresses are listed as reciepient 
        $PrimarySmtp = $ADUser.ProxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } |
        ForEach-Object { $_ -replace '^SMTP:', '' }

        if ($null -eq $PrimarySmtp) {
            Write-Log -Level WARN -Message "User '$Identity' does not have a primary SMTP address."
        }

        return $PrimarySmtp

    }
    catch {
        Write-Log -Level ERROR -Message "Error retrieving SMTP address for user '$Identity': $_"
        return $null
    }
}

function Send-PasswordExpiryReminder {

    # Validate the content file
    if (-not (Test-Path $ContentFile)) {
        Write-Log -Level ERROR -Message "The file specified in ContentFile does not exist: $ContentFile"
    }

    # Regex pattern to validate SenderAddress
    $EmailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # Validate email
    if (-not ($SenderAddress -match $EmailRegex)) {
        Write-Log -Level ERROR -Message "The provided SenderAddress is not a valid email address"
    }

    # Load the content file
    $EmailBodyTemplate = Get-Content $ContentFile -Raw

    # Calculate password expiration thresholds
    $CurrentDate = Get-Date
    $TargetDatesEq = @()
    $TargetDatesLt = @()
    $TargetDatesLe = @()

    if ($IfDaysEq) {
        $TargetDatesEq = $IfDaysEq | ForEach-Object { $CurrentDate.AddDays($_) }
    }
    if ($IfDayslt) {
        $TargetDatesLt = $IfDayslt | ForEach-Object { $CurrentDate.AddDays($_) }
    }
    if ($IfDaysle) {
        $TargetDatesLe = $IfDaysle | ForEach-Object { $CurrentDate.AddDays($_) }
    }

    # Convert the target dates to FileTime format for comparison
    $TargetFileTimesEq = $TargetDatesEq | ForEach-Object { $_.ToFileTime() }
    $TargetFileTimesLt = $TargetDatesLt | ForEach-Object { $_.ToFileTime() }
    $TargetFileTimesLe = $TargetDatesLe | ForEach-Object { $_.ToFileTime() }

    # Query AD for users
    $Users = Get-ADUser -Filter $Filter -SearchBase $SearchBase -Property EmailAddress, msDS-UserPasswordExpiryTimeComputed |
    Where-Object {
        $ExpiryFileTime = $_.'msDS-UserPasswordExpiryTimeComputed'
        $ExpiryDate = [datetime]::FromFileTime($ExpiryFileTime)

            ($IfDaysEq -and ($ExpiryFileTime -in $TargetFileTimesEq)) -or
            ($IfDayslt -and ($ExpiryFileTime -lt ($TargetDatesLt | Measure-Object -Minimum).Minimum.ToFileTime())) -or
            ($IfDaysle -and ($ExpiryFileTime -le ($TargetDatesLe | Measure-Object -Minimum).Minimum.ToFileTime()))
    }


        
    # Send email notifications
    foreach ($User in $Users) {
        $EmailAddress = Get-PrimarySmtpAddress -Identity $User.SamAccountName
        if (-not $EmailAddress) {
            Write-Warning "User $($User.SamAccountName) does not have an email address. Skipping."
            continue
        }

        $ExpiryDate = [datetime]::FromFileTime($User.'msDS-UserPasswordExpiryTimeComputed')
        $EmailBody = $EmailBodyTemplate -replace '{{UserName}}', $User.Name -replace '{{ExpiryDate}}', $ExpiryDate.ToString()

        try {
            Send-MailMessage -To $EmailAddress -From $SenderAddress `
                -Subject "Password Expiry Reminder" `
                -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer

            if ($LogPath) {
                Write-Log -Level INFO -Message "Email sent to $EmailAddress for user $($User.Name)"
            }  
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to send email to $EmailAddress : $_"
        }
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    # Get timestamp
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") # Replace invalid characters

    # Define the log file path
    if (-not $Global:LogPath) {
        $Global:LogPath = $env:TEMP # Default log path if not set
    }
    [string]$LogFile = "$LogPath\Log_$Timestamp.log" 

    # Ensure the directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    # Format log message
    $LogEntry = "[$Timestamp] [$Level] $Message"

    # Write to console
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Green }
        "WARN" { Write-Warning $Message }
        "ERROR" { Write-Error $Message }
        "DEBUG" { Write-Host $LogEntry -ForegroundColor Cyan }
    }

    # Write to log file
    Add-Content -Path $LogFile -Value $LogEntry
}

Send-PasswordExpiryReminder 

