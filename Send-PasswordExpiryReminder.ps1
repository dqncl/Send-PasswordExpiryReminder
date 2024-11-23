param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Filter,

    [Parameter(Mandatory = $true)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [int[]]$IfDaysEq,

    [Parameter(Mandatory = $false)]
    [int[]]$IfDayslt,

    [Parameter(Mandatory = $false)]
    [int[]]$IfDaysle,

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
            Write-Log -Level WARN -Message "User with Identity '$Identity' not found in Active Directory."
            return $null
        }

        # Extract the primary SMTP address (starts with "SMTP:")
        $PrimarySmtp = $ADUser.ProxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } |
            ForEach-Object { $_ -replace '^SMTP:', '' }

        if ($null -eq $PrimarySmtp) {
            Write-Log -Level WARN -Message "User '$Identity' does not have a primary SMTP address."
        }

        return $PrimarySmtp
    } catch {
        Write-Log -Level ERROR -Message "Error retrieving SMTP address for user '$Identity': $_"
        return $null
    }
}

function Get-TargetDates {
    param (
        [datetime]$CurrentDate,
        [int[]]$Days
    )
    if ($null -eq $Days) {
        return @()
    }
    return $Days | ForEach-Object { $CurrentDate.AddDays($_) }
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
    if (!$LogPath) {
        $LogPath = $Env:TEMP # Use environment variable for default log path
    }
    [string]$LogFile = "$LogPath\Log_$Timestamp.log"

    # Ensure the directory exists
    if (!(Test-Path $LogPath)) {
        try {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        } catch {
            Write-Log -Level ERROR -Message "Failed to create log directory at $LogPath : $_"
            return
        }
    }

    # Format log message
    $LogEntry = "[$Timestamp] [$Level] $Message"

    # Write to console
    switch ($Level) {
        "INFO"  { Write-Host $LogEntry -ForegroundColor Green }
        "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "DEBUG" { Write-Host $LogEntry -ForegroundColor Cyan }
    }

    # Write to log file
    Add-Content -Path $LogFile -Value $LogEntry
}

function Send-PasswordExpiryReminder {
    # Validate the content file
    if (!Test-Path $ContentFile) {
        throw "The file specified in ContentFile does not exist: $ContentFile"
    }

    # Regex pattern to validate SenderAddress
    $EmailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # Validate email
    if (!($SenderAddress -match $EmailRegex)) {
        throw "The provided SenderAddress is not a valid email address"
    }

    # Load the content file
    $EmailBodyTemplate = Get-Content $ContentFile -Raw

    # Calculate password expiration thresholds
    $CurrentDate = Get-Date
    $TargetDatesEq = Get-TargetDates -CurrentDate $CurrentDate -Days $IfDaysEq
    $TargetDatesLt = Get-TargetDates -CurrentDate $CurrentDate -Days $IfDayslt
    $TargetDatesLe = Get-TargetDates -CurrentDate $CurrentDate -Days $IfDaysle

    # Convert the target dates to FileTime format for comparison
    $TargetFileTimesEq = $TargetDatesEq | ForEach-Object { $_.ToFileTime() }
    $TargetFileTimesLt = $TargetDatesLt | ForEach-Object { $_.ToFileTime() }
    $TargetFileTimesLe = $TargetDatesLe | ForEach-Object { $_.ToFileTime() }

    try {
        # Query AD for users
        $Users = Get-ADUser -Filter $Filter -SearchBase $SearchBase -Property EmailAddress, msDS-UserPasswordExpiryTimeComputed |
            Where-Object {
                $ExpiryFileTime = $_.'msDS-UserPasswordExpiryTimeComputed'
                ($IfDaysEq -and ($ExpiryFileTime -in $TargetFileTimesEq)) -or
                ($IfDayslt -and ($ExpiryFileTime -lt ($TargetFileTimesLt | Measure-Object -Minimum).Minimum.ToFileTime())) -or
                ($IfDaysle -and ($ExpiryFileTime -le ($TargetFileTimesLe | Measure-Object -Minimum).Minimum.ToFileTime()))
            }
    } catch {
        Write-Log -Level ERROR -Message "Failed to query AD users: $_"
        return
    }

    # Send email notifications
    foreach ($User in $Users) {
        $EmailAddress = Get-PrimarySmtpAddress -Identity $User.SamAccountName
        if (!$EmailAddress) {
            Write-Log -Level WARN -Message "User $($User.SamAccountName) does not have an email address. Skipping."
            continue
        }

        $ExpiryDate = [datetime]::FromFileTime($User.'msDS-UserPasswordExpiryTimeComputed')
        $EmailBody = $EmailBodyTemplate -replace '{{UserName}}', $User.Name -replace '{{ExpiryDate}}', $ExpiryDate.ToString()

        try {
            Send-MailMessage -To $EmailAddress -From $SenderAddress `
                -Subject "Password Expiry Reminder" `
                -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer

            Write-Log -Level INFO -Message "Email sent to $EmailAddress for user $($User.Name)"
        } catch {
            Write-Log -Level ERROR -Message "Failed to send email to $EmailAddress : $_"
        }
    }
}

# Call main function
Send-PasswordExpiryReminder
