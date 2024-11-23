
# **Password Expiry Reminder Script**

This PowerShell script is designed to send email reminders to users whose passwords are nearing expiration. It retrieves user data from Active Directory (AD), calculates password expiration dates, and sends customizable email notifications.

---

## **Prerequisites**
1. **Active Directory Module**:
   - Ensure the Active Directory PowerShell module is installed on the system.
2. **Email Server**:
   - Confirm that the SMTP server is accessible and configured for sending emails.
3. **File Permissions**:
   - Verify that the script has read permissions for the `ContentFile` and write permissions for the `LogPath` (if specified).
   - 
---

## **Parameters**

### **Mandatory Parameters**

1. **`SearchBase`**
   - **Description**: The Active Directory search base (distinguished name) to limit the search scope.
   - **Default**: None (searches the entire domain).
   - **Example**: 
     ```powershell
     -SearchBase "OU=Employees,DC=company,DC=com"
     ```

2. **`Filter`**
   - **Description**: A string filter for querying users in Active Directory.
   - **Example**: 
     ```powershell
     -Filter "Enabled -eq 'True'"
     ```

3. **`SmtpServer`**
   - **Description**: The SMTP server to send the email notifications through.
   - **Example**: 
     ```powershell
     -SmtpServer "smtp.company.com"
     ```

4. **`SenderAddress`**
   - **Description**: The email address from which the notifications will be sent.
   - **Example**: 
     ```powershell
     -SenderAddress "admin@company.com"
     ```

5. **`ContentFile`**
   - **Description**: Path to the file containing the email body template. The template can include placeholders `{{UserName}}` and `{{ExpiryDate}}`.
   - **Example**: 
     ```powershell
     -ContentFile "C:\Templates\EmailTemplate.html"
     ```

---

### **Optional Parameters**


1. **`IfDaysEq`**
   - **Description**: An array of integers specifying exact numbers of days until password expiration for triggering the email notification.
   - **Default**: None.
   - **Example**: 
     ```powershell
     -IfDaysEq 7, 14, 30
     ```

2. **`IfDayslt`**
   - **Description**: An array of integers specifying thresholds for "less than" conditions to trigger notifications.
   - **Default**: None.
   - **Example**: 
     ```powershell
     -IfDayslt 5
     ```

3. **`IfDaysle`**
   - **Description**: An array of integers specifying thresholds for "less than or equal to" conditions to trigger notifications.
   - **Default**: None.
   - **Example**: 
     ```powershell
     -IfDaysle 3
     ```

4. **`LogPath`**
   - **Description**: Path to the directory where log files will be stored. Defaults to the system’s temporary folder (`$Env:TEMP`) if not provided.
   - **Default**: `$Env:TEMP`.
   - **Example**: 
     ```powershell
     -LogPath "C:\Logs\PasswordExpiry"
     ```

---

## **Usage Examples**

### **Example 1: Basic Notification**
Send email reminders to all enabled users with passwords expiring in exactly 7 or 14 days.

```powershell
.\PasswordExpiryReminder.ps1 -Filter "Enabled -eq 'True'" `
                             -SmtpServer "smtp.company.com" `
                             -SenderAddress "admin@company.com" `
                             -ContentFile "C:\Templates\EmailTemplate.html" `
                             -IfDaysEq 7, 14
```

---

### **Example 2: Custom Search Base and Thresholds**
Restrict the search to a specific organizational unit (OU) and send reminders for passwords expiring in less than 5 days.

```powershell
.\PasswordExpiryReminder.ps1 -Filter "Enabled -eq 'True'" `
                             -SearchBase "OU=Employees,DC=company,DC=com" `
                             -SmtpServer "smtp.company.com" `
                             -SenderAddress "admin@company.com" `
                             -ContentFile "C:\Templates\EmailTemplate.html" `
                             -IfDayslt 5 `
                             -LogPath "C:\Logs\PasswordExpiry"
```

---

### **Example 3: Use Multiple Conditions**
Send reminders for passwords expiring in exactly 14 days or in less than 7 days.

```powershell
.\PasswordExpiryReminder.ps1 -Filter "Enabled -eq 'True'" `
                             -SmtpServer "smtp.company.com" `
                             -SenderAddress "admin@company.com" `
                             -ContentFile "C:\Templates\EmailTemplate.html" `
                             -IfDaysEq 14 `
                             -IfDayslt 7
```

---

### **Example 4: Default Log Path**
Use the system temporary directory for storing log files.

```powershell
.\PasswordExpiryReminder.ps1 -Filter "Enabled -eq 'True'" `
                             -SmtpServer "smtp.company.com" `
                             -SenderAddress "admin@company.com" `
                             -ContentFile "C:\Templates\EmailTemplate.html" `
                             -IfDaysle 3
```

---

## **Placeholders in Email Template**
The email template can contain the following placeholders:
- **`{{UserName}}`**: Replaced with the user's name.
- **`{{ExpiryDate}}`**: Replaced with the formatted password expiry date.

---

## **Logging**
- All logs are stored in the directory specified by the `-LogPath` parameter or the system’s temporary folder if not provided.
- Log entries include the following levels:
  - **INFO**: General information about script execution (e.g., emails sent).
  - **WARN**: Warnings about missing data (e.g., users without email addresses).
  - **ERROR**: Errors encountered during execution (e.g., failed AD queries).


---

## **Error Handling**
- The script includes error handling for:
  - Missing or invalid file paths.
  - Invalid email addresses for the sender.
  - AD queries that fail or return incomplete data.
- Errors and warnings are logged using the `Write-Log` function.

---
