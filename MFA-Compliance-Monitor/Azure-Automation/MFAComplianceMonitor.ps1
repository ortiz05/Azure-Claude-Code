<#
.SYNOPSIS
    Azure Automation for monitoring MFA compliance and notifying users of non-Microsoft Authenticator usage
    
.DESCRIPTION
    This script analyzes Azure AD sign-in logs to identify users who have used MFA methods
    other than Microsoft Authenticator in the last 30 days. It sends notification emails
    to users and provides detailed reporting for IT administrators.
    
.PARAMETER DaysToAnalyze
    Number of days to look back for sign-in analysis (default: 30)
    
.PARAMETER WhatIf
    Run in simulation mode without sending emails
    
.PARAMETER ITAdminEmails
    Array of IT administrator email addresses to CC on notifications
    
.PARAMETER ExcludedUsers
    Array of user UPNs to exclude from monitoring
    
.PARAMETER ExportPath
    Path where CSV reports will be saved (DEPRECATED - use blob storage)
    
.PARAMETER StorageAccountName
    Azure Storage Account name for report storage (required for blob storage)
    
.PARAMETER StorageContainerName
    Azure Storage Container name for reports (default: mfa-compliance-reports)
    
.PARAMETER UseManagedIdentity
    Use Azure Automation managed identity for authentication (recommended)
    
.PARAMETER IncludeCompliantUsers
    Include users who only used Microsoft Authenticator in reports
    
.PARAMETER SendUserNotifications
    Enable/disable user notification emails
    
.PARAMETER SendAdminSummary
    Enable/disable admin summary reports
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$DaysToAnalyze = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedUsers = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\MFAComplianceReports",
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageContainerName = "mfa-compliance-reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseManagedIdentity = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeCompliantUsers = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendUserNotifications = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendAdminSummary = $true
)

# Import required modules
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Import Azure Storage modules for blob storage functionality
if ($StorageAccountName) {
    Import-Module Az.Storage -ErrorAction Stop
    Import-Module Az.Accounts -ErrorAction Stop
}
Import-Module Microsoft.Graph.Reports -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

# Initialize tracking collections
$Script:NonCompliantUsers = [System.Collections.ArrayList]::new()
$Script:CompliantUsers = [System.Collections.ArrayList]::new()
$Script:ProcessingErrors = [System.Collections.ArrayList]::new()
$Script:EmailsSent = [System.Collections.ArrayList]::new()

#region Helper Functions

function Export-ToBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$BlobName,
        
        [Parameter(Mandatory=$false)]
        [string]$StorageAccount = $StorageAccountName,
        
        [Parameter(Mandatory=$false)]
        [string]$ContainerName = $StorageContainerName
    )
    
    if (-not $StorageAccount) {
        Write-Warning "No storage account specified. Skipping blob upload for $BlobName"
        return $false
    }
    
    try {
        # Create storage context using managed identity
        $Context = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount
        
        # Create folder structure with year/month
        $DatePath = Get-Date -Format "yyyy/MM"
        $BlobPath = "$DatePath/$BlobName"
        
        # Upload file to blob storage
        $BlobResult = Set-AzStorageBlobContent -File $FilePath -Container $ContainerName -Blob $BlobPath -Context $Context -StandardBlobTier Cool -Force
        
        Write-Output "✓ Uploaded to blob storage: $($BlobResult.Name)"
        return $true
    }
    catch {
        Write-Warning "Failed to upload $BlobName to blob storage: $_"
        return $false
    }
}

function Test-RequiredPermissions {
    [CmdletBinding()]
    param()
    
    Write-Output "Validating Graph API permissions..."
    
    $RequiredPermissions = @{
        "AuditLog.Read.All" = $false
        "User.Read.All" = $false
        "Mail.Send" = $false
        "Directory.Read.All" = $false
    }
    
    $AllPermissionsValid = $true
    
    try {
        $Context = Get-MgContext
        if ($null -eq $Context) {
            Write-Error "Not connected to Microsoft Graph"
            return $false
        }
        
        $CurrentScopes = $Context.Scopes
        
        foreach ($Permission in $RequiredPermissions.Keys) {
            $HasPermission = $CurrentScopes -contains $Permission
            $RequiredPermissions[$Permission] = $HasPermission
            
            if ($HasPermission) {
                Write-Output "  ✓ $Permission - Granted"
            } else {
                Write-Warning "  ✗ $Permission - Missing or not granted"
                $AllPermissionsValid = $false
            }
        }
        
        return $AllPermissionsValid
    }
    catch {
        Write-Error "Permission validation failed: $_"
        return $false
    }
}

function Get-MFAMethodDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AuthMethod
    )
    
    # Map Graph API authentication method names to user-friendly names
    $MethodMapping = @{
        "microsoftAuthenticatorPush" = "Microsoft Authenticator (Push)"
        "microsoftAuthenticatorOTP" = "Microsoft Authenticator (OTP)"
        "softwareOath" = "Software OATH Token"
        "sms" = "SMS Text Message"
        "voice" = "Voice Call"
        "email" = "Email"
        "fido2" = "FIDO2 Security Key"
        "windowsHelloForBusiness" = "Windows Hello for Business"
        "certificate" = "Certificate-based Authentication"
        "federatedSingleSignOn" = "Federated SSO"
        "oath" = "OATH Hardware Token"
        "unknownFutureValue" = "Unknown Method"
    }
    
    return $MethodMapping[$AuthMethod] ?? $AuthMethod
}

function Get-DeviceDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$DeviceDetail
    )
    
    if ([string]::IsNullOrEmpty($DeviceDetail)) {
        return "Unknown Device"
    }
    
    try {
        $DeviceInfo = $DeviceDetail | ConvertFrom-Json
        $DisplayName = ""
        
        if ($DeviceInfo.displayName) {
            $DisplayName = $DeviceInfo.displayName
        } elseif ($DeviceInfo.browser) {
            $DisplayName = "$($DeviceInfo.browser)"
            if ($DeviceInfo.operatingSystem) {
                $DisplayName += " on $($DeviceInfo.operatingSystem)"
            }
        } elseif ($DeviceInfo.operatingSystem) {
            $DisplayName = $DeviceInfo.operatingSystem
        } else {
            $DisplayName = "Unknown Device"
        }
        
        return $DisplayName
    }
    catch {
        return $DeviceDetail
    }
}

function Send-MFAComplianceNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RecipientEmail,
        
        [Parameter(Mandatory=$true)]
        [string]$RecipientName,
        
        [Parameter(Mandatory=$true)]
        [array]$NonCompliantSignIns,
        
        [Parameter(Mandatory=$false)]
        [string[]]$CCEmails = @()
    )
    
    # Generate sign-in details table for email
    $SignInTableRows = $NonCompliantSignIns | ForEach-Object {
        $DeviceName = Get-DeviceDisplayName -DeviceDetail $_.DeviceDetail
        $MFAMethod = Get-MFAMethodDisplayName -AuthMethod $_.AuthenticationMethod
        $SignInTime = ([DateTime]$_.CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss")
        
        @"
        <tr>
            <td>$SignInTime</td>
            <td>$DeviceName</td>
            <td>$MFAMethod</td>
            <td>$($_.Location)</td>
        </tr>
"@
    }
    
    $EmailBody = @"
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .alert { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 15px; margin: 20px 0; }
        .alert-icon { color: #856404; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #f8f9fa; text-align: left; padding: 12px; border: 1px solid #dee2e6; font-weight: bold; }
        td { padding: 10px; border: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .action-required { background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 4px; padding: 15px; margin: 20px 0; }
        .footer { font-size: 12px; color: #666; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; }
        .highlight { background: #fff3cd; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>🔐 MFA Security Notice: Non-Standard Authentication Detected</h2>
        <p>Important security notification regarding your multi-factor authentication methods</p>
    </div>
    
    <p>Dear $RecipientName,</p>
    
    <div class="alert">
        <span class="alert-icon">⚠️ Security Alert:</span><br>
        Our monitoring systems have detected that you've used <strong>non-Microsoft Authenticator</strong> methods 
        for multi-factor authentication in the past $DaysToAnalyze days. This may pose security risks to your account and our organization.
    </div>
    
    <h3>📊 Recent Non-Compliant Sign-Ins</h3>
    <table>
        <thead>
            <tr>
                <th>📅 Date & Time</th>
                <th>💻 Device/Browser</th>
                <th>🔐 MFA Method Used</th>
                <th>📍 Location</th>
            </tr>
        </thead>
        <tbody>
            $($SignInTableRows -join "`n")
        </tbody>
    </table>
    
    <div class="action-required">
        <h3>🎯 Action Required</h3>
        <p><strong>Please take the following steps to ensure your account security:</strong></p>
        <ol>
            <li><strong>Install Microsoft Authenticator:</strong> Download from your device's app store</li>
            <li><strong>Configure Microsoft Authenticator:</strong> Set it up as your primary MFA method</li>
            <li><strong>Remove non-compliant methods:</strong> Disable SMS, voice calls, or other non-Authenticator methods</li>
            <li><strong>Test your setup:</strong> Verify Microsoft Authenticator works for your next sign-in</li>
        </ol>
    </div>
    
    <h3>🛡️ Why Microsoft Authenticator is Required</h3>
    <ul>
        <li><strong>Enhanced Security:</strong> More secure than SMS or voice calls</li>
        <li><strong>Phishing Protection:</strong> Built-in protection against phishing attacks</li>
        <li><strong>Offline Capability:</strong> Works without cellular or internet connection</li>
        <li><strong>Company Policy:</strong> Required for compliance with our security standards</li>
    </ul>
    
    <h3>📞 Need Help?</h3>
    <p>If you need assistance setting up Microsoft Authenticator or have questions about this notice:</p>
    <ul>
        <li><strong>IT Help Desk:</strong> Contact your IT support team</li>
        <li><strong>Self-Service:</strong> Visit the company security portal</li>
        <li><strong>Documentation:</strong> Check the MFA setup guide in your employee resources</li>
    </ul>
    
    <div class="alert">
        <span class="alert-icon">🚨 Important:</span><br>
        <strong>Deadline for Compliance:</strong> Please update your MFA settings within <span class="highlight">7 days</span> 
        to maintain access to company resources. Non-compliant accounts may be subject to access restrictions.
    </div>
    
    <p>Thank you for helping us maintain the security of our organization's data and systems.</p>
    
    <div class="footer">
        <p><strong>This is an automated security notification.</strong></p>
        <p>Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>If you believe this notification was sent in error, please contact your IT administrator immediately.</p>
        <p><strong>Do not reply to this email.</strong> This mailbox is not monitored.</p>
    </div>
</body>
</html>
"@
    
    # Prepare recipient list
    $Recipients = @(
        @{
            EmailAddress = @{
                Address = $RecipientEmail
                Name = $RecipientName
            }
        }
    )
    
    # Add CC recipients if provided
    $CCRecipients = @()
    if ($CCEmails.Count -gt 0) {
        $CCRecipients = $CCEmails | ForEach-Object {
            @{
                EmailAddress = @{
                    Address = $_
                }
            }
        }
    }
    
    # Create email message
    $EmailMessage = @{
        Message = @{
            Subject = "🔐 SECURITY ALERT: Update Your MFA Settings - Action Required"
            Body = @{
                ContentType = "HTML"
                Content = $EmailBody
            }
            ToRecipients = $Recipients
            CcRecipients = $CCRecipients
            Importance = "High"
        }
        SaveToSentItems = $true
    }
    
    try {
        if (-not $WhatIf) {
            $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10 -Compress
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson
            Write-Output "  ✓ Security notification sent to $RecipientEmail"
            
            # Track sent email
            [void]$Script:EmailsSent.Add(@{
                Recipient = $RecipientEmail
                SentTime = Get-Date
                NonCompliantSignIns = $NonCompliantSignIns.Count
            })
        } else {
            Write-Output "  [WhatIf] Would send security notification to $RecipientEmail"
        }
        
        return $true
    }
    catch {
        Write-Warning "  ✗ Failed to send notification to $RecipientEmail`: $_"
        return $false
    }
}

function Send-AdminSummaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$AdminEmails,
        
        [Parameter(Mandatory=$true)]
        [array]$NonCompliantUsers,
        
        [Parameter(Mandatory=$true)]
        [array]$CompliantUsers,
        
        [Parameter(Mandatory=$true)]
        [array]$ProcessingErrors
    )
    
    $TotalUsers = $NonCompliantUsers.Count + $CompliantUsers.Count
    $ComplianceRate = if ($TotalUsers -gt 0) { 
        [math]::Round(($CompliantUsers.Count / $TotalUsers) * 100, 2) 
    } else { 100 }
    
    # Generate top non-compliant methods
    $MethodUsage = @{}
    $NonCompliantUsers | ForEach-Object {
        $_.NonCompliantMethods | ForEach-Object {
            $Method = Get-MFAMethodDisplayName -AuthMethod $_
            if ($MethodUsage.ContainsKey($Method)) {
                $MethodUsage[$Method]++
            } else {
                $MethodUsage[$Method] = 1
            }
        }
    }
    
    $TopMethods = $MethodUsage.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    
    $EmailBody = @"
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #0078d4; }
        .summary-number { font-size: 24px; font-weight: bold; color: #0078d4; }
        .summary-label { color: #666; font-size: 14px; margin-top: 5px; }
        .alert-card { border-left-color: #dc3545; }
        .alert-number { color: #dc3545; }
        .success-card { border-left-color: #28a745; }
        .success-number { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #f8f9fa; text-align: left; padding: 10px; border: 1px solid #dee2e6; }
        td { padding: 8px; border: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .section { margin: 30px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 MFA Compliance Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Analysis Period: Last $DaysToAnalyze days</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <div class="summary-number">$TotalUsers</div>
            <div class="summary-label">Total Users Analyzed</div>
        </div>
        <div class="summary-card alert-card">
            <div class="summary-number alert-number">$($NonCompliantUsers.Count)</div>
            <div class="summary-label">Non-Compliant Users</div>
        </div>
        <div class="summary-card success-card">
            <div class="summary-number success-number">$($CompliantUsers.Count)</div>
            <div class="summary-label">Compliant Users</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$ComplianceRate%</div>
            <div class="summary-label">Compliance Rate</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$($Script:EmailsSent.Count)</div>
            <div class="summary-label">Notifications Sent</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$($ProcessingErrors.Count)</div>
            <div class="summary-label">Processing Errors</div>
        </div>
    </div>
    
    $(if ($NonCompliantUsers.Count -gt 0) {
        @"
        <div class="section">
            <h2>🚨 Non-Compliant Users (Top 10)</h2>
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Email</th>
                        <th>Non-Compliant Sign-Ins</th>
                        <th>Methods Used</th>
                        <th>Last Non-Compliant Sign-In</th>
                    </tr>
                </thead>
                <tbody>
                    $(($NonCompliantUsers | Select-Object -First 10 | ForEach-Object {
                        $Methods = ($_.NonCompliantMethods | ForEach-Object { Get-MFAMethodDisplayName -AuthMethod $_ }) -join ", "
                        "<tr>
                            <td>$($_.DisplayName)</td>
                            <td>$($_.UserPrincipalName)</td>
                            <td>$($_.NonCompliantSignIns.Count)</td>
                            <td>$Methods</td>
                            <td>$($_.LastNonCompliantSignIn)</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($TopMethods.Count -gt 0) {
        @"
        <div class="section">
            <h2>📊 Most Common Non-Compliant MFA Methods</h2>
            <table>
                <thead>
                    <tr>
                        <th>Authentication Method</th>
                        <th>Usage Count</th>
                    </tr>
                </thead>
                <tbody>
                    $(($TopMethods | ForEach-Object {
                        "<tr>
                            <td>$($_.Key)</td>
                            <td>$($_.Value)</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($ProcessingErrors.Count -gt 0) {
        @"
        <div class="section">
            <h2>⚠️ Processing Errors</h2>
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Error Message</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    $(($ProcessingErrors | ForEach-Object {
                        "<tr>
                            <td>$($_.User)</td>
                            <td>$($_.Error)</td>
                            <td>$($_.Timestamp)</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    <div class="section">
        <h2>📋 Recommendations</h2>
        <ul>
            $(if ($NonCompliantUsers.Count -gt 0) {
                "<li><strong>Priority Action:</strong> Follow up with $($NonCompliantUsers.Count) non-compliant users within 7 days</li>"
            })
            $(if ($ComplianceRate -lt 90) {
                "<li><strong>Training:</strong> Consider organization-wide MFA training (compliance rate: $ComplianceRate%)</li>"
            })
            <li><strong>Policy:</strong> Review and potentially enforce Microsoft Authenticator-only policies</li>
            <li><strong>Monitoring:</strong> Continue weekly monitoring until compliance reaches 95%+</li>
            $(if ($ProcessingErrors.Count -gt 0) {
                "<li><strong>Technical:</strong> Investigate and resolve $($ProcessingErrors.Count) processing errors</li>"
            })
        </ul>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #666;">
        <p>This report was automatically generated by the MFA Compliance Monitor.</p>
        <p>For questions or technical issues, contact the IT Security team.</p>
    </div>
</body>
</html>
"@
    
    foreach ($AdminEmail in $AdminEmails) {
        $EmailMessage = @{
            Message = @{
                Subject = "🔐 MFA Compliance Report - $(Get-Date -Format 'yyyy-MM-dd')"
                Body = @{
                    ContentType = "HTML"
                    Content = $EmailBody
                }
                ToRecipients = @(
                    @{
                        EmailAddress = @{
                            Address = $AdminEmail
                        }
                    }
                )
                Importance = "Normal"
            }
            SaveToSentItems = $true
        }
        
        try {
            if (-not $WhatIf) {
                $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10 -Compress
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson
                Write-Output "Admin summary report sent to $AdminEmail"
            } else {
                Write-Output "[WhatIf] Would send admin report to $AdminEmail"
            }
        }
        catch {
            Write-Warning "Failed to send admin report to $AdminEmail`: $_"
        }
    }
}

#endregion

#region Main Processing Functions

function Get-NonCompliantMFAUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$DaysBack
    )
    
    Write-Output "Analyzing sign-in logs for the last $DaysBack days..."
    
    $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
    $Filter = "createdDateTime ge $StartDate and signInEventTypes/any(t: t eq 'interactiveUser')"
    
    try {
        # Get sign-in logs with MFA details
        Write-Output "Retrieving sign-in logs from Microsoft Graph..."
        
        $SignInLogs = @()
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$select=id,createdDateTime,userPrincipalName,userDisplayName,authenticationMethodsUsed,authenticationRequirement,conditionalAccessStatus,deviceDetail,location&`$top=1000"
        
        do {
            $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri
            $SignInLogs += $Response.value
            $Uri = $Response.'@odata.nextLink'
            
            Write-Output "Retrieved $($SignInLogs.Count) sign-in records..."
        } while ($Uri)
        
        Write-Output "Total sign-in records retrieved: $($SignInLogs.Count)"
        
        # Filter for MFA-required sign-ins
        $MFASignIns = $SignInLogs | Where-Object {
            $_.authenticationRequirement -eq "multiFactorAuthentication" -and
            $_.authenticationMethodsUsed -and
            $_.authenticationMethodsUsed.Count -gt 0
        }
        
        Write-Output "MFA sign-ins found: $($MFASignIns.Count)"
        
        # Group by user and analyze MFA methods
        $UserGroups = $MFASignIns | Group-Object userPrincipalName
        
        foreach ($UserGroup in $UserGroups) {
            $UserPrincipalName = $UserGroup.Name
            
            # Skip excluded users
            if ($ExcludedUsers -contains $UserPrincipalName) {
                Write-Verbose "Skipping excluded user: $UserPrincipalName"
                continue
            }
            
            try {
                $UserSignIns = $UserGroup.Group
                $DisplayName = $UserSignIns[0].userDisplayName
                
                # Get all MFA methods used by this user
                $AllMethods = @()
                $NonCompliantSignIns = @()
                
                foreach ($SignIn in $UserSignIns) {
                    foreach ($Method in $SignIn.authenticationMethodsUsed) {
                        $AllMethods += $Method
                        
                        # Check if method is non-compliant (not Microsoft Authenticator)
                        if ($Method -notin @("microsoftAuthenticatorPush", "microsoftAuthenticatorOTP")) {
                            $NonCompliantSignIns += [PSCustomObject]@{
                                CreatedDateTime = $SignIn.createdDateTime
                                AuthenticationMethod = $Method
                                DeviceDetail = ($SignIn.deviceDetail | ConvertTo-Json -Compress) ?? ""
                                Location = if ($SignIn.location) { 
                                    "$($SignIn.location.city), $($SignIn.location.countryOrRegion)" 
                                } else { 
                                    "Unknown" 
                                }
                            }
                        }
                    }
                }
                
                # Get unique methods
                $UniqueMethods = $AllMethods | Sort-Object -Unique
                $NonCompliantMethods = $UniqueMethods | Where-Object { 
                    $_ -notin @("microsoftAuthenticatorPush", "microsoftAuthenticatorOTP") 
                }
                
                if ($NonCompliantMethods.Count -gt 0) {
                    # User has non-compliant MFA usage
                    $UserRecord = [PSCustomObject]@{
                        UserPrincipalName = $UserPrincipalName
                        DisplayName = $DisplayName
                        TotalSignIns = $UserSignIns.Count
                        NonCompliantSignIns = $NonCompliantSignIns
                        AllMethods = $UniqueMethods
                        NonCompliantMethods = $NonCompliantMethods
                        LastNonCompliantSignIn = ($NonCompliantSignIns | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
                        ComplianceStatus = "Non-Compliant"
                    }
                    
                    [void]$Script:NonCompliantUsers.Add($UserRecord)
                    Write-Output "  ⚠ Non-compliant user found: $DisplayName ($UserPrincipalName) - Methods: $($NonCompliantMethods -join ', ')"
                } elseif ($IncludeCompliantUsers) {
                    # User is compliant - only used Microsoft Authenticator
                    $UserRecord = [PSCustomObject]@{
                        UserPrincipalName = $UserPrincipalName
                        DisplayName = $DisplayName
                        TotalSignIns = $UserSignIns.Count
                        AllMethods = $UniqueMethods
                        ComplianceStatus = "Compliant"
                    }
                    
                    [void]$Script:CompliantUsers.Add($UserRecord)
                    Write-Verbose "  ✓ Compliant user: $DisplayName ($UserPrincipalName)"
                }
            }
            catch {
                Write-Warning "Error processing user $UserPrincipalName`: $_"
                [void]$Script:ProcessingErrors.Add(@{
                    User = $UserPrincipalName
                    Error = $_.Exception.Message
                    Timestamp = Get-Date
                })
            }
        }
        
        Write-Output "Analysis complete:"
        Write-Output "  Non-compliant users: $($Script:NonCompliantUsers.Count)"
        Write-Output "  Compliant users: $($Script:CompliantUsers.Count)"
        Write-Output "  Processing errors: $($Script:ProcessingErrors.Count)"
    }
    catch {
        Write-Error "Failed to retrieve or process sign-in logs: $_"
        throw
    }
}

#endregion

#region Main Execution

Write-Output "========================================="
Write-Output "MFA Compliance Monitor"
Write-Output "========================================="
Write-Output "Analysis Period: Last $DaysToAnalyze days"
Write-Output "WhatIf Mode: $($WhatIf.IsPresent)"
Write-Output "User Notifications: $($SendUserNotifications.IsPresent)"
Write-Output "Admin Summary: $($SendAdminSummary.IsPresent)"
Write-Output "Export Path: $ExportPath"
if ($StorageAccountName) {
    Write-Output "Blob Storage: $StorageAccountName/$StorageContainerName"
}
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "========================================="

# Ensure export directory exists
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

try {
    # Connect to Microsoft Graph
    Write-Output "`nConnecting to Microsoft Graph..."
    
    $Context = Get-MgContext
    if ($null -eq $Context) {
        if ($UseManagedIdentity -or $StorageAccountName) {
            # Use Managed Identity for authentication (required for blob storage)
            Write-Output "Connecting with Azure Automation Managed Identity..."
            Connect-MgGraph -Identity -NoWelcome
            
            # Also connect to Azure for storage operations if needed
            if ($StorageAccountName) {
                Write-Output "Connecting to Azure for storage operations..."
                Connect-AzAccount -Identity
            }
        }
        else {
            # Fallback authentication (not recommended for production)
            Write-Warning "Using fallback authentication. For production, use managed identity."
            Connect-MgGraph -Scopes "AuditLog.Read.All","User.Read.All","Mail.Send","Directory.Read.All" -NoWelcome
        }
    }
    
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }
    Write-Output "Successfully connected to tenant: $($Context.TenantId)"
    
    # Validate permissions - FAIL FAST for security
    Write-Output "`n--- Validating Permissions ---"
    $PermissionsValid = Test-RequiredPermissions
    if (-not $PermissionsValid) {
        $RequiredPermissions = @("AuditLog.Read.All", "User.Read.All", "Mail.Send", "Directory.Read.All")
        $ErrorMessage = @"
CRITICAL ERROR: Missing required Microsoft Graph permissions.

Required permissions:
$(($RequiredPermissions | ForEach-Object { "  - $_" }) -join "`n")

To fix this:
1. Go to Azure Portal → App Registrations → [Your App]
2. Navigate to API Permissions  
3. Add the missing Microsoft Graph permissions (Application type)
4. Click 'Grant admin consent'
5. Re-run this script

Cannot proceed safely without proper permissions.
"@
        Write-Error $ErrorMessage
        throw "Missing required Microsoft Graph permissions. Cannot continue safely."
    }
    
    # Analyze sign-in logs for MFA compliance
    Write-Output "`n--- Analyzing MFA Usage ---"
    Get-NonCompliantMFAUsers -DaysBack $DaysToAnalyze
    
    # Send user notifications
    if ($SendUserNotifications -and $Script:NonCompliantUsers.Count -gt 0) {
        Write-Output "`n--- Sending User Notifications ---"
        
        foreach ($User in $Script:NonCompliantUsers) {
            Write-Output "Processing notification for: $($User.DisplayName)"
            
            try {
                Send-MFAComplianceNotification `
                    -RecipientEmail $User.UserPrincipalName `
                    -RecipientName $User.DisplayName `
                    -NonCompliantSignIns $User.NonCompliantSignIns `
                    -CCEmails $ITAdminEmails
            }
            catch {
                Write-Warning "Failed to send notification to $($User.UserPrincipalName): $_"
                [void]$Script:ProcessingErrors.Add(@{
                    User = $User.UserPrincipalName
                    Error = "Failed to send notification: $($_.Exception.Message)"
                    Timestamp = Get-Date
                })
            }
        }
    }
    
    # Generate CSV Reports
    Write-Output "`n--- Generating CSV Reports ---"
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export non-compliant users
    if ($Script:NonCompliantUsers.Count -gt 0) {
        $NonCompliantReport = $Script:NonCompliantUsers | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                ComplianceStatus = $_.ComplianceStatus
                TotalSignIns = $_.TotalSignIns
                NonCompliantSignInsCount = $_.NonCompliantSignIns.Count
                NonCompliantMethods = ($_.NonCompliantMethods -join "; ")
                AllMethods = ($_.AllMethods -join "; ")
                LastNonCompliantSignIn = $_.LastNonCompliantSignIn
                NotificationSent = ($Script:EmailsSent | Where-Object { $_.Recipient -eq $_.UserPrincipalName }) -ne $null
            }
        }
        
        $NonCompliantFile = Join-Path $ExportPath "NonCompliantMFAUsers_$Timestamp.csv"
        $NonCompliantReport | Export-Csv -Path $NonCompliantFile -NoTypeInformation -Encoding UTF8
        Write-Output "Non-compliant users report: $NonCompliantFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $NonCompliantFile -BlobName "NonCompliantMFAUsers_$Timestamp.csv"
        }
    }
    
    # Export compliant users (if requested)
    if ($IncludeCompliantUsers -and $Script:CompliantUsers.Count -gt 0) {
        $CompliantReport = $Script:CompliantUsers | ForEach-Object {
            [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                ComplianceStatus = $_.ComplianceStatus
                TotalSignIns = $_.TotalSignIns
                AllMethods = ($_.AllMethods -join "; ")
            }
        }
        
        $CompliantFile = Join-Path $ExportPath "CompliantMFAUsers_$Timestamp.csv"
        $CompliantReport | Export-Csv -Path $CompliantFile -NoTypeInformation -Encoding UTF8
        Write-Output "Compliant users report: $CompliantFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $CompliantFile -BlobName "CompliantMFAUsers_$Timestamp.csv"
        }
    }
    
    # Export detailed sign-in data
    if ($Script:NonCompliantUsers.Count -gt 0) {
        $DetailedSignIns = @()
        $Script:NonCompliantUsers | ForEach-Object {
            $User = $_
            $User.NonCompliantSignIns | ForEach-Object {
                $DetailedSignIns += [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    UserPrincipalName = $User.UserPrincipalName
                    DisplayName = $User.DisplayName
                    SignInDateTime = $_.CreatedDateTime
                    AuthenticationMethod = $_.AuthenticationMethod
                    AuthenticationMethodDisplay = Get-MFAMethodDisplayName -AuthMethod $_.AuthenticationMethod
                    DeviceDetail = Get-DeviceDisplayName -DeviceDetail $_.DeviceDetail
                    Location = $_.Location
                }
            }
        }
        
        $DetailedFile = Join-Path $ExportPath "NonCompliantSignInDetails_$Timestamp.csv"
        $DetailedSignIns | Export-Csv -Path $DetailedFile -NoTypeInformation -Encoding UTF8
        Write-Output "Detailed sign-in report: $DetailedFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $DetailedFile -BlobName "NonCompliantSignInDetails_$Timestamp.csv"
        }
    }
    
    # Export processing errors
    if ($Script:ProcessingErrors.Count -gt 0) {
        $ErrorFile = Join-Path $ExportPath "ProcessingErrors_$Timestamp.csv"
        $Script:ProcessingErrors | Export-Csv -Path $ErrorFile -NoTypeInformation -Encoding UTF8
        Write-Output "Processing errors report: $ErrorFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $ErrorFile -BlobName "ProcessingErrors_$Timestamp.csv"
        }
    }
    
    # Generate summary CSV
    $SummaryData = @(
        [PSCustomObject]@{
            RunDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Mode = if ($WhatIf) { "Simulation (WhatIf)" } else { "Production" }
            DaysAnalyzed = $DaysToAnalyze
            TotalUsersAnalyzed = $Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count
            NonCompliantUsers = $Script:NonCompliantUsers.Count
            CompliantUsers = $Script:CompliantUsers.Count
            ComplianceRate = if (($Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count) -gt 0) { 
                [math]::Round(($Script:CompliantUsers.Count / ($Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count)) * 100, 2) 
            } else { 100 }
            NotificationsSent = $Script:EmailsSent.Count
            ProcessingErrors = $Script:ProcessingErrors.Count
            UserNotificationsEnabled = $SendUserNotifications
            AdminSummaryEnabled = $SendAdminSummary
        }
    )
    
    $SummaryFile = Join-Path $ExportPath "MFAComplianceSummary_$Timestamp.csv"
    $SummaryData | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
    Write-Output "Summary report: $SummaryFile"
    
    # Upload summary to blob storage if configured
    if ($StorageAccountName) {
        Export-ToBlob -FilePath $SummaryFile -BlobName "MFAComplianceSummary_$Timestamp.csv"
    }
    
    # Send admin summary report
    if ($SendAdminSummary -and $ITAdminEmails.Count -gt 0) {
        Write-Output "`n--- Sending Admin Summary ---"
        Send-AdminSummaryReport `
            -AdminEmails $ITAdminEmails `
            -NonCompliantUsers $Script:NonCompliantUsers `
            -CompliantUsers $Script:CompliantUsers `
            -ProcessingErrors $Script:ProcessingErrors
    }
    
    # Display final summary
    Write-Output "`n========================================="
    Write-Output "MFA Compliance Analysis Summary"
    Write-Output "========================================="
    Write-Output "Analysis Period: Last $DaysToAnalyze days"
    Write-Output "Total Users Analyzed: $($Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count)"
    Write-Output "Non-Compliant Users: $($Script:NonCompliantUsers.Count)"
    Write-Output "Compliant Users: $($Script:CompliantUsers.Count)"
    $ComplianceRate = if (($Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count) -gt 0) { 
        [math]::Round(($Script:CompliantUsers.Count / ($Script:NonCompliantUsers.Count + $Script:CompliantUsers.Count)) * 100, 2) 
    } else { 100 }
    Write-Output "Compliance Rate: $ComplianceRate%"
    Write-Output "Notifications Sent: $($Script:EmailsSent.Count)"
    Write-Output "Processing Errors: $($Script:ProcessingErrors.Count)"
    Write-Output "Mode: $(if ($WhatIf) { 'Simulation (WhatIf)' } else { 'Production' })"
    Write-Output "Reports saved to: $ExportPath"
    if ($StorageAccountName) {
        Write-Output "Reports uploaded to blob storage: $StorageAccountName/$StorageContainerName"
    }
    Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "========================================="
    
    if ($Script:NonCompliantUsers.Count -gt 0) {
        Write-Output "`n⚠️  ACTION REQUIRED: $($Script:NonCompliantUsers.Count) users require MFA compliance follow-up"
        Write-Output "📧 User notifications sent: $($Script:EmailsSent.Count)"
        Write-Output "📊 Review detailed reports in: $ExportPath"
    } else {
        Write-Output "`n✅ Excellent! All analyzed users are MFA compliant"
    }
}
catch {
    Write-Error "Critical error in MFA compliance monitoring: $_"
    
    # Save error to file
    $ErrorFile = Join-Path $ExportPath "CriticalError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $ErrorDetails = @"
MFA Compliance Monitor - Critical Error Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Error Details:
$($_.Exception.Message)

Stack Trace:
$($_.Exception.StackTrace)

Script Parameters:
- DaysToAnalyze: $DaysToAnalyze
- WhatIf: $($WhatIf.IsPresent)
- SendUserNotifications: $($SendUserNotifications.IsPresent)
- SendAdminSummary: $($SendAdminSummary.IsPresent)
- ExportPath: $ExportPath
"@
    
    $ErrorDetails | Out-File -FilePath $ErrorFile -Encoding UTF8
    Write-Output "Error details saved to: $ErrorFile"
    
    # Upload error to blob storage if configured
    if ($StorageAccountName) {
        Export-ToBlob -FilePath $ErrorFile -BlobName "CriticalError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    }
    
    # Send error notification to admins if possible
    if ($ITAdminEmails.Count -gt 0) {
        try {
            $ErrorEmailBody = @"
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: red;">🚨 MFA Compliance Monitor - Critical Error</h2>
    <p>The MFA Compliance Monitor automation encountered a critical error:</p>
    <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px;">$($_.Exception.Message)</pre>
    <p><strong>Time:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p><strong>Please review the Azure Automation logs for more details.</strong></p>
</body>
</html>
"@
            
            foreach ($AdminEmail in $ITAdminEmails) {
                $ErrorEmailMessage = @{
                    Message = @{
                        Subject = "🚨 ALERT: MFA Compliance Monitor Failed"
                        Body = @{
                            ContentType = "HTML"
                            Content = $ErrorEmailBody
                        }
                        ToRecipients = @(@{EmailAddress = @{Address = $AdminEmail}})
                        Importance = "High"
                    }
                    SaveToSentItems = $true
                }
                
                $EmailJson = $ErrorEmailMessage | ConvertTo-Json -Depth 10 -Compress
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Warning "Failed to send error notification to administrators"
        }
    }
    
    throw
}
finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Output "`nDisconnecting from Microsoft Graph..."
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}

#endregion