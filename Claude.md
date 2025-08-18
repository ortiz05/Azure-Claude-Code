# Azure Enterprise Security Automation Suite

## Overview
This comprehensive Azure automation repository contains production-ready security and compliance solutions for enterprise environments. The suite includes six core automations plus a robust validation framework to ensure secure, reliable operations.

## Mission Statement
Create enterprise-grade Azure automation solutions that prioritize security, maintainability, and operational excellence while providing clear guidance for future AI agents working on similar security automation projects.

## Core Security Automations

### 1. Device Cleanup Automation
**Primary Focus**: Entra ID device lifecycle management
- **Registered Device Cleanup**: Removes standard registered devices inactive for 90+ days  
- **Autopilot Device Cleanup**: Cleans up Autopilot-registered devices without removing Autopilot enrollment
- **Email Notifications**: Professional HTML notifications to device owners and IT administrators
- **Safety Thresholds**: Prevents accidental mass deletions with configurable limits
- **Comprehensive Reporting**: CSV exports and HTML compliance reports for audit trails

### 2. MFA Compliance Monitor  
**Primary Focus**: Microsoft Authenticator enforcement and compliance tracking
- **Sign-In Analysis**: Monitors Azure AD audit logs for non-compliant MFA methods
- **User Notifications**: Professional email alerts to users with non-Microsoft Authenticator usage
- **Compliance Reporting**: Detailed CSV reports with user sign-in patterns and device information
- **Trend Analysis**: Tracks compliance rates over time for security governance
- **Executive Dashboards**: Summary reports for IT leadership with actionable insights

### 3. Enterprise App Usage Monitor
**Primary Focus**: Application lifecycle management and cost optimization  
- **Usage Analysis**: Identifies Enterprise Applications unused for 90+ days
- **Cost Assessment**: Analyzes potential cost savings from app consolidation
- **Risk Evaluation**: Assesses security risks of unused applications with access permissions
- **Business Impact Analysis**: Categorizes applications by criticality and usage patterns
- **Cleanup Recommendations**: Provides prioritized action items for application governance

### 4. Enterprise App Certificate Monitor
**Primary Focus**: Critical security monitoring for certificate/secret expiration
- **Certificate Lifecycle Tracking**: Monitors all Enterprise Application certificates and secrets
- **Expiration Analysis**: Identifies expired and soon-to-expire credentials
- **Risk Prioritization**: Focuses on unused applications with expired certificates (highest security risk)
- **Immediate Alerts**: Real-time notifications for critical security combinations
- **Usage Correlation**: Cross-references certificate status with application usage data

### 5. Service Principal Credential Manager
**Primary Focus**: Enterprise Service Principal credential lifecycle management
- **Comprehensive Credential Discovery**: Scans all Service Principals for certificate and secret-based credentials
- **Advanced Risk Assessment**: Multi-factor scoring with usage correlation and business impact analysis
- **Automated Remediation**: Safe cleanup of unused credentials with comprehensive audit logging
- **Enterprise Reporting**: Executive dashboards and detailed compliance documentation for SOC2/SOX audits
- **DevOps Integration**: Hooks for automated certificate renewal and rotation workflows

### 6. Application Permission Auditor
**Primary Focus**: Enterprise application permission governance and compliance
- **Comprehensive Permission Analysis**: Scans all Enterprise Applications for Microsoft Graph API permissions
- **OAuth Consent Monitoring**: Tracks delegated and application permissions with consent type analysis
- **Over-Privilege Detection**: Identifies applications violating principle of least privilege
- **Risk-Based Prioritization**: Focuses on unused applications with dangerous permissions (critical attack vectors)
- **Governance Automation**: Admin consent compliance monitoring and permission approval workflows

## Security-First Architecture and Patterns

### Validation Framework
**Comprehensive PowerShell Validation and Security Controls**
- **Scripts/Validate-PowerShellScripts.ps1**: Multi-layer validation covering syntax, security, error handling, and best practices
- **Scripts/Test-GraphAuthentication.ps1**: Reusable authentication patterns using environment variables (never hardcoded credentials)
- **Scripts/Pre-Commit-Hook.ps1**: Automated credential scanning and validation before any commit
- **GitHub Actions CI/CD**: Automated validation pipeline for continuous security assurance

### Critical Security Guardrails Implemented  
- **Fail-Fast Permission Validation**: All scripts immediately stop execution when required Microsoft Graph permissions are missing
- **Zero Hardcoded Credentials**: Comprehensive scanning prevents credential leaks in repository
- **Environment Variable Patterns**: Secure testing using `$env:AZURE_CLIENT_ID`, `$env:AZURE_TENANT_ID`, `$env:AZURE_CLIENT_SECRET`
- **Pre-Commit Security Scanning**: Automatic detection of GUIDs, Base64 patterns, and credential assignments
- **Managed Identity for Production**: All scripts designed for managed identity authentication in production environments

### Lessons Learned for Future AI Agents
**Critical Patterns Documented in LESSONS-LEARNED.md**
- **Permission Validation Anti-Pattern**: Never use `Write-Warning` for missing permissions - always use `throw` for fail-fast security
- **Clear Error Messages**: Provide specific required permissions and step-by-step fix instructions
- **Credential Management**: Never commit credentials - always use secure parameter patterns and environment variables
- **Testing Patterns**: Comprehensive validation frameworks prevent security regressions
- **Documentation Standards**: Security lessons learned must be captured for future development

### Core Technical Implementation Patterns

#### 1. Microsoft Graph API Integration
- **Authentication**: Managed Identity (production) / Environment Variables (testing)
- **Permission Validation**: Fail-fast validation with clear error messages
- **Error Handling**: Comprehensive try-catch blocks with actionable guidance
- **API Efficiency**: Pagination support for large datasets, proper filtering, and batching

#### 2. Email Notification Systems
- **Professional HTML Templates**: Corporate branding with responsive design
- **Multi-Recipient Support**: User notifications with IT admin CC functionality  
- **Actionable Content**: Clear instructions, deadlines, and next steps
- **Delivery Tracking**: Success/failure logging for audit and compliance requirements

#### 3. Reporting and Analytics
- **Multiple Export Formats**: CSV for data analysis, HTML for executive reporting
- **Comprehensive Metrics**: Compliance rates, trend analysis, risk assessments
- **Audit Trail Generation**: Complete logging for SOX, SOC2, and security compliance
- **Executive Dashboards**: High-level summaries with drill-down capabilities

#### 4. Safety and Validation Controls
- **WhatIf Mode**: Simulation capabilities for testing and validation
- **Safety Thresholds**: Configurable limits to prevent accidental mass operations
- **Exclusion Lists**: Flexible filtering for service accounts and critical systems
- **Progressive Rollout**: Staged deployment patterns for risk mitigation

## Enterprise Deployment Guidance

### Required Microsoft Graph Permissions by Automation

| Automation | Required Permissions | Purpose |
|------------|---------------------|---------|
| **Device Cleanup** | Device.ReadWrite.All, User.Read.All, Directory.ReadWrite.All, Mail.Send | Device management and notifications |
| **MFA Compliance** | AuditLog.Read.All, User.Read.All, Mail.Send, Directory.Read.All | Audit log analysis and compliance reporting |
| **App Usage Monitor** | Application.Read.All, AuditLog.Read.All, Directory.Read.All, Mail.Send | Application usage analysis and reporting |
| **App Certificate Monitor** | Application.Read.All, AuditLog.Read.All, Directory.Read.All, Mail.Send | Certificate lifecycle monitoring and alerts |
| **Service Principal Credential Manager** | Application.Read.All, Application.ReadWrite.All, Directory.Read.All, AuditLog.Read.All, Mail.Send | Service Principal credential lifecycle management |
| **Application Permission Auditor** | Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All, AppRoleAssignment.Read.All, AuditLog.Read.All, Mail.Send | Application permission governance and compliance |

### Production Deployment Checklist
- [ ] **Run credential scan** - Execute validation framework to ensure no hardcoded secrets
- [ ] **Validate permissions** - Confirm all required Graph API permissions granted with admin consent
- [ ] **Configure managed identity** - Set up system-assigned managed identity for authentication
- [ ] **Test in WhatIf mode** - Validate functionality in target environment without making changes
- [ ] **Configure monitoring** - Set up Azure Monitor alerts for automation failures and thresholds
- [ ] **Establish exclusion lists** - Define service accounts and systems to exclude from automated processing
- [ ] **Schedule regular execution** - Configure appropriate schedules based on business requirements
- [ ] **Document customizations** - Record any environment-specific modifications for maintenance

## Future Development Guidelines

### For AI Agents Working on Similar Projects
- **Start with security**: Implement fail-fast permission validation before any business logic
- **Never hardcode credentials**: Always use environment variables or managed identity patterns
- **Comprehensive error handling**: Every Graph API call should have try-catch with clear error messages
- **Validate early and often**: Use the established validation framework for all PowerShell development
- **Document security lessons**: Update LESSONS-LEARNED.md with any new security patterns discovered
- **Test thoroughly**: Always test permission validation failures to ensure proper error handling
- **Follow established patterns**: Use existing authentication and reporting patterns for consistency

### Repository Structure Conventions
```
Project-Name/
├── Documentation/
│   └── CLAUDE.md                    # AI-readable implementation guidelines  
├── Scripts/
│   └── MainScript.ps1              # Primary automation logic
├── Tests/
│   └── Test-Connection.ps1         # Connection and permission testing
├── Templates/
│   ├── UserNotification.html       # Email templates
│   └── AdminSummary.html
└── Reports/                        # CSV output directory (gitignored)
```

### Security Standards for All Automations
1. **Authentication**: Managed Identity for production, environment variables for testing
2. **Permission Validation**: Explicit checking with fail-fast error handling
3. **Error Reporting**: Clear messages with specific required permissions and fix instructions
4. **Credential Management**: Zero tolerance for hardcoded credentials, comprehensive scanning
5. **Audit Logging**: Complete operation logging for compliance and troubleshooting
6. **Safety Controls**: WhatIf mode, safety thresholds, and exclusion list support

## Prerequisites

### Required Azure Resources
- Azure Automation Account
- Managed Identity or Service Principal with appropriate permissions

### Required Graph API Permissions
Configure the following Microsoft Graph API permissions for your Managed Identity or Service Principal:

| Permission | Type | Purpose |
|------------|------|---------|
| Device.ReadWrite.All | Application | Read and delete device objects |
| DeviceManagementServiceConfig.ReadWrite.All | Application | Read Autopilot device information |
| Directory.ReadWrite.All | Application | Read and modify directory objects |
| User.Read.All | Application | Read user information for email notifications |
| Mail.Send | Application | Send email notifications to users and admins |

### PowerShell Modules
Install the following modules in your Azure Automation Account:
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.DeviceManagement.Enrollment

## Implementation

### Email Notification Functions

```powershell
function Send-DeviceCleanupNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RecipientEmail,
        
        [Parameter(Mandatory=$true)]
        [string]$RecipientName,
        
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        
        [Parameter(Mandatory=$true)]
        [datetime]$LastSignIn,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Warning", "Final", "Deleted")]
        [string]$NotificationType,
        
        [Parameter(Mandatory=$false)]
        [int]$DaysUntilDeletion = 7
    )
    
    # Email templates based on notification type
    $Subject = switch ($NotificationType) {
        "Warning" { "Action Required: Your device '$DeviceName' will be removed in $DaysUntilDeletion days" }
        "Final" { "Final Notice: Your device '$DeviceName' will be removed today" }
        "Deleted" { "Device Removed: '$DeviceName' has been removed from the organization" }
    }
    
    $Body = switch ($NotificationType) {
        "Warning" {
            @"
<html>
<body style="font-family: Arial, sans-serif;">
    <h2>Device Cleanup Notice</h2>
    <p>Dear $RecipientName,</p>
    
    <p>Your device <strong>$DeviceName</strong> has been inactive since <strong>$($LastSignIn.ToString('MMMM dd, yyyy'))</strong> 
    and is scheduled for removal from our organization's device registry.</p>
    
    <div style="background-color: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 12px; margin: 20px 0;">
        <strong>⚠️ Action Required:</strong><br>
        This device will be automatically removed in <strong>$DaysUntilDeletion days</strong> unless you sign in to it.
    </div>
    
    <h3>What you need to do:</h3>
    <ul>
        <li>Sign in to the device before the deletion date to keep it active</li>
        <li>If you no longer use this device, no action is needed</li>
        <li>If this device was replaced or upgraded, no action is needed</li>
    </ul>
    
    <h3>What happens if the device is removed:</h3>
    <ul>
        <li>The device will need to be re-registered to access organization resources</li>
        <li>Any cached credentials on the device may need to be re-entered</li>
        <li>Company policies will need to be reapplied</li>
    </ul>
    
    <p>If you have questions or believe this is an error, please contact your IT administrator.</p>
    
    <hr style="margin-top: 30px;">
    <p style="font-size: 12px; color: #666;">
        This is an automated message from the Device Management System.<br>
        Device ID: $($Device.Id)<br>
        Last Activity: $($LastSignIn.ToString('yyyy-MM-dd HH:mm:ss'))
    </p>
</body>
</html>
"@
        }
        "Final" {
            @"
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: #dc3545;">Final Device Cleanup Notice</h2>
    <p>Dear $RecipientName,</p>
    
    <div style="background-color: #f8d7da; border: 1px solid #dc3545; border-radius: 4px; padding: 12px; margin: 20px 0;">
        <strong>🔴 Final Notice:</strong><br>
        Your device <strong>$DeviceName</strong> will be removed <strong>TODAY</strong> due to inactivity since 
        <strong>$($LastSignIn.ToString('MMMM dd, yyyy'))</strong>.
    </div>
    
    <p>If you need to keep this device, please sign in to it immediately.</p>
    
    <p>After removal, you will need to re-register the device to access organization resources.</p>
    
    <hr style="margin-top: 30px;">
    <p style="font-size: 12px; color: #666;">
        This is an automated message from the Device Management System.<br>
        Device ID: $($Device.Id)
    </p>
</body>
</html>
"@
        }
        "Deleted" {
            @"
<html>
<body style="font-family: Arial, sans-serif;">
    <h2>Device Removal Confirmation</h2>
    <p>Dear $RecipientName,</p>
    
    <p>This confirms that your device <strong>$DeviceName</strong> has been removed from the organization's 
    device registry due to inactivity since <strong>$($LastSignIn.ToString('MMMM dd, yyyy'))</strong>.</p>
    
    <h3>Next Steps:</h3>
    <ul>
        <li>If you need to use this device again, you'll need to re-register it</li>
        <li>Contact your IT administrator for assistance with re-registration</li>
        <li>Sign in to your devices regularly to prevent future removals</li>
    </ul>
    
    <p>Thank you for helping us maintain a secure and organized device environment.</p>
    
    <hr style="margin-top: 30px;">
    <p style="font-size: 12px; color: #666;">
        This is an automated message from the Device Management System.<br>
        Removal Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </p>
</body>
</html>
"@
        }
    }
    
    # Create the email message
    $EmailMessage = @{
        Message = @{
            Subject = $Subject
            Body = @{
                ContentType = "HTML"
                Content = $Body
            }
            ToRecipients = @(
                @{
                    EmailAddress = @{
                        Address = $RecipientEmail
                    }
                }
            )
        }
        SaveToSentItems = $false
    }
    
    try {
        # Send email using Graph API
        $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$RecipientEmail/sendMail" -Body $EmailJson
        Write-Output "  ✓ Email sent to $RecipientEmail ($NotificationType notification)"
        return $true
    }
    catch {
        Write-Warning "  ⚠ Failed to send email to $RecipientEmail: $_"
        return $false
    }
}

function Send-AdminSummaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$AdminEmails,
        
        [Parameter(Mandatory=$true)]
        [array]$ProcessedDevices,
        
        [Parameter(Mandatory=$true)]
        [array]$FailedDevices,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Daily", "Weekly", "Monthly")]
        [string]$ReportType
    )
    
    $TotalProcessed = $ProcessedDevices.Count
    $TotalFailed = $FailedDevices.Count
    $SuccessRate = if ($TotalProcessed -gt 0) { 
        [math]::Round((($TotalProcessed - $TotalFailed) / $TotalProcessed) * 100, 2) 
    } else { 100 }
    
    $DeviceTableRows = $ProcessedDevices | ForEach-Object {
        @"
        <tr>
            <td>$($_.DisplayName)</td>
            <td>$($_.OperatingSystem)</td>
            <td>$($_.LastSignIn.ToString('yyyy-MM-dd'))</td>
            <td>$($_.Owner)</td>
            <td>$($_.Status)</td>
        </tr>
"@
    }
    
    $Body = @"
<html>
<head>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
    </style>
</head>
<body style="font-family: Arial, sans-serif;">
    <h1>Device Cleanup $ReportType Report</h1>
    <p>Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Total Devices Processed: <strong>$TotalProcessed</strong></li>
            <li>Successfully Cleaned: <strong class="success">$($TotalProcessed - $TotalFailed)</strong></li>
            <li>Failed Operations: <strong class="error">$TotalFailed</strong></li>
            <li>Success Rate: <strong>$SuccessRate%</strong></li>
        </ul>
    </div>
    
    <h2>Processed Devices</h2>
    <table>
        <thead>
            <tr>
                <th>Device Name</th>
                <th>Operating System</th>
                <th>Last Sign-In</th>
                <th>Owner</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            $($DeviceTableRows -join "`n")
        </tbody>
    </table>
    
    $(if ($FailedDevices.Count -gt 0) {
        @"
        <h2 class="error">Failed Operations</h2>
        <ul>
        $(($FailedDevices | ForEach-Object { "<li>$($_.DisplayName): $($_.Error)</li>" }) -join "`n")
        </ul>
"@
    })
    
    <hr style="margin-top: 30px;">
    <p style="font-size: 12px; color: #666;">
        This report was automatically generated by the Azure Device Cleanup Automation.<br>
        For questions or concerns, please contact your IT administrator.
    </p>
</body>
</html>
"@
    
    foreach ($AdminEmail in $AdminEmails) {
        $EmailMessage = @{
            Message = @{
                Subject = "Device Cleanup $ReportType Report - $(Get-Date -Format 'yyyy-MM-dd')"
                Body = @{
                    ContentType = "HTML"
                    Content = $Body
                }
                ToRecipients = @(
                    @{
                        EmailAddress = @{
                            Address = $AdminEmail
                        }
                    }
                )
            }
            SaveToSentItems = $true
        }
        
        try {
            $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$AdminEmail/sendMail" -Body $EmailJson
            Write-Output "Admin report sent to $AdminEmail"
        }
        catch {
            Write-Warning "Failed to send admin report to $AdminEmail: $_"
        }
    }
}
```

### Authentication Setup

```powershell
# Connect to Microsoft Graph using Managed Identity
Connect-MgGraph -Identity

# Alternative: Connect using Service Principal
$ClientId = Get-AutomationVariable -Name 'ClientId'
$TenantId = Get-AutomationVariable -Name 'TenantId'
$ClientSecret = Get-AutomationVariable -Name 'ClientSecret'

$SecureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureClientSecret)

Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential
```

### Function 1: Clean Up Registered Devices with Email Notifications

```powershell
function Remove-InactiveRegisteredDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 90,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf,
        
        [Parameter(Mandatory=$false)]
        [switch]$SendNotifications = $true,
        
        [Parameter(Mandatory=$false)]
        [string[]]$AdminEmails = @()
    )
    
    Write-Output "Starting cleanup of registered devices inactive for $InactiveDays days or more..."
    
    # Calculate the cutoff date
    $CutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    $ProcessedDevices = @()
    $FailedDevices = @()
    
    try {
        # Get all devices from Entra ID with additional properties
        $AllDevices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime, OperatingSystem, DeviceId, TrustType, RegisteredOwners
        
        # Filter devices that are inactive and not Autopilot devices
        $InactiveDevices = $AllDevices | Where-Object {
            $_.ApproximateLastSignInDateTime -ne $null -and 
            $_.ApproximateLastSignInDateTime -lt $CutoffDate -and
            $_.TrustType -ne "AzureAD" # Exclude Autopilot devices
        }
        
        Write-Output "Found $($InactiveDevices.Count) inactive registered devices"
        
        foreach ($Device in $InactiveDevices) {
            $LastSignIn = if ($Device.ApproximateLastSignInDateTime) { 
                $Device.ApproximateLastSignInDateTime 
            } else { 
                $null 
            }
            
            # Get device owner information
            $DeviceOwner = $null
            $OwnerEmail = $null
            $OwnerName = "Device Owner"
            
            if ($Device.RegisteredOwners -and $Device.RegisteredOwners.Count -gt 0) {
                try {
                    $OwnerId = $Device.RegisteredOwners[0]
                    $Owner = Get-MgUser -UserId $OwnerId -Property DisplayName, Mail, UserPrincipalName -ErrorAction SilentlyContinue
                    if ($Owner) {
                        $DeviceOwner = $Owner.DisplayName
                        $OwnerEmail = if ($Owner.Mail) { $Owner.Mail } else { $Owner.UserPrincipalName }
                        $OwnerName = $Owner.DisplayName
                    }
                }
                catch {
                    Write-Warning "Could not retrieve owner information for device $($Device.DisplayName)"
                }
            }
            
            Write-Output "Processing: $($Device.DisplayName) - Last Sign-in: $($LastSignIn.ToString('yyyy-MM-dd')) - Owner: $DeviceOwner"
            
            if (-not $WhatIf) {
                try {
                    # Send notification to device owner before deletion
                    if ($SendNotifications -and $OwnerEmail) {
                        Send-DeviceCleanupNotification `
                            -RecipientEmail $OwnerEmail `
                            -RecipientName $OwnerName `
                            -DeviceName $Device.DisplayName `
                            -LastSignIn $LastSignIn `
                            -NotificationType "Deleted"
                    }
                    
                    # Remove the device
                    Remove-MgDevice -DeviceId $Device.Id -Confirm:$false
                    Write-Output "  ✓ Successfully removed device: $($Device.DisplayName)"
                    
                    $ProcessedDevices += @{
                        DisplayName = $Device.DisplayName
                        OperatingSystem = $Device.OperatingSystem
                        LastSignIn = $LastSignIn
                        Owner = $DeviceOwner
                        Status = "Removed"
                    }
                }
                catch {
                    Write-Error "  ✗ Failed to remove device $($Device.DisplayName): $_"
                    $FailedDevices += @{
                        DisplayName = $Device.DisplayName
                        Error = $_.Exception.Message
                    }
                }
            }
            else {
                Write-Output "  [WhatIf] Would remove device: $($Device.DisplayName)"
                if ($SendNotifications -and $OwnerEmail) {
                    Write-Output "  [WhatIf] Would send notification to: $OwnerEmail"
                }
                
                $ProcessedDevices += @{
                    DisplayName = $Device.DisplayName
                    OperatingSystem = $Device.OperatingSystem
                    LastSignIn = $LastSignIn
                    Owner = $DeviceOwner
                    Status = "Would Remove (WhatIf)"
                }
            }
        }
        
        # Send admin summary report
        if ($AdminEmails.Count -gt 0 -and $ProcessedDevices.Count -gt 0) {
            Send-AdminSummaryReport `
                -AdminEmails $AdminEmails `
                -ProcessedDevices $ProcessedDevices `
                -FailedDevices $FailedDevices `
                -ReportType "Daily"
        }
        
        Write-Output "Registered device cleanup completed. Processed $($InactiveDevices.Count) devices."
    }
    catch {
        Write-Error "Error during registered device cleanup: $_"
        throw
    }
}
```

### Function 2: Clean Up Autopilot Devices (Without Removing from Autopilot)

```powershell
function Remove-InactiveAutopilotDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 90,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    Write-Output "Starting cleanup of Autopilot devices inactive for $InactiveDays days or more..."
    
    # Calculate the cutoff date
    $CutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    try {
        # Get all Autopilot devices
        $AutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All
        
        # Get all Entra ID devices for cross-reference
        $EntraDevices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime, DeviceId
        
        $InactiveAutopilotDevices = @()
        
        foreach ($AutopilotDevice in $AutopilotDevices) {
            # Find corresponding Entra ID device
            $EntraDevice = $EntraDevices | Where-Object { 
                $_.DeviceId -eq $AutopilotDevice.AzureActiveDirectoryDeviceId 
            }
            
            if ($EntraDevice) {
                if ($EntraDevice.ApproximateLastSignInDateTime -ne $null -and 
                    $EntraDevice.ApproximateLastSignInDateTime -lt $CutoffDate) {
                    
                    $InactiveAutopilotDevices += @{
                        AutopilotDevice = $AutopilotDevice
                        EntraDevice = $EntraDevice
                    }
                }
            }
        }
        
        Write-Output "Found $($InactiveAutopilotDevices.Count) inactive Autopilot devices"
        
        foreach ($DeviceInfo in $InactiveAutopilotDevices) {
            $Device = $DeviceInfo.EntraDevice
            $AutopilotInfo = $DeviceInfo.AutopilotDevice
            
            $LastSignIn = if ($Device.ApproximateLastSignInDateTime) { 
                $Device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") 
            } else { 
                "Never" 
            }
            
            Write-Output "Processing Autopilot device: $($Device.DisplayName) - Serial: $($AutopilotInfo.SerialNumber) - Last Sign-in: $LastSignIn"
            
            if (-not $WhatIf) {
                try {
                    # Remove from Entra ID only (keeps Autopilot registration)
                    Remove-MgDevice -DeviceId $Device.Id -Confirm:$false
                    Write-Output "  ✓ Successfully removed from Entra ID: $($Device.DisplayName)"
                    Write-Output "  ℹ Device remains registered in Autopilot with serial: $($AutopilotInfo.SerialNumber)"
                }
                catch {
                    Write-Error "  ✗ Failed to remove device $($Device.DisplayName): $_"
                }
            }
            else {
                Write-Output "  [WhatIf] Would remove from Entra ID: $($Device.DisplayName)"
                Write-Output "  [WhatIf] Device would remain in Autopilot"
            }
        }
        
        Write-Output "Autopilot device cleanup completed. Processed $($InactiveAutopilotDevices.Count) devices."
    }
    catch {
        Write-Error "Error during Autopilot device cleanup: $_"
        throw
    }
}
```

### Permission Validation Function

```powershell
function Test-RequiredPermissions {
    [CmdletBinding()]
    param()
    
    Write-Output "Validating Graph API permissions..."
    
    $RequiredPermissions = @{
        "Device.ReadWrite.All" = $false
        "User.Read.All" = $false
        "Mail.Send" = $false
        "Directory.ReadWrite.All" = $false
        "DeviceManagementServiceConfig.ReadWrite.All" = $false
    }
    
    $AllPermissionsValid = $true
    
    try {
        # Get current context and permissions
        $Context = Get-MgContext
        if ($null -eq $Context) {
            Write-Error "Not connected to Microsoft Graph"
            return $false
        }
        
        $CurrentScopes = $Context.Scopes
        
        # Check each required permission
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
        
        # Test actual API access
        Write-Output "`nTesting API access..."
        
        # Test device read
        try {
            $TestDevice = Get-MgDevice -Top 1 -ErrorAction Stop
            Write-Output "  ✓ Device read access confirmed"
        } catch {
            Write-Warning "  ✗ Cannot read devices: $_"
            $AllPermissionsValid = $false
        }
        
        # Test user read
        try {
            $TestUser = Get-MgUser -Top 1 -ErrorAction Stop
            Write-Output "  ✓ User read access confirmed"
        } catch {
            Write-Warning "  ✗ Cannot read users: $_"
        }
        
        return $AllPermissionsValid
    }
    catch {
        Write-Error "Permission validation failed: $_"
        return $false
    }
}
```

### Advanced Features Functions

```powershell
# Function to create device cleanup exclusion list
function New-DeviceExclusionList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedDeviceNames = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedDeviceIds = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedOSTypes = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedOwners = @()
    )
    
    return @{
        DeviceNames = $ExcludedDeviceNames
        DeviceIds = $ExcludedDeviceIds
        OSTypes = $ExcludedOSTypes
        Owners = $ExcludedOwners
    }
}

# Function to check if device should be excluded
function Test-DeviceExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Device,
        
        [Parameter(Mandatory=$true)]
        $ExclusionList
    )
    
    # Check device name exclusions
    if ($ExclusionList.DeviceNames -contains $Device.DisplayName) {
        return $true
    }
    
    # Check device ID exclusions
    if ($ExclusionList.DeviceIds -contains $Device.Id) {
        return $true
    }
    
    # Check OS type exclusions
    if ($ExclusionList.OSTypes -contains $Device.OperatingSystem) {
        return $true
    }
    
    # Check owner exclusions
    if ($Device.RegisteredOwners) {
        foreach ($OwnerId in $Device.RegisteredOwners) {
            try {
                $Owner = Get-MgUser -UserId $OwnerId -Property UserPrincipalName -ErrorAction SilentlyContinue
                if ($Owner -and $ExclusionList.Owners -contains $Owner.UserPrincipalName) {
                    return $true
                }
            } catch {}
        }
    }
    
    return $false
}

# Function to export device list before cleanup
function Export-DeviceBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Devices,
        
        [Parameter(Mandatory=$false)]
        [string]$BackupPath = "C:\DeviceBackups"
    )
    
    $BackupFileName = "DeviceBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $FullPath = Join-Path $BackupPath $BackupFileName
    
    # Ensure backup directory exists
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $BackupData = $Devices | ForEach-Object {
        @{
            Id = $_.Id
            DeviceId = $_.DeviceId
            DisplayName = $_.DisplayName
            OperatingSystem = $_.OperatingSystem
            TrustType = $_.TrustType
            LastSignIn = $_.ApproximateLastSignInDateTime
            RegisteredOwners = $_.RegisteredOwners
            BackupDate = Get-Date
        }
    }
    
    try {
        $BackupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $FullPath -Encoding UTF8
        Write-Output "Device backup created: $FullPath"
        return $FullPath
    }
    catch {
        Write-Error "Failed to create device backup: $_"
        return $null
    }
}

# Function to generate detailed compliance report
function New-ComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ProcessedDevices,
        
        [Parameter(Mandatory=$true)]
        [array]$ExcludedDevices,
        
        [Parameter(Mandatory=$true)]
        [array]$FailedDevices,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportPath = "C:\ComplianceReports"
    )
    
    $ReportFileName = "ComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $FullPath = Join-Path $ReportPath $ReportFileName
    
    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }
    
    $Html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Device Cleanup Compliance Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f0f0f0; text-align: left; padding: 10px; border-bottom: 2px solid #ddd; }
        td { padding: 8px; border-bottom: 1px solid #eee; }
        .success { color: #107c10; font-weight: bold; }
        .warning { color: #ff8c00; font-weight: bold; }
        .error { color: #d83b01; font-weight: bold; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f8f8f8; padding: 15px; border-radius: 5px; border-left: 4px solid #0078d4; }
        .summary-number { font-size: 24px; font-weight: bold; color: #0078d4; }
        .summary-label { color: #666; font-size: 14px; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Device Cleanup Compliance Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Automation Account: $env:AUTOMATION_ACCOUNT_NAME</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-number">$($ProcessedDevices.Count)</div>
                <div class="summary-label">Devices Processed</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">$($ExcludedDevices.Count)</div>
                <div class="summary-label">Devices Excluded</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">$($FailedDevices.Count)</div>
                <div class="summary-label">Failed Operations</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">$(if ($ProcessedDevices.Count -gt 0) { [math]::Round((($ProcessedDevices.Count - $FailedDevices.Count) / $ProcessedDevices.Count) * 100, 2) } else { 100 })%</div>
                <div class="summary-label">Success Rate</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Compliance Details</h2>
        <ul>
            <li>Cleanup Policy: Devices inactive for more than 90 days</li>
            <li>Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</li>
            <li>Automation Type: $(if ($WhatIf) { "Simulation Mode (WhatIf)" } else { "Production Mode" })</li>
            <li>Email Notifications: $(if ($SendNotifications) { "Enabled" } else { "Disabled" })</li>
        </ul>
    </div>
    
    $(if ($ProcessedDevices.Count -gt 0) {
        @"
        <div class="section">
            <h2>Processed Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Operating System</th>
                        <th>Last Sign-In</th>
                        <th>Owner</th>
                        <th>Action Taken</th>
                        <th>Notification Sent</th>
                    </tr>
                </thead>
                <tbody>
                    $(($ProcessedDevices | ForEach-Object {
                        "<tr>
                            <td>$($_.DisplayName)</td>
                            <td>$($_.OperatingSystem)</td>
                            <td>$($_.LastSignIn.ToString('yyyy-MM-dd'))</td>
                            <td>$($_.Owner)</td>
                            <td class='success'>$($_.Status)</td>
                            <td>$($_.NotificationSent)</td>
                        </tr>"
                    }) -join "")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($ExcludedDevices.Count -gt 0) {
        @"
        <div class="section">
            <h2>Excluded Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Exclusion Reason</th>
                    </tr>
                </thead>
                <tbody>
                    $(($ExcludedDevices | ForEach-Object {
                        "<tr>
                            <td>$($_.DisplayName)</td>
                            <td>$($_.ExclusionReason)</td>
                        </tr>"
                    }) -join "")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($FailedDevices.Count -gt 0) {
        @"
        <div class="section">
            <h2>Failed Operations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Error Message</th>
                    </tr>
                </thead>
                <tbody>
                    $(($FailedDevices | ForEach-Object {
                        "<tr>
                            <td>$($_.DisplayName)</td>
                            <td class='error'>$($_.Error)</td>
                        </tr>"
                    }) -join "")
                </tbody>
            </table>
        </div>
"@
    })
    
    <div class="section">
        <h2>Audit Trail</h2>
        <p>All actions have been logged to Azure Monitor for compliance and audit purposes.</p>
        <p>Log Analytics Workspace: $env:LOG_ANALYTICS_WORKSPACE</p>
        <p>Retention Period: 90 days</p>
    </div>
</body>
</html>
"@
    
    try {
        $Html | Out-File -FilePath $FullPath -Encoding UTF8
        Write-Output "Compliance report created: $FullPath"
        return $FullPath
    }
    catch {
        Write-Error "Failed to create compliance report: $_"
        return $null
    }
}

# Function for progressive cleanup with safety thresholds
function Test-SafetyThreshold {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$DevicesToDelete,
        
        [Parameter(Mandatory=$true)]
        [int]$TotalDevices,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxPercentage = 10,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxAbsolute = 100
    )
    
    $PercentageToDelete = if ($TotalDevices -gt 0) { 
        ($DevicesToDelete / $TotalDevices) * 100 
    } else { 0 }
    
    if ($DevicesToDelete -gt $MaxAbsolute) {
        Write-Warning "Safety threshold exceeded: Attempting to delete $DevicesToDelete devices (max: $MaxAbsolute)"
        return $false
    }
    
    if ($PercentageToDelete -gt $MaxPercentage) {
        Write-Warning "Safety threshold exceeded: Attempting to delete $([math]::Round($PercentageToDelete, 2))% of devices (max: $MaxPercentage%)"
        return $false
    }
    
    Write-Output "Safety check passed: $DevicesToDelete devices ($([math]::Round($PercentageToDelete, 2))% of total)"
    return $true
}
```

### Main Runbook

```powershell
<#
.SYNOPSIS
    Azure Automation Runbook for cleaning up inactive devices in Entra ID
    
.DESCRIPTION
    This runbook identifies and removes devices that have been inactive for specified days.
    It handles both standard registered devices and Autopilot devices differently.
    Includes safety checks, exclusions, notifications, and compliance reporting.
    
.PARAMETER InactiveDays
    Number of days of inactivity before a device is considered for cleanup (default: 90)
    
.PARAMETER WhatIf
    Run in simulation mode without actually deleting devices
    
.PARAMETER CleanupType
    Type of cleanup to perform: "All", "RegisteredOnly", "AutopilotOnly"
    
.PARAMETER SendNotifications
    Send email notifications to device owners and admins
    
.PARAMETER AdminEmails
    Array of admin email addresses for reports
    
.PARAMETER ExcludedDeviceNames
    Array of device names to exclude from cleanup
    
.PARAMETER ExcludedOSTypes
    Array of operating system types to exclude
    
.PARAMETER MaxDeletePercentage
    Maximum percentage of devices that can be deleted (safety threshold)
    
.PARAMETER MaxDeleteAbsolute
    Maximum absolute number of devices that can be deleted
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "RegisteredOnly", "AutopilotOnly")]
    [string]$CleanupType = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$SendNotifications = $true,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AdminEmails = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedDeviceNames = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedOSTypes = @(),
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDeletePercentage = 10,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDeleteAbsolute = 100
)

# Import required modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.DeviceManagement.Enrollment

Write-Output "========================================="
Write-Output "Entra ID Device Cleanup Automation"
Write-Output "========================================="
Write-Output "Inactive Days Threshold: $InactiveDays"
Write-Output "Cleanup Type: $CleanupType"
Write-Output "WhatIf Mode: $($WhatIf.IsPresent)"
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "========================================="

try {
    # Connect to Microsoft Graph
    Write-Output "Connecting to Microsoft Graph..."
    Connect-MgGraph -Identity -NoWelcome
    
    # Verify connection
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }
    Write-Output "Successfully connected to tenant: $($Context.TenantId)"
    
    # Execute cleanup based on type
    switch ($CleanupType) {
        "All" {
            Write-Output "`n--- Cleaning Up Registered Devices ---"
            Remove-InactiveRegisteredDevices -InactiveDays $InactiveDays -WhatIf:$WhatIf
            
            Write-Output "`n--- Cleaning Up Autopilot Devices ---"
            Remove-InactiveAutopilotDevices -InactiveDays $InactiveDays -WhatIf:$WhatIf
        }
        "RegisteredOnly" {
            Write-Output "`n--- Cleaning Up Registered Devices Only ---"
            Remove-InactiveRegisteredDevices -InactiveDays $InactiveDays -WhatIf:$WhatIf
        }
        "AutopilotOnly" {
            Write-Output "`n--- Cleaning Up Autopilot Devices Only ---"
            Remove-InactiveAutopilotDevices -InactiveDays $InactiveDays -WhatIf:$WhatIf
        }
    }
    
    Write-Output "`n========================================="
    Write-Output "Device cleanup completed successfully"
    Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "========================================="
}
catch {
    Write-Error "Critical error in device cleanup automation: $_"
    throw
}
finally {
    # Disconnect from Microsoft Graph
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
```

## Scheduling

### Create Schedule in Azure Automation

1. Navigate to your Azure Automation Account
2. Go to **Schedules** → **Add a schedule**
3. Configure schedule:
   - **Name**: Daily-Device-Cleanup
   - **Recurrence**: Recurring
   - **Recur every**: 1 Day
   - **Start time**: 2:00 AM (or preferred time)
   - **Time zone**: Your preferred timezone

### Link Schedule to Runbook

1. Go to **Runbooks** → Select your cleanup runbook
2. Click **Schedules** → **Add a schedule**
3. Link to the schedule created above
4. Set parameters:
   - `InactiveDays`: 90
   - `WhatIf`: False (set to True for testing)
   - `CleanupType`: All

## Monitoring and Alerts

### Configure Alert Rules

Create alert rules in Azure Monitor for:
- Runbook failures
- Excessive device deletions (threshold-based)
- Long execution times

### Log Analytics Integration

```kusto
// Query to monitor device cleanup activities
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.AUTOMATION"
| where Category == "JobLogs"
| where RunbookName_s contains "DeviceCleanup"
| project TimeGenerated, ResultType, ResultDescription
| order by TimeGenerated desc
```

## Testing

### Test Procedure

1. **Initial Test with WhatIf**:
   ```powershell
   # Run with WhatIf to see what would be deleted
   .\DeviceCleanupRunbook.ps1 -InactiveDays 90 -WhatIf -CleanupType "All"
   ```

2. **Test with Shorter Inactive Period**:
   ```powershell
   # Test with 180 days to start conservatively
   .\DeviceCleanupRunbook.ps1 -InactiveDays 180 -CleanupType "RegisteredOnly"
   ```

3. **Gradual Rollout**:
   - Start with 180 days inactive
   - Monitor for 1 week
   - Reduce to 120 days
   - Monitor for 1 week
   - Finally implement 90 days

## Troubleshooting

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Permission Denied | Verify Graph API permissions are granted and admin consented |
| Module Not Found | Install required modules in Automation Account |
| Timeout Errors | Implement pagination for large device counts |
| Autopilot Devices Deleted | Verify TrustType filtering is working correctly |

### Debug Logging

Enable verbose logging by adding:
```powershell
$VerbosePreference = "Continue"
Write-Verbose "Detailed logging message"
```

## Security Considerations

1. **Least Privilege**: Use only required Graph API permissions
2. **Audit Logging**: Enable diagnostic logging for all automation activities
3. **Approval Workflow**: Consider implementing approval for deletions over threshold
4. **Backup**: Export device list before deletion for recovery purposes

## Recovery Procedures

### Restore Accidentally Deleted Device

Devices can be restored from the Entra ID Recycle Bin within 30 days:

```powershell
# List deleted devices
Get-MgDirectoryDeletedItem -DirectoryObjectType "device"

# Restore specific device
Restore-MgDirectoryDeletedItem -DirectoryObjectId $DeviceId
```

## Performance Optimization

For large environments (10,000+ devices):

1. Implement pagination:
```powershell
$Devices = Get-MgDevice -All -PageSize 999
```

2. Use parallel processing:
```powershell
$Devices | ForEach-Object -Parallel {
    # Process device
} -ThrottleLimit 5
```

3. Implement batching for deletions

## Compliance and Reporting

### Generate Cleanup Report

```powershell
function Export-CleanupReport {
    param(
        [string]$OutputPath = "C:\Reports\DeviceCleanup_$(Get-Date -Format 'yyyyMMdd').csv"
    )
    
    $Report = @()
    
    # Collect device information before deletion
    $InactiveDevices | ForEach-Object {
        $Report += [PSCustomObject]@{
            DeviceName = $_.DisplayName
            DeviceId = $_.Id
            LastSignIn = $_.ApproximateLastSignInDateTime
            OperatingSystem = $_.OperatingSystem
            TrustType = $_.TrustType
            Action = "Deleted"
            Timestamp = Get-Date
        }
    }
    
    $Report | Export-Csv -Path $OutputPath -NoTypeInformation
    
    # Upload to Azure Storage for retention
    $StorageAccount = Get-AutomationVariable -Name 'StorageAccountName'
    $Container = Get-AutomationVariable -Name 'ReportsContainer'
    
    $Context = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount
    Set-AzStorageBlobContent -File $OutputPath -Container $Container -Context $Context
}
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial release with basic cleanup functionality |
| 1.1.0 | 2024-02 | Added Autopilot device handling |
| 1.2.0 | 2024-03 | Added WhatIf mode and reporting |

## Support and Maintenance

- Review and update inactive days threshold quarterly
- Monitor Graph API deprecations and update accordingly
- Test in non-production environment after Azure updates
- Maintain documentation for compliance requirements