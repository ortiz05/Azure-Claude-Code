# MFA Compliance Monitor

Automated solution for monitoring and enforcing Microsoft Authenticator compliance across your organization.

## 📋 Overview

This automation analyzes Azure AD sign-in logs to identify users who have used MFA methods other than Microsoft Authenticator in the last 30 days. It sends detailed notification emails to non-compliant users and provides comprehensive reporting for IT administrators.

## ✨ Key Features

- **Automated Compliance Detection**
  - Analyzes sign-in logs for MFA method usage
  - Identifies non-Microsoft Authenticator methods
  - Tracks compliance trends over time

- **User Notification System**
  - Professional HTML email templates
  - Detailed sign-in information with device and location data
  - Clear action items and compliance deadlines
  - CC functionality for IT administrators

- **Comprehensive Reporting**
  - Multiple CSV exports for audit trails
  - Executive dashboard with compliance metrics
  - Detailed sign-in analysis with device information
  - Processing error tracking

- **Enterprise Security Features**
  - Permission validation and managed identity support
  - User exclusion lists for service accounts
  - WhatIf mode for testing
  - Comprehensive error handling and logging

## 📁 Project Structure

```
MFA-Compliance-Monitor/
├── Documentation/
│   └── CLAUDE.md                   # AI-readable implementation guidelines
├── Scripts/
│   └── MFAComplianceMonitor.ps1    # Main automation script
├── Tests/
│   └── Test-MFAConnection.ps1      # Connection and permission testing
├── Templates/
│   ├── UserNotification.html       # Email template for users
│   └── AdminSummary.html          # Email template for admins
└── Reports/                        # CSV output directory
```

## 🚀 Quick Start

### Prerequisites

1. **Azure Resources**
   - Azure Automation Account (for production)
   - Service Principal or Managed Identity

2. **Required Permissions**
   - AuditLog.Read.All (to read sign-in logs)
   - User.Read.All (to read user information)
   - Mail.Send (to send notifications)
   - Directory.Read.All (for user directory access)

3. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

1. **Test Connection**
   ```powershell
   .\Tests\Test-MFAConnection.ps1
   ```

2. **Run in Simulation Mode**
   ```powershell
   .\Scripts\MFAComplianceMonitor.ps1 -WhatIf -DaysToAnalyze 30
   ```

3. **Production Execution**
   ```powershell
   .\Scripts\MFAComplianceMonitor.ps1 `
       -DaysToAnalyze 30 `
       -ITAdminEmails @("admin@company.com", "security@company.com") `
       -ExportPath "C:\MFAReports" `
       -SendUserNotifications `
       -SendAdminSummary
   ```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| DaysToAnalyze | Int | 30 | Days to look back for sign-in analysis |
| WhatIf | Switch | False | Simulation mode without sending emails |
| ITAdminEmails | String[] | [] | Admin emails to CC on notifications |
| ExcludedUsers | String[] | [] | User UPNs to exclude from monitoring |
| ExportPath | String | C:\MFAComplianceReports | Report output path |
| IncludeCompliantUsers | Switch | False | Include compliant users in reports |
| SendUserNotifications | Switch | True | Enable user notification emails |
| SendAdminSummary | Switch | True | Enable admin summary reports |

## 📈 Generated Reports

The automation generates multiple CSV reports:

1. **NonCompliantMFAUsers_[timestamp].csv**
   - Users who used non-Microsoft Authenticator methods
   - Compliance status and method details
   - Notification tracking

2. **CompliantMFAUsers_[timestamp].csv** (optional)
   - Users who only used Microsoft Authenticator
   - Baseline for compliance tracking

3. **NonCompliantSignInDetails_[timestamp].csv**
   - Detailed sign-in records for non-compliant users
   - Device, location, and method information

4. **ProcessingErrors_[timestamp].csv**
   - Any processing errors encountered
   - User and error details for troubleshooting

5. **MFAComplianceSummary_[timestamp].csv**
   - High-level statistics and run configuration
   - Compliance rates and trends

## 📧 Email Notifications

### User Notification Features
- **Professional HTML design** with company branding capability
- **Detailed sign-in table** showing:
  - Date and time of sign-in
  - Device/browser information
  - MFA method used
  - Geographic location
- **Clear action items** with step-by-step instructions
- **Security education** explaining why Microsoft Authenticator is required
- **Compliance deadline** (7 days) with consequences outlined

### Admin Summary Features
- **Executive dashboard** with key metrics
- **Top 10 non-compliant users** with details
- **Most common non-compliant methods** analysis
- **Processing errors** and recommendations
- **Compliance trends** and actionable insights

## 🔧 MFA Methods Detected

The automation recognizes and categorizes these MFA methods:

### ✅ Compliant Methods
- Microsoft Authenticator (Push)
- Microsoft Authenticator (OTP)

### ⚠️ Non-Compliant Methods
- SMS Text Message
- Voice Call
- Email
- Software OATH Token
- FIDO2 Security Key
- Windows Hello for Business
- Certificate-based Authentication
- OATH Hardware Token

## 🔄 Deployment Options

### Azure Automation Deployment
1. **Create Runbook**
   - Import MFAComplianceMonitor.ps1
   - Configure schedule (recommended: weekly)
   - Set up parameters

2. **Configure Authentication**
   - Enable managed identity
   - Grant required Graph permissions
   - Test with WhatIf mode first

### Manual Execution
1. **Development Testing**
   ```powershell
   # Test with small date range
   .\Scripts\MFAComplianceMonitor.ps1 -DaysToAnalyze 7 -WhatIf
   ```

2. **Production Run**
   ```powershell
   # Full production execution
   .\Scripts\MFAComplianceMonitor.ps1 -ITAdminEmails @("admin@company.com")
   ```

## 📊 Sample Output

```
=========================================
MFA Compliance Monitor
=========================================
Analysis Period: Last 30 days
WhatIf Mode: False
User Notifications: True
Admin Summary: True
Export Path: C:\MFAComplianceReports
Start Time: 2024-01-15 09:00:00
=========================================

Connecting to Microsoft Graph...
Successfully connected to tenant: your-tenant-id

--- Validating Permissions ---
  ✓ AuditLog.Read.All - Granted
  ✓ User.Read.All - Granted
  ✓ Mail.Send - Granted
  ✓ Directory.Read.All - Granted

--- Analyzing MFA Usage ---
Retrieving sign-in logs from Microsoft Graph...
Retrieved 5000 sign-in records...
Total sign-in records retrieved: 5000
MFA sign-ins found: 1200

  ⚠ Non-compliant user found: John Doe (john.doe@company.com) - Methods: SMS Text Message
  ⚠ Non-compliant user found: Jane Smith (jane.smith@company.com) - Methods: Voice Call

Analysis complete:
  Non-compliant users: 25
  Compliant users: 475
  Processing errors: 0

--- Sending User Notifications ---
Processing notification for: John Doe
  ✓ Security notification sent to john.doe@company.com

MFA Compliance Analysis Summary
=========================================
Analysis Period: Last 30 days
Total Users Analyzed: 500
Non-Compliant Users: 25
Compliant Users: 475
Compliance Rate: 95.0%
Notifications Sent: 25
Processing Errors: 0
Mode: Production
Reports saved to: C:\MFAComplianceReports
=========================================

⚠️  ACTION REQUIRED: 25 users require MFA compliance follow-up
📧 User notifications sent: 25
📊 Review detailed reports in: C:\MFAComplianceReports
```

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied for sign-in logs | Verify AuditLog.Read.All permission and admin consent |
| No sign-in data found | Check if users have signed in during analysis period |
| Email sending failures | Verify Mail.Send permission and SMTP connectivity |
| High processing times | Consider reducing DaysToAnalyze or implementing pagination |

## 📋 Best Practices

1. **Start with WhatIf mode** to understand impact
2. **Use exclusion lists** for service accounts and shared mailboxes
3. **Schedule weekly runs** for consistent monitoring
4. **Monitor compliance trends** over time
5. **Follow up manually** with persistently non-compliant users
6. **Regular permission audits** to ensure continued access

## 🔗 Related Documentation

- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/azure/active-directory/reports-monitoring)
- [Microsoft Authenticator Deployment](https://docs.microsoft.com/azure/active-directory/authentication)

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review Azure Automation job logs
3. Verify Graph API permissions
4. Create an issue in the repository