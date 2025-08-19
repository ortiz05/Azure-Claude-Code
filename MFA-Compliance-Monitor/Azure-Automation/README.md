# Azure Automation Deployment - MFA Compliance Monitor

Deploy and configure the MFA Compliance Monitor for Azure Automation with managed identity authentication and scheduled execution.

## 🚀 Quick Deployment

```powershell
.\Deploy-MFAComplianceMonitor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -StorageAccountName "your-storage-account" `
    -DaysToAnalyze 30 `
    -ITAdminEmails @("admin@company.com")
```

## 📊 Key Parameters

- **DaysToAnalyze**: Sign-in analysis period (default: 30 days)
- **ITAdminEmails**: Admin notification email addresses
- **ExcludeUsers**: Users to exclude from compliance monitoring
- **StartTime**: Daily execution time (default: 07:00:00)
- **StorageAccountName**: Azure Storage account for report archival
- **StorageContainerName**: Container name (default: "mfa-compliance-reports")
- **UseManagedIdentity**: Use managed identity for authentication (default: true)

## 🔐 Required Permissions

- AuditLog.Read.All
- User.Read.All
- Mail.Send
- Directory.Read.All

## 📈 Compliance Focus

- Monitors Azure AD sign-in logs for MFA method usage
- Identifies users using non-Microsoft Authenticator MFA
- Sends professional email notifications to non-compliant users
- Generates executive compliance reports for IT leadership

See main [README](../README.md) for detailed usage instructions.