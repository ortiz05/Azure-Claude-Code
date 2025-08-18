# Azure Automation Deployment - Enterprise App Certificate Monitor

Deploy and configure the Enterprise App Certificate Monitor for Azure Automation with managed identity authentication and scheduled execution.

## 🚀 Quick Deployment

```powershell
.\Deploy-EnterpriseAppCertificateMonitor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -CriticalThresholdDays 7 `
    -SecurityTeamEmails @("security@company.com")
```

## 📊 Key Parameters

- **CriticalThresholdDays**: Critical alert threshold (default: 7 days)
- **WarningThresholdDays**: Warning alert threshold (default: 30 days)
- **SecurityTeamEmails**: Security team notification addresses
- **StartTime**: Daily execution time (default: 05:00:00)

## 🔐 Required Permissions

- Application.Read.All
- AuditLog.Read.All
- Directory.Read.All
- Mail.Send

## 🚨 Critical Security Focus

- Monitors all Enterprise Application certificates and secrets
- Identifies expired credentials on unused applications (highest risk)
- Sends immediate alerts for critical security combinations
- Correlates certificate status with application usage patterns
- Prevents service disruptions from unexpected certificate expiration

See main [README](../README.md) for detailed usage instructions.