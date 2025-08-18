# Azure Automation Deployment - Enterprise App Usage Monitor

Deploy and configure the Enterprise App Usage Monitor for Azure Automation with managed identity authentication and scheduled execution.

## 🚀 Quick Deployment

```powershell
.\Deploy-EnterpriseAppUsageMonitor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -UnusedDaysThreshold 90 `
    -ITAdminEmails @("admin@company.com")
```

## 📊 Key Parameters

- **UnusedDaysThreshold**: Application inactivity threshold (default: 90 days)
- **MinimumRiskThreshold**: Risk scoring threshold (default: 5)
- **ExcludeApplications**: Applications to exclude from analysis
- **StartTime**: Weekly execution time (default: 04:00:00)

## 🔐 Required Permissions

- Application.Read.All
- AuditLog.Read.All
- Directory.Read.All
- Mail.Send

## 💰 Business Value

- Identifies unused applications for cost optimization
- Assesses security risks of inactive applications
- Provides business impact analysis for application cleanup
- Generates prioritized action items for IT governance

See main [README](../README.md) for detailed usage instructions.