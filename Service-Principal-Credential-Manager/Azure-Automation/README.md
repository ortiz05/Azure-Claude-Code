# Azure Automation Deployment - Service Principal Credential Manager

Deploy and configure the Service Principal Credential Manager for Azure Automation with managed identity authentication and scheduled execution.

## 🚀 Quick Deployment

```powershell
.\Deploy-ServicePrincipalCredentialManager.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -CriticalThresholdDays 7 `
    -SecurityTeamEmails @("security@company.com")
```

## 📊 Key Parameters

- **CriticalThresholdDays**: Critical alert threshold (default: 7 days)
- **WarningThresholdDays**: Warning alert threshold (default: 30 days)
- **LongLivedThresholdDays**: Long-lived credential threshold (default: 365 days)
- **EnableAutomatedRemediation**: Enable automatic credential cleanup (default: false)
- **StartTime**: Daily execution time (default: 06:00:00)

## 🔐 Required Permissions

**Read-Only Mode:**
- Application.Read.All
- Directory.Read.All
- AuditLog.Read.All
- Mail.Send

**With Automated Remediation:**
- Application.ReadWrite.All (additional permission)

## 🔒 Critical Security Management

- Monitors all Service Principal certificates and secrets
- Advanced risk assessment with usage correlation
- Executive dashboards for compliance documentation
- DevOps integration hooks for automated renewal workflows
- Comprehensive audit logging for SOC2/SOX compliance

⚠️ **Important**: Test thoroughly with WhatIf mode before enabling automated remediation.

See main [README](../README.md) for detailed usage instructions.