# Azure Automation Deployment - Device Cleanup Automation

Deploy and configure the Device Cleanup Automation for Azure Automation with managed identity authentication and scheduled execution.

## 🚀 Quick Deployment

```powershell
.\Deploy-DeviceCleanupAutomation.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -StorageAccountName "your-storage-account" `
    -InactiveDays 90 `
    -MaxDeletePercentage 10 `
    -AdminEmails @("admin@company.com")
```

## 📊 Key Parameters

- **InactiveDays**: Device inactivity threshold (default: 90)
- **MaxDeletePercentage**: Safety limit as percentage (default: 10%)
- **MaxDeleteAbsolute**: Maximum devices to delete (default: 100)
- **CleanupType**: "All", "RegisteredOnly", or "AutopilotOnly"
- **StorageAccountName**: Azure Storage account for report archival
- **StorageContainerName**: Container name (default: "device-cleanup-reports")
- **UseManagedIdentity**: Use managed identity for authentication (default: true)

## 🔐 Required Permissions

- Device.ReadWrite.All
- User.Read.All  
- Directory.ReadWrite.All
- Mail.Send

## ⚠️ Safety Features

- WhatIf mode enabled by default
- Configurable safety thresholds
- Progressive rollout recommendations
- Comprehensive audit logging

See main [README](../README.md) for detailed usage instructions.