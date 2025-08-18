# Device Cleanup Automation

Automated solution for managing and cleaning up inactive devices in Microsoft Entra ID (Azure Active Directory).

## 📋 Overview

This automation identifies and removes devices that have been inactive for a specified period (default: 90 days), with separate handling for standard registered devices and Windows Autopilot devices.

## ✨ Key Features

- **Dual Device Type Handling**
  - Standard devices: Complete removal from Entra ID
  - Autopilot devices: Remove from Entra ID, preserve Autopilot enrollment

- **Safety Mechanisms**
  - Configurable inactivity thresholds
  - Maximum deletion limits (percentage and absolute)
  - Device exclusion lists
  - WhatIf/simulation mode

- **Comprehensive Reporting**
  - Multiple CSV reports for different device categories
  - Detailed device information capture
  - Summary statistics and audit trails

- **Email Notifications**
  - Warning emails before deletion
  - Confirmation emails post-deletion
  - Admin summary reports

## 📁 Project Structure

```
Device-Cleanup-Automation/
├── Documentation/
│   └── CLAUDE.md                        # Detailed implementation guidelines
├── Scripts/
│   └── DeviceCleanupAutomation.ps1     # Main automation script
├── Tests/
│   ├── Test-GraphConnection.ps1         # API connection testing
│   └── Test-DeviceCleanupFunctions.ps1  # Function validation
└── Reports/                             # CSV output directory
```

## 🚀 Quick Start

### Prerequisites

1. **Azure Resources**
   - Azure Automation Account (for production)
   - Service Principal or Managed Identity

2. **Required Permissions**
   - Device.ReadWrite.All
   - User.Read.All
   - Mail.Send (optional)
   - Directory.ReadWrite.All

3. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

1. **Test Connection**
   ```powershell
   .\Tests\Test-GraphConnection.ps1
   ```

2. **Run in Simulation Mode**
   ```powershell
   .\Scripts\DeviceCleanupAutomation.ps1 -WhatIf -InactiveDays 90
   ```

3. **Production Execution**
   ```powershell
   .\Scripts\DeviceCleanupAutomation.ps1 `
       -InactiveDays 90 `
       -ExportPath "C:\DeviceReports" `
       -MaxDeletePercentage 10 `
       -MaxDeleteAbsolute 100
   ```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| InactiveDays | Int | 90 | Days of inactivity threshold |
| WhatIf | Switch | False | Simulation mode |
| CleanupType | String | All | All, RegisteredOnly, AutopilotOnly |
| SendNotifications | Switch | True | Enable email notifications |
| AdminEmails | String[] | [] | Admin email addresses |
| ExcludedDeviceNames | String[] | [] | Device name patterns to exclude |
| ExcludedOSTypes | String[] | [] | OS types to exclude |
| MaxDeletePercentage | Int | 10 | Max % of devices to delete |
| MaxDeleteAbsolute | Int | 100 | Max absolute number to delete |
| ExportPath | String | C:\DeviceCleanupReports | Report output path |

## 📈 Generated Reports

The automation generates multiple CSV reports:

1. **AllInactiveDevices_[timestamp].csv**
   - Complete list of all inactive devices found
   - Includes all device details and owner information

2. **ProcessedDevices_[timestamp].csv**
   - Devices successfully processed/deleted
   - Action taken and status

3. **ExcludedDevices_[timestamp].csv**
   - Devices excluded from cleanup
   - Exclusion reasons

4. **FailedDevices_[timestamp].csv**
   - Devices where deletion failed
   - Error messages and details

5. **CleanupSummary_[timestamp].csv**
   - High-level statistics
   - Run configuration and results

## 🔄 Deployment to Azure Automation

1. **Create Runbook**
   ```powershell
   # In Azure Automation Account
   New-AzAutomationRunbook `
       -Name "DeviceCleanupAutomation" `
       -Type PowerShell `
       -ResourceGroupName "YourRG" `
       -AutomationAccountName "YourAutomation"
   ```

2. **Import Script**
   - Upload DeviceCleanupAutomation.ps1 content
   - Publish the runbook

3. **Configure Schedule**
   - Recommended: Weekly execution
   - Suggested time: 2:00 AM local time

4. **Set Parameters**
   - Configure default parameter values
   - Start with conservative thresholds

## 🛡️ Safety Recommendations

1. **Progressive Rollout**
   - Start with 180-day threshold
   - Gradually reduce to 90 days
   - Monitor results at each stage

2. **Exclusion Lists**
   - Exclude critical device patterns
   - Exclude VIP user devices
   - Exclude specific OS types if needed

3. **Testing Protocol**
   - Always run WhatIf first
   - Review generated reports
   - Validate exclusion rules

## 📊 Sample Output

```
=========================================
Entra ID Device Cleanup Automation
=========================================
Inactive Days Threshold: 90
Cleanup Type: All
WhatIf Mode: True
Export Path: C:\DeviceReports
Start Time: 2024-01-15 02:00:00
=========================================

Validating Graph API permissions...
  ✓ Device.ReadWrite.All - Granted
  ✓ User.Read.All - Granted

Performing Safety Check...
Total devices in tenant: 1000
Devices potentially eligible for cleanup: 75
Safety check passed: 75 devices (7.5% of total)

Processing registered devices inactive for 90+ days...
Found 50 inactive registered devices
  [WhatIf] Would remove device: DESKTOP-ABC123
  [WhatIf] Would remove device: LAPTOP-XYZ789

Device Cleanup Summary
=========================================
Total Devices in Tenant: 1000
Inactive Devices Found: 75
Devices Processed: 50
Devices Excluded: 20
Failed Operations: 0
Mode: Simulation (WhatIf)
Reports saved to: C:\DeviceReports
=========================================
```

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Verify Graph API permissions and admin consent |
| No devices found | Check Device.Read permissions |
| Autopilot access error | Verify DeviceManagementServiceConfig permissions |
| Safety threshold exceeded | Adjust MaxDeletePercentage or MaxDeleteAbsolute |

## 📝 Best Practices

1. **Always test with WhatIf mode first**
2. **Review CSV reports before production runs**
3. **Maintain device backups for 90 days**
4. **Monitor execution logs in Azure**
5. **Set up alerting for failures**

## 🔗 Related Documentation

- [Full Implementation Guidelines](./Documentation/CLAUDE.md)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph)
- [Azure Automation Documentation](https://docs.microsoft.com/azure/automation)

## 📧 Support

For issues or questions:
1. Check the troubleshooting section
2. Review Azure Automation job logs
3. Verify Graph API permissions
4. Create an issue in the repository