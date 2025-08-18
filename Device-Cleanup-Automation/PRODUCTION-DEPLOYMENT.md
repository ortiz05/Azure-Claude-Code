# Production Deployment Guide

## 🚀 Production Deployment Checklist

This guide provides step-by-step instructions for deploying the Device Cleanup Automation to production environments.

## 📋 Pre-Deployment Requirements

### ✅ Infrastructure Prerequisites
- [ ] Azure Automation Account created
- [ ] Log Analytics Workspace configured
- [ ] Azure Storage Account for reports (optional but recommended)
- [ ] Azure Key Vault for sensitive configuration
- [ ] Network connectivity validated
- [ ] Backup and recovery procedures documented

### ✅ Security Prerequisites
- [ ] Managed Identity enabled on Automation Account
- [ ] Required Graph API permissions granted and admin consented
- [ ] RBAC roles assigned correctly
- [ ] Security assessment completed
- [ ] Compliance requirements validated

### ✅ Operational Prerequisites
- [ ] Monitoring and alerting configured
- [ ] Change management approval obtained
- [ ] Stakeholder notifications sent
- [ ] Rollback procedures documented
- [ ] Support contacts identified

## 🔧 Step-by-Step Deployment

### Step 1: Environment Preparation

1. **Create Resource Group**
   ```powershell
   New-AzResourceGroup -Name "rg-automation-prod" -Location "East US"
   ```

2. **Create Automation Account**
   ```powershell
   New-AzAutomationAccount `
       -ResourceGroupName "rg-automation-prod" `
       -Name "aa-device-cleanup-prod" `
       -Location "East US" `
       -AssignSystemIdentity
   ```

3. **Configure Diagnostic Settings**
   ```powershell
   $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName "rg-automation-prod" -Name "aa-device-cleanup-prod"
   Set-AzDiagnosticSetting -ResourceId $AutomationAccount.ResourceId -WorkspaceId $LogAnalyticsWorkspaceId -Enabled $true
   ```

### Step 2: Permission Configuration

1. **Grant Graph API Permissions to Managed Identity**
   ```powershell
   # Get the managed identity
   $ManagedIdentity = Get-AzADServicePrincipal -DisplayName "aa-device-cleanup-prod"
   
   # Required permissions (must be granted via Azure portal or Graph API)
   $RequiredPermissions = @(
       "Device.ReadWrite.All",
       "User.Read.All", 
       "Directory.ReadWrite.All",
       "DeviceManagementServiceConfig.ReadWrite.All"
   )
   ```

2. **Configure RBAC Permissions**
   ```powershell
   # Grant Automation Contributor to service account
   New-AzRoleAssignment `
       -ObjectId $ManagedIdentity.Id `
       -RoleDefinitionName "Automation Contributor" `
       -Scope "/subscriptions/$SubscriptionId/resourceGroups/rg-automation-prod"
   ```

### Step 3: Script Deployment

1. **Create PowerShell Runbook**
   ```powershell
   New-AzAutomationRunbook `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "DeviceCleanupAutomation" `
       -Type PowerShell `
       -Description "Automated cleanup of inactive devices in Entra ID"
   ```

2. **Import Script Content**
   ```powershell
   # Upload the script file
   Import-AzAutomationRunbook `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "DeviceCleanupAutomation" `
       -Type PowerShell `
       -Path ".\Scripts\DeviceCleanupAutomation.ps1"
   ```

3. **Publish Runbook**
   ```powershell
   Publish-AzAutomationRunbook `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "DeviceCleanupAutomation"
   ```

### Step 4: Configuration Management

1. **Create Automation Variables**
   ```powershell
   # Admin email addresses
   New-AzAutomationVariable `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "AdminEmails" `
       -Value "admin1@company.com,admin2@company.com" `
       -Encrypted $false
   
   # Export path for reports
   New-AzAutomationVariable `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "ExportPath" `
       -Value "C:\DeviceCleanupReports" `
       -Encrypted $false
   
   # Safety thresholds
   New-AzAutomationVariable `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "MaxDeletePercentage" `
       -Value "5" `
       -Encrypted $false
   ```

2. **Store Sensitive Configuration in Key Vault**
   ```powershell
   # Example: Store excluded device patterns
   Set-AzKeyVaultSecret `
       -VaultName "kv-automation-prod" `
       -Name "ExcludedDevicePatterns" `
       -SecretValue (ConvertTo-SecureString "SERVER-*,DC-*,CRITICAL-*" -AsPlainText -Force)
   ```

### Step 5: Initial Testing

1. **Run WhatIf Test**
   ```powershell
   Start-AzAutomationRunbook `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "DeviceCleanupAutomation" `
       -Parameters @{
           "WhatIf" = $true
           "InactiveDays" = 180  # Start conservative
           "CleanupType" = "RegisteredOnly"  # Start with non-Autopilot devices
       }
   ```

2. **Review Test Results**
   - Check job output in Azure portal
   - Verify CSV reports are generated
   - Validate device counts and exclusions
   - Confirm no actual deletions occurred

### Step 6: Production Schedule Configuration

1. **Create Production Schedule**
   ```powershell
   New-AzAutomationSchedule `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -Name "WeeklyDeviceCleanup" `
       -StartTime (Get-Date).AddDays(7).Date.AddHours(2) `
       -WeekInterval 1 `
       -DaysOfWeek Tuesday
   ```

2. **Link Schedule to Runbook**
   ```powershell
   Register-AzAutomationScheduledRunbook `
       -ResourceGroupName "rg-automation-prod" `
       -AutomationAccountName "aa-device-cleanup-prod" `
       -RunbookName "DeviceCleanupAutomation" `
       -ScheduleName "WeeklyDeviceCleanup" `
       -Parameters @{
           "InactiveDays" = 90
           "CleanupType" = "All"
           "SendNotifications" = $true
           "MaxDeletePercentage" = 5
           "MaxDeleteAbsolute" = 50
       }
   ```

## 📊 Monitoring Setup

### Azure Monitor Configuration

1. **Create Alert Rules**
   ```powershell
   # Alert on runbook failures
   $ActionGroup = Get-AzActionGroup -ResourceGroupName "rg-monitoring" -Name "ag-automation-alerts"
   
   New-AzMetricAlertRule `
       -ResourceGroupName "rg-automation-prod" `
       -Name "DeviceCleanupFailure" `
       -Location "East US" `
       -Description "Alert when device cleanup runbook fails" `
       -Severity 2 `
       -Enabled $true `
       -MetricName "JobsFailed" `
       -Operator GreaterThan `
       -Threshold 0 `
       -WindowSize 01:00:00 `
       -TimeAggregationOperator Total `
       -Actions $ActionGroup
   ```

2. **Configure Log Analytics Queries**
   ```kusto
   // Save these queries in Log Analytics workspace
   
   // Monitor execution summary
   AzureDiagnostics
   | where ResourceProvider == "MICROSOFT.AUTOMATION"
   | where Category == "JobLogs" 
   | where RunbookName_s == "DeviceCleanupAutomation"
   | where ResultDescription contains "Device Cleanup Summary"
   | project TimeGenerated, ResultDescription
   | order by TimeGenerated desc
   
   // Track deletion counts
   AzureDiagnostics
   | where Category == "JobLogs"
   | where RunbookName_s == "DeviceCleanupAutomation"
   | where ResultDescription contains "Devices Processed:"
   | extend ProcessedCount = extract(@"Devices Processed: (\d+)", 1, ResultDescription)
   | project TimeGenerated, ProcessedCount = toint(ProcessedCount)
   | render timechart
   ```

## 🔄 Rollout Strategy

### Phase 1: Conservative Testing (Week 1-2)
- **Threshold**: 180 days inactive
- **Scope**: RegisteredOnly devices
- **Frequency**: Manual execution
- **Validation**: Review all reports before proceeding

### Phase 2: Extended Testing (Week 3-4)
- **Threshold**: 120 days inactive  
- **Scope**: RegisteredOnly devices
- **Frequency**: Weekly scheduled
- **Validation**: Monitor for false positives

### Phase 3: Full Implementation (Week 5+)
- **Threshold**: 90 days inactive
- **Scope**: All device types
- **Frequency**: Weekly scheduled
- **Validation**: Ongoing monitoring and alerting

## 🚨 Emergency Procedures

### Immediate Actions for Issues
1. **Disable Schedule**
   ```powershell
   Set-AzAutomationSchedule -ResourceGroupName "rg-automation-prod" -AutomationAccountName "aa-device-cleanup-prod" -Name "WeeklyDeviceCleanup" -IsEnabled $false
   ```

2. **Stop Running Jobs**
   ```powershell
   Get-AzAutomationJob -ResourceGroupName "rg-automation-prod" -AutomationAccountName "aa-device-cleanup-prod" -Status Running | Stop-AzAutomationJob
   ```

3. **Notify Stakeholders**
   - Send immediate email to admin distribution list
   - Update incident tracking system
   - Escalate to management if business impact

### Device Recovery Procedures
1. **Restore from Entra ID Recycle Bin** (within 30 days)
   ```powershell
   # Connect to Graph
   Connect-MgGraph -Scopes "Directory.ReadWrite.All"
   
   # List deleted devices
   Get-MgDirectoryDeletedItem -DirectoryObjectType "device"
   
   # Restore specific device
   Restore-MgDirectoryDeletedItem -DirectoryObjectId "device-id"
   ```

2. **Re-register Devices** (if needed)
   - Provide self-service instructions to users
   - Deploy through Intune if applicable
   - Manual registration for critical systems

## 📋 Validation Checklist

### Post-Deployment Validation
- [ ] First execution completed successfully
- [ ] CSV reports generated and accessible
- [ ] Email notifications sent to administrators
- [ ] Audit logs captured in Log Analytics
- [ ] No unexpected device deletions occurred
- [ ] Safety thresholds worked as expected
- [ ] Exclusion lists honored correctly
- [ ] Performance metrics within acceptable range

### Weekly Operational Checks
- [ ] Review execution status and duration
- [ ] Validate device counts and trends
- [ ] Check for any failed operations
- [ ] Review excluded device list for updates
- [ ] Monitor for security or compliance issues
- [ ] Update documentation if needed

## 📞 Support Contacts

### Escalation Matrix
| Issue Type | Primary Contact | Secondary Contact | Escalation |
|------------|----------------|-------------------|------------|
| Technical Failures | IT Operations | Platform Team | Engineering Manager |
| Security Incidents | InfoSec Team | CISO | C-Level Executive |
| Business Impact | Service Owner | Business Unit | VP/Director |
| Compliance Issues | Compliance Team | Legal | Chief Compliance Officer |

### Contact Information
- **24/7 Operations**: operations@company.com
- **Security Hotline**: security@company.com  
- **Emergency Escalation**: +1-XXX-XXX-XXXX

---

**Note**: This deployment guide should be customized for your specific environment and organizational requirements. Always test thoroughly in non-production environments first.