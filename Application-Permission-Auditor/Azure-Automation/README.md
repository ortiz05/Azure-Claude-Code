# Azure Automation Deployment - Application Permission Auditor

This directory contains the deployment scripts and configuration for running the Application Permission Auditor in Azure Automation.

## 📋 Overview

Azure Automation provides a cloud-based automation platform for running the Application Permission Auditor on a scheduled basis. This deployment configures:

- **Runbook Creation**: PowerShell runbook for the main automation
- **Module Installation**: Required Microsoft Graph PowerShell modules
- **Managed Identity**: System-assigned identity for secure authentication
- **Scheduled Execution**: Weekly execution schedule
- **Monitoring Integration**: Azure Monitor integration for alerting

## 🚀 Quick Deployment

### Prerequisites

1. **Azure Resources**
   - Azure subscription with Contributor access
   - Resource group for the Automation Account
   - Azure Automation Account (will be validated during deployment)

2. **PowerShell Requirements**
   ```powershell
   # Install required PowerShell modules
   Install-Module Az.Automation -Scope CurrentUser
   Install-Module Az.Accounts -Scope CurrentUser
   ```

3. **Permissions**
   - Contributor access to the Azure subscription
   - Ability to assign permissions to managed identities

### Basic Deployment

```powershell
# Deploy with minimal configuration
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account"
```

### Production Deployment

```powershell
# Deploy with full configuration
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-security-automation" `
    -AutomationAccountName "aa-security-automation" `
    -SecurityTeamEmails @("security@company.com", "compliance@company.com") `
    -ITAdminEmails @("itadmin@company.com") `
    -NotificationEmailFrom "automation@company.com" `
    -ScheduleName "ApplicationPermissionAuditor-Weekly" `
    -StartTime "06:00:00" `
    -TimeZone "Eastern Standard Time" `
    -EnableSchedule
```

## 📊 Deployment Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| SubscriptionId | String | Yes | - | Azure subscription ID |
| ResourceGroupName | String | Yes | - | Resource group containing Automation Account |
| AutomationAccountName | String | Yes | - | Name of the Azure Automation Account |
| RunbookName | String | No | ApplicationPermissionAuditor | Name for the created runbook |
| ScheduleName | String | No | ApplicationPermissionAuditor-Weekly | Name for the execution schedule |
| StartTime | String | No | 06:00:00 | Daily start time for execution |
| TimeZone | String | No | UTC | Time zone for schedule |
| SecurityTeamEmails | String[] | No | @() | Email addresses for security team notifications |
| ITAdminEmails | String[] | No | @() | Email addresses for IT admin notifications |
| NotificationEmailFrom | String | No | "" | Sender email address |
| EnableSchedule | Switch | No | True | Create and enable execution schedule |
| WhatIf | Switch | No | False | Preview changes without executing |

## 🔧 Post-Deployment Configuration

### 1. Configure Managed Identity Permissions

After deployment, the managed identity needs Microsoft Graph API permissions:

```powershell
# Get the managed identity Object ID from Azure Portal
$ManagedIdentityObjectId = "12345678-1234-1234-1234-123456789012"

# Required Microsoft Graph permissions
$RequiredPermissions = @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All", 
    "AppRoleAssignment.ReadWrite.All",
    "AuditLog.Read.All",
    "Mail.Send"
)

# Grant permissions using Azure CLI
foreach ($Permission in $RequiredPermissions) {
    az ad app permission add --id $ManagedIdentityObjectId --api 00000003-0000-0000-c000-000000000000 --api-permissions "$Permission=Role"
}

# Grant admin consent
az ad app permission grant --id $ManagedIdentityObjectId --api 00000003-0000-0000-c000-000000000000
```

### 2. Verify Module Installation

Monitor module installation progress:

1. Go to **Azure Portal** → **Automation Account** → **Modules**
2. Wait for all modules to show **"Available"** status (15-30 minutes)
3. Required modules:
   - Microsoft.Graph.Authentication
   - Microsoft.Graph.Applications
   - Microsoft.Graph.Identity.SignIns
   - Microsoft.Graph.Reports
   - Microsoft.Graph.Mail

### 3. Test the Runbook

```powershell
# Test in Azure Portal
# 1. Go to Automation Account → Runbooks → ApplicationPermissionAuditor
# 2. Click "Test pane"
# 3. Set parameters:
#    - WhatIf: true (for safe testing)
#    - IncludeOAuthConsents: true
#    - GenerateExecutiveSummary: true
# 4. Click "Start" and monitor output
```

## 📅 Schedule Configuration

### Default Schedule
- **Frequency**: Weekly
- **Start Time**: 06:00:00 UTC (configurable)
- **Days**: Every 7 days from start date
- **Next Run**: Tomorrow at specified start time

### Custom Schedule Examples

```powershell
# Daily execution
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -ScheduleName "ApplicationPermissionAuditor-Daily" `
    -StartTime "02:00:00" # 2 AM daily

# Bi-weekly execution
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -ScheduleName "ApplicationPermissionAuditor-BiWeekly" `
    -StartTime "06:00:00" # Every 14 days
```

## 🔄 Maintenance and Updates

### Updating the Runbook

```powershell
# Redeploy with new configuration
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -SecurityTeamEmails @("security@company.com", "newsecurity@company.com")
```

### Module Updates

```powershell
# Update Microsoft Graph modules to latest versions
$ModulesToUpdate = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.SignIns"
)

foreach ($Module in $ModulesToUpdate) {
    Import-AzAutomationModule -ResourceGroupName "your-rg" `
        -AutomationAccountName "your-aa" `
        -Name $Module
}
```

## 📊 Monitoring and Alerting

### Job Monitoring

Monitor runbook execution:

1. **Azure Portal** → **Automation Account** → **Jobs**
2. Filter by runbook name: `ApplicationPermissionAuditor`
3. Review job status and output logs

### Azure Monitor Integration

```powershell
# Example: Create alert for failed runbook jobs
New-AzMetricAlertRuleV2 `
    -ResourceGroupName "your-rg" `
    -Name "ApplicationPermissionAuditor-FailureAlert" `
    -TargetResourceId "/subscriptions/your-sub/resourceGroups/your-rg/providers/Microsoft.Automation/automationAccounts/your-aa" `
    -MetricName "TotalJob" `
    -Operator GreaterThan `
    -Threshold 0 `
    -WindowSize "PT5M" `
    -Frequency "PT1M" `
    -Severity 2
```

## 🔍 Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Authentication failures | Managed identity permissions not granted | Follow post-deployment permission configuration |
| Module import errors | Modules not fully installed | Wait for installation completion, check Modules blade |
| Schedule not triggering | Incorrect time zone or start time | Verify schedule configuration in Automation Account |
| Empty reports | Insufficient Graph API permissions | Verify all required permissions are granted |
| Email failures | Mail.Send permission missing | Grant Mail.Send permission to managed identity |

### Debug Mode

Run in debug mode for detailed troubleshooting:

```powershell
# Deploy with additional logging
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -AutomationAccountName "your-automation-account" `
    -WhatIf -Verbose
```

### Log Analysis

Check runbook execution logs:

1. **Azure Portal** → **Automation Account** → **Jobs**
2. Select the specific job execution
3. Review **Output** and **Errors** tabs
4. Check **All Logs** for detailed execution flow

## 🔐 Security Considerations

### Managed Identity Best Practices

1. **Least Privilege**: Only grant required Microsoft Graph permissions
2. **Regular Review**: Audit managed identity permissions quarterly
3. **Access Control**: Restrict access to Automation Account resources
4. **Monitoring**: Enable Azure AD sign-in logs for managed identity

### Data Protection

1. **Report Storage**: Configure secure storage for generated reports
2. **Email Security**: Use secure email configurations for notifications
3. **Access Logs**: Enable audit logging for all automation activities
4. **Compliance**: Ensure deployment meets organizational security requirements

## 📝 Best Practices

### Production Deployment

1. **Environment Separation**: Use separate Automation Accounts for dev/test/prod
2. **Resource Naming**: Use consistent naming conventions
3. **Tagging**: Apply appropriate Azure resource tags
4. **Backup**: Implement backup strategies for runbook configurations

### Performance Optimization

1. **Module Management**: Keep modules updated but test changes in non-production first
2. **Schedule Optimization**: Avoid peak business hours for execution
3. **Resource Sizing**: Monitor Automation Account usage and scale as needed
4. **Parallel Processing**: Consider multiple smaller automation accounts for large tenants

### Compliance and Governance

1. **Documentation**: Maintain deployment documentation
2. **Change Management**: Use version control for deployment scripts
3. **Audit Trail**: Maintain logs of all configuration changes
4. **Review Process**: Implement regular review of automation configurations

## 🔗 Related Resources

- [Azure Automation Documentation](https://docs.microsoft.com/en-us/azure/automation/)
- [Microsoft Graph PowerShell SDK](https://docs.microsoft.com/en-us/powershell/microsoftgraph/)
- [Azure Managed Identity Documentation](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
- [Application Permission Auditor Main Documentation](../README.md)