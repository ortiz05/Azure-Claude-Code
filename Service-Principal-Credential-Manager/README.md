# Service Principal Credential Manager

Enterprise-grade automation for monitoring, assessing, and managing Azure Service Principal credentials at scale.

## 📋 Overview

This automation addresses one of the most critical Azure security risks: expired or poorly managed Service Principal credentials that can lead to service disruptions, security vulnerabilities, and compliance violations. It provides comprehensive credential lifecycle management with risk-based prioritization and automated remediation capabilities.

## ✨ Key Features

- **Comprehensive Credential Discovery**
  - Scans all Service Principals across Azure AD tenant
  - Inventories both certificate and secret-based credentials
  - Tracks creation dates, expiration dates, and credential age

- **Advanced Risk Assessment**
  - Multi-factor risk scoring algorithm
  - Correlates credential status with application usage
  - Prioritizes critical security combinations (expired + unused)

- **Enterprise Reporting Suite**
  - Executive dashboard with security posture metrics
  - Detailed CSV reports for security team analysis
  - Professional HTML email alerts for critical issues
  - Compliance documentation for SOC2/SOX audits

- **Automated Remediation Framework**
  - Safe credential cleanup for unused applications
  - Renewal workflow orchestration
  - DevOps pipeline integration hooks
  - Complete audit logging for compliance

- **Usage Pattern Analysis**
  - Integrates with Azure AD audit logs
  - Identifies unused vs. active Service Principals
  - Tracks sign-in patterns for risk assessment

## 📁 Project Structure

```
Service-Principal-Credential-Manager/
├── Documentation/
│   └── CLAUDE.md                                    # AI implementation guidelines
├── Scripts/
│   └── ServicePrincipalCredentialManager.ps1       # Main automation script
├── Templates/
│   ├── CriticalCredentialAlert.html                # Critical security alert template
│   └── ExecutiveSummaryReport.html                 # Executive dashboard template
├── Tests/
│   └── Test-ServicePrincipalConnection.ps1         # Connection & permission testing
└── Reports/                                        # Generated reports directory
```

## 🚀 Quick Start

### Prerequisites

1. **Azure Resources**
   - Azure Automation Account (for production)
   - Service Principal or Managed Identity with required permissions

2. **Required Microsoft Graph Permissions**
   - Application.Read.All (required)
   - Application.ReadWrite.All (for automated remediation)
   - Directory.Read.All (required)
   - AuditLog.Read.All (for usage analysis)
   - Mail.Send (for notifications)

3. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

1. **Test Connection and Permissions**
   ```powershell
   .\Tests\Test-ServicePrincipalConnection.ps1
   ```

2. **Run Security Assessment (Simulation Mode)**
   ```powershell
   .\Scripts\ServicePrincipalCredentialManager.ps1 `
       -WhatIf `
       -IncludeUsageAnalysis `
       -GenerateExecutiveSummary
   ```

3. **Production Execution with Notifications**
   ```powershell
   .\Scripts\ServicePrincipalCredentialManager.ps1 `
       -CriticalThresholdDays 7 `
       -WarningThresholdDays 30 `
       -SecurityTeamEmails @("security@company.com") `
       -ITAdminEmails @("itadmin@company.com") `
       -SendNotifications `
       -EnableAutomatedRemediation:$false
   ```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| TenantId | String | $env:AZURE_TENANT_ID | Azure AD tenant identifier |
| ClientId | String | $env:AZURE_CLIENT_ID | Service Principal client ID |
| ClientSecret | String | $env:AZURE_CLIENT_SECRET | Service Principal secret (testing only) |
| CriticalThresholdDays | Int | 7 | Days threshold for critical alerts |
| WarningThresholdDays | Int | 30 | Days threshold for warning alerts |
| PlanningThresholdDays | Int | 90 | Days threshold for planning alerts |
| LongLivedThresholdDays | Int | 365 | Days threshold for long-lived credential warnings |
| ExcludeServicePrincipals | String[] | @() | Service Principal names/IDs to exclude |
| ReportPath | String | ".\Reports" | Output directory for reports |
| NotificationEmailFrom | String | $env:NOTIFICATION_EMAIL_FROM | Email sender address |
| SecurityTeamEmails | String[] | @() | Security team notification emails |
| ITAdminEmails | String[] | @() | IT admin notification emails |
| WhatIf | Switch | True | Simulation mode (safe default) |
| EnableAutomatedRemediation | Switch | False | Enable automatic credential cleanup |
| SendNotifications | Switch | True | Send email notifications |
| IncludeUsageAnalysis | Switch | True | Analyze Service Principal usage patterns |
| GenerateExecutiveSummary | Switch | True | Generate executive dashboard report |

## 🎯 Risk Assessment Framework

### Risk Levels

| Risk Level | Criteria | Action Required |
|------------|----------|-----------------|
| **Critical** | Expired credentials on unused applications | Immediate (24 hours) |
| **High** | Expired credentials on active apps, expires in ≤7 days | Urgent (this week) |
| **Medium** | Long-lived secrets (>365 days), expires in ≤30 days | Planned (30 days) |
| **Low** | Well-managed credentials with proper rotation | Monitor |

### Risk Factors

- **Expired**: Credential has passed expiration date
- **Expires Soon**: Credential expires within threshold period
- **Long-Lived**: Credential age exceeds organizational policy
- **Unused**: No sign-in activity in past 90 days
- **Secret Type**: Secret vs. certificate preference policies

## 📈 Generated Reports

The automation generates comprehensive reporting suite:

### 1. Detailed Credential Report
**File**: `ServicePrincipal-Credentials-Detailed-[timestamp].csv`
- Complete credential inventory with risk assessment
- Usage patterns and last sign-in information
- Risk factors and recommended actions

### 2. Service Principal Summary
**File**: `ServicePrincipal-Summary-[timestamp].csv`
- Per-application risk summary
- Credential counts by type and status
- Recommended action prioritization

### 3. Executive Summary Dashboard
**File**: `ServicePrincipal-Executive-Summary-[timestamp].json`
- High-level security metrics
- Risk distribution and trends
- Compliance status indicators

### 4. Remediation Activity Log
**File**: `Remediation-Actions-[timestamp].csv`
- All automated and manual actions taken
- Audit trail for compliance documentation

## 🔧 Automated Remediation

### Safe Remediation Actions

1. **Expired Unused Credentials**
   - Automatically disable expired credentials on unused Service Principals
   - Requires confirmation in production mode
   - Full audit logging of all actions

2. **Renewal Orchestration**
   - Triggers certificate renewal workflows
   - Integrates with Azure Key Vault for secret rotation
   - Coordinates with DevOps pipelines

3. **Risk Mitigation**
   - Flags high-risk combinations for manual review
   - Generates action plans with business context
   - Provides rollback capabilities

### Safety Mechanisms

- **WhatIf Mode**: Enabled by default, shows proposed actions without execution
- **Confirmation Required**: Explicit approval needed for destructive operations
- **Exclusion Lists**: Protect critical Service Principals from automated changes
- **Rollback Support**: Ability to reverse automated actions if needed

## 🔄 Deployment to Azure Automation

### 1. Create Automation Account Resources

```powershell
# Create Runbook
New-AzAutomationRunbook `
    -Name "ServicePrincipalCredentialManager" `
    -Type PowerShell `
    -ResourceGroupName "YourRG" `
    -AutomationAccountName "YourAutomation"
```

### 2. Configure Managed Identity

```powershell
# Enable system-assigned managed identity
Set-AzAutomationAccount `
    -ResourceGroupName "YourRG" `
    -Name "YourAutomation" `
    -AssignSystemIdentity
```

### 3. Grant Required Permissions

```bash
# Using Azure CLI
az ad app permission add --id <managed-identity-id> --api 00000003-0000-0000-c000-000000000000 --api-permissions Application.Read.All=Role
az ad app permission grant --id <managed-identity-id> --api 00000003-0000-0000-c000-000000000000 --scope Application.Read.All
```

### 4. Schedule Execution

- **Recommended**: Daily execution for critical monitoring
- **Suggested time**: 6:00 AM local time (before business hours)
- **Parameters**: Configure appropriate thresholds for your environment

## 📊 Sample Output

```
==========================================
Service Principal Credential Manager
Enterprise Security Automation
==========================================
Tenant ID: contoso.onmicrosoft.com
Report Path: .\Reports
WhatIf Mode: True
Automated Remediation: False
==========================================

Validating Microsoft Graph permissions...
  ✓ Granted: Application.Read.All
  ✓ Granted: Directory.Read.All
  ✓ Granted: AuditLog.Read.All
  ✓ Granted: Mail.Send
✓ All required permissions validated

Scanning Service Principal credentials...
Found 247 Service Principals
✓ Found 1,156 credentials across 247 Service Principals

Analyzing Service Principal usage patterns...
Analyzed usage for 247/247 applications...
✓ Usage analysis completed for 189 applications

Calculating credential risk levels...
✓ Risk assessment completed:
  Critical: 12
  High: 28
  Medium: 45
  Low: 1,071

📊 Executive Summary:
  Total Service Principals: 247
  Total Credentials: 1,156
  Expired Credentials: 34
  Critical Risk: 12
  High Risk: 28
  Expiring in 7 days: 8
  Expiring in 30 days: 23

🚨 CRITICAL: Immediate action required for 12 credentials!
📁 Reports generated in: .\Reports
```

## 🛡️ Security Best Practices

### 1. Authentication Security
- **Production**: Use managed identity (never hardcode credentials)
- **Testing**: Use environment variables for Service Principal authentication
- **Credential Storage**: Store secrets in Azure Key Vault with proper access controls

### 2. Permission Management
- **Least Privilege**: Only grant Application.ReadWrite.All if automated remediation is required
- **Regular Review**: Audit automation permissions quarterly
- **Access Control**: Restrict report access to authorized security personnel

### 3. Monitoring and Alerting
- **Critical Alerts**: Immediate notification for expired credentials on active applications
- **Trend Monitoring**: Track credential health improvements over time
- **Compliance Tracking**: Regular reports for audit and governance requirements

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied errors | Verify Graph API permissions and admin consent |
| No Service Principals found | Check Application.Read.All permission |
| Usage analysis fails | Verify AuditLog.Read.All permission and data availability |
| Email notifications not sent | Check Mail.Send permission and SMTP configuration |
| Automation timeouts | Increase Azure Automation job timeout for large tenants |
| Missing credentials in reports | Verify Service Principal has certificates or secrets configured |

## 📊 Performance Considerations

### Large Tenant Optimization
- **Batch Processing**: Processes Service Principals in batches of 50
- **Progress Tracking**: Real-time progress updates during execution
- **Memory Management**: Efficient object handling for large datasets
- **Timeout Handling**: Graceful handling of API rate limits

### Recommended Schedules
- **Critical Monitoring**: Daily execution for immediate security issues
- **Compliance Reporting**: Weekly executive summaries
- **Trend Analysis**: Monthly comprehensive assessments

## 🔗 Integration Opportunities

### DevOps Pipeline Integration
```powershell
# Example: Trigger certificate renewal pipeline
if ($Credential.RiskLevel -eq "High" -and $Credential.CredentialType -eq "Certificate") {
    # Invoke Azure DevOps REST API to trigger renewal pipeline
    $PipelineUri = "https://dev.azure.com/{organization}/{project}/_apis/pipelines/{pipelineId}/runs"
    # Implementation details...
}
```

### SIEM Integration
- Export security events to Splunk, Sentinel, or other SIEM platforms
- Custom metrics for security dashboards
- Automated incident creation for critical findings

### ServiceNow Integration
- Automated ticket creation for manual intervention requirements
- Integration with ITSM workflows for credential renewal processes

## 📝 Best Practices

1. **Start with Conservative Settings**
   - Begin with longer threshold periods (90+ days)
   - Enable WhatIf mode for initial runs
   - Gradually reduce thresholds based on organizational comfort

2. **Establish Clear Governance**
   - Define credential rotation policies
   - Assign ownership for Service Principal management
   - Create escalation procedures for critical findings

3. **Regular Review Processes**
   - Weekly review of high-risk credentials
   - Monthly executive summary review
   - Quarterly automation configuration review

4. **Incident Response Preparation**
   - Document procedures for expired credential incidents
   - Maintain emergency contact lists
   - Test restoration procedures regularly

## 🔗 Related Documentation

- [AI Implementation Guidelines](./Documentation/CLAUDE.md)
- [Enterprise Security Architecture Overview](../Claude.md)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph)
- [Azure Service Principal Best Practices](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)

## 📧 Support and Maintenance

### Regular Maintenance Tasks
1. **Monthly**: Review exclusion lists and thresholds
2. **Quarterly**: Validate automation permissions and access
3. **Annually**: Update risk assessment criteria based on security posture

### Troubleshooting Resources
1. Check Azure Automation job execution logs
2. Verify Microsoft Graph API permissions in Azure Portal
3. Review generated CSV reports for detailed error information
4. Consult the troubleshooting section above for common issues

### Enhancement Requests
Consider implementing additional features based on organizational needs:
- Certificate Authority (CA) integration for automated renewal
- Integration with privileged access management (PAM) solutions
- Advanced analytics and machine learning for risk prediction
- Custom risk scoring based on application criticality