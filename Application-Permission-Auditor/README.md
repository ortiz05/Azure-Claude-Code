# Application Permission Auditor

Enterprise-grade automation for comprehensive application permission governance, compliance monitoring, and over-privilege detection across Microsoft Azure environments.

## 📋 Overview

This automation addresses critical enterprise security risks by analyzing Microsoft Graph API permissions across all Enterprise Applications. It identifies over-privileged applications, monitors OAuth consent patterns, and enforces principle of least privilege to prevent security breaches through application permission abuse.

## ✨ Key Features

- **Comprehensive Permission Discovery**
  - Scans all Enterprise Applications and Service Principals
  - Analyzes both Application permissions (app-to-app) and Delegated permissions (user-to-app)
  - Maps OAuth2 permission grants with consent type analysis
  - Identifies permissions across Microsoft Graph, SharePoint, Exchange, and third-party APIs

- **Advanced Risk Assessment Framework**
  - Multi-factor risk scoring based on privilege level, scope, usage patterns, and application age
  - Detects over-privileged applications violating principle of least privilege
  - Identifies unused applications with dangerous permissions (critical attack vectors)
  - Monitors admin consent compliance and governance violations

- **Enterprise Governance Reporting**
  - Executive security dashboards with permission risk summaries
  - Detailed CSV reports for security team analysis and remediation
  - High-risk permission alerts with professional HTML email templates
  - SOC2/SOX compliance documentation with audit trails

- **Permission Usage Analysis**
  - Cross-references permission grants with actual application usage patterns
  - Identifies shadow IT applications through OAuth consent analysis
  - Tracks permission trends and governance improvements over time
  - Provides business context for permission risk assessment

## 📁 Project Structure

```
Application-Permission-Auditor/
├── Documentation/
│   └── CLAUDE.md                                # AI implementation guidelines
├── Scripts/
│   └── ApplicationPermissionAuditor.ps1        # Main automation script
├── Templates/
│   ├── HighRiskPermissionAlert.html            # Critical security alert template
│   └── PermissionAuditExecutiveSummary.html    # Executive dashboard template
├── Tests/
│   └── Test-PermissionAuditorConnection.ps1    # Connection & permission testing
├── Azure-Automation/
│   ├── Deploy-ApplicationPermissionAuditor.ps1 # Azure Automation deployment
│   └── README.md                               # Deployment instructions
└── Reports/                                    # Generated reports directory
```

## 🚀 Quick Start

### Prerequisites

1. **Azure Resources**
   - Azure Automation Account (for production)
   - Service Principal or Managed Identity with required permissions

2. **Required Microsoft Graph Permissions**
   - Application.Read.All (required)
   - Directory.Read.All (required)
   - DelegatedPermissionGrant.Read.All (required - OAuth consent analysis)
   - AppRoleAssignment.Read.All (required - application permission analysis)
   - AuditLog.Read.All (for usage analysis)
   - Mail.Send (for notifications)

3. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

1. **Test Connection and Permissions**
   ```powershell
   .\Tests\Test-PermissionAuditorConnection.ps1
   ```

2. **Run Permission Security Assessment (Simulation Mode)**
   ```powershell
   .\Scripts\ApplicationPermissionAuditor.ps1 `
       -WhatIf `
       -IncludeOAuthConsents `
       -GenerateExecutiveSummary
   ```

3. **Production Execution with Governance Monitoring**
   ```powershell
   .\Scripts\ApplicationPermissionAuditor.ps1 `
       -SecurityTeamEmails @("security@company.com") `
       -ITAdminEmails @("itadmin@company.com") `
       -SendNotifications `
       -AnalyzePermissionTrends
   ```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| TenantId | String | $env:AZURE_TENANT_ID | Azure AD tenant identifier |
| ClientId | String | $env:AZURE_CLIENT_ID | Service Principal client ID |
| ClientSecret | String | $env:AZURE_CLIENT_SECRET | Service Principal secret (testing only) |
| ExcludeApplications | String[] | @() | Application names/IDs to exclude from analysis |
| ReportPath | String | ".\Reports" | Output directory for reports |
| NotificationEmailFrom | String | $env:NOTIFICATION_EMAIL_FROM | Email sender address |
| SecurityTeamEmails | String[] | @() | Security team notification emails |
| ITAdminEmails | String[] | @() | IT admin notification emails |
| WhatIf | Switch | True | Simulation mode (safe default) |
| SendNotifications | Switch | True | Send email notifications |
| IncludeOAuthConsents | Switch | True | Analyze OAuth2 delegated permissions |
| GenerateExecutiveSummary | Switch | True | Generate executive dashboard |
| AnalyzePermissionTrends | Switch | True | Include usage pattern analysis |
| HighRiskPermissions | String[] | Predefined list | Custom high-risk permission definitions |
| AdminConsentRequiredPermissions | String[] | Predefined list | Permissions requiring admin consent |

## 🎯 Risk Assessment Framework

### Risk Levels

| Risk Level | Criteria | Action Required |
|------------|----------|-----------------|
| **Critical** | High-risk app permissions on unused applications | Immediate (24 hours) |
| **High** | Dangerous permissions (Directory.ReadWrite.All, etc.) | Urgent (this week) |
| **Medium** | Broad scope permissions, admin consent violations | Planned (30 days) |
| **Low** | Standard delegated permissions with appropriate scope | Monitor |

### High-Risk Permissions (Default Detection)

- **Directory.ReadWrite.All**: Full directory control
- **User.ReadWrite.All**: Modify any user account
- **Application.ReadWrite.All**: Create/modify applications
- **RoleManagement.ReadWrite.Directory**: Assign admin roles
- **Sites.FullControl.All**: Complete SharePoint access
- **AppRoleAssignment.ReadWrite.All**: Modify application permissions
- **Device.ReadWrite.All**: Device management control
- **Policy.ReadWrite.All**: Modify organizational policies

### Risk Factors

- **Over-Privileged**: Applications with excessive permissions beyond business needs
- **Unused Application**: No sign-in activity in past 90 days with dangerous permissions
- **Broad Scope**: Permissions with keywords like "All", "ReadWrite", "FullControl"
- **Admin Consent Required**: Permissions requiring admin consent without proper governance
- **Legacy Application**: Applications older than 365 days with powerful permissions
- **Microsoft Graph API**: Extensive access to Microsoft Graph endpoints

## 📈 Generated Reports

### 1. Detailed Permission Report
**File**: `Application-Permissions-Detailed-[timestamp].csv`
- Complete permission inventory with risk assessment
- OAuth consent analysis and usage patterns
- Risk factors and recommended actions for each permission

### 2. Application Summary Report
**File**: `Application-Summary-[timestamp].csv`
- Per-application permission risk summary
- Aggregated metrics by application
- Recommended action prioritization

### 3. High-Risk Permissions Report
**File**: `High-Risk-Permissions-[timestamp].csv`
- Focused analysis of critical and high-risk permissions
- Prioritized list for immediate security review

### 4. Executive Summary Dashboard
**File**: `Permission-Audit-Executive-Summary-[timestamp].json`
- High-level governance metrics for leadership
- Risk distribution and compliance trends
- Top security findings and recommendations

## 🛡️ Security Best Practices

### 1. Permission Governance
- **Principle of Least Privilege**: Regularly review and remove unnecessary permissions
- **Admin Consent Process**: Implement formal approval workflows for high-risk permissions
- **Regular Audits**: Schedule quarterly comprehensive permission reviews

### 2. Risk Mitigation
- **Critical Risk Response**: Immediate review of unused applications with dangerous permissions
- **Legacy Application Assessment**: Prioritize review of older applications with broad permissions
- **Shadow IT Detection**: Monitor unauthorized applications through OAuth consent analysis

### 3. Compliance Monitoring
- **SOC2/SOX Documentation**: Maintain audit trails for all permission governance decisions
- **Continuous Monitoring**: Set up automated alerting for new high-risk permission grants
- **Executive Reporting**: Regular governance summaries for leadership oversight

## 🔄 Deployment to Azure Automation

### Quick Deployment
```powershell
# Navigate to Azure Automation deployment
cd .\Azure-Automation\

# Run deployment script
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-rg" `
    -AutomationAccountName "your-automation-account"
```

### Manual Setup
1. **Create Runbook**
   ```powershell
   New-AzAutomationRunbook `
       -Name "ApplicationPermissionAuditor" `
       -Type PowerShell `
       -ResourceGroupName "YourRG" `
       -AutomationAccountName "YourAutomation"
   ```

2. **Configure Managed Identity**
   - Enable system-assigned managed identity
   - Grant required Microsoft Graph permissions

3. **Schedule Execution**
   - Recommended: Weekly execution for governance monitoring
   - Suggested time: 6:00 AM local time (before business hours)

## 📊 Sample Output

```
==========================================
Application Permission Auditor
Enterprise Security & Compliance Automation
==========================================
Tenant ID: contoso.onmicrosoft.com
WhatIf Mode: True
Include OAuth Consents: True
==========================================

Validating Microsoft Graph permissions...
  ✓ Granted: Application.Read.All
  ✓ Granted: DelegatedPermissionGrant.Read.All
  ✓ Granted: AppRoleAssignment.Read.All
  ✓ Granted: AuditLog.Read.All
✓ All required permissions validated

Scanning Enterprise Applications and permissions...
Found 156 Enterprise Applications
✓ Found 2,847 permissions across 156 applications

Analyzing permission risk levels...
✓ Risk assessment completed:
  Critical: 23
  High: 87
  Medium: 341
  Low: 2,396

📊 Executive Summary:
  Total Applications: 156
  Total Permissions: 2,847
  Critical Risk: 23
  High Risk: 87
  Application Permissions: 445
  Admin Consent Required: 234
  Microsoft Graph Permissions: 1,923

🚨 CRITICAL: Immediate security review required for 23 permissions!

📁 Reports generated in: .\Reports
```

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied errors | Verify Graph API permissions and admin consent |
| No applications found | Check Application.Read.All permission |
| OAuth consent analysis fails | Verify DelegatedPermissionGrant.Read.All permission |
| App role assignment errors | Check AppRoleAssignment.Read.All permission |
| Usage analysis fails | Verify AuditLog.Read.All permission and data availability |
| Missing critical permissions in results | Review high-risk permission configuration |

## 🔧 Advanced Configuration

### Custom High-Risk Permissions
```powershell
$CustomHighRiskPermissions = @(
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "YourCustom.Permission.All"
)

.\Scripts\ApplicationPermissionAuditor.ps1 `
    -HighRiskPermissions $CustomHighRiskPermissions
```

### Large Tenant Optimization
- **Batch Processing**: Processes applications in batches of 25
- **Progress Tracking**: Real-time progress updates during execution
- **Memory Management**: Efficient object handling for large datasets
- **Timeout Handling**: Graceful handling of API rate limits

## 📝 Best Practices

1. **Start with Assessment Mode**
   - Begin with WhatIf mode to understand current permission landscape
   - Review generated reports before implementing governance changes
   - Validate high-risk permission definitions for your environment

2. **Establish Clear Governance**
   - Define application permission approval policies
   - Assign ownership for application permission management
   - Create escalation procedures for critical permission findings

3. **Regular Review Processes**
   - Weekly review of critical and high-risk permissions
   - Monthly executive summary review with governance metrics
   - Quarterly comprehensive permission audit and policy review

4. **Integration with Security Operations**
   - Export high-risk findings to SIEM platforms
   - Create automated tickets for permission review requirements
   - Integrate with incident response procedures for critical findings

## 🔗 Related Documentation

- [AI Implementation Guidelines](./Documentation/CLAUDE.md)
- [Azure Automation Deployment Guide](./Azure-Automation/README.md)
- [Enterprise Security Architecture Overview](../Claude.md)
- [Microsoft Graph Permissions Reference](https://docs.microsoft.com/graph/permissions-reference)

## 📧 Support and Maintenance

### Regular Maintenance Tasks
1. **Monthly**: Review high-risk permission configurations and exclusion lists
2. **Quarterly**: Validate automation permissions and access controls
3. **Annually**: Update risk assessment criteria based on evolving security landscape

### Troubleshooting Resources
1. Check Azure Automation job execution logs for detailed error information
2. Verify Microsoft Graph API permissions in Azure Portal
3. Review generated CSV reports for permission-specific error details
4. Consult the troubleshooting section above for common issues

### Enhancement Opportunities
- **Real-Time Monitoring**: Continuous monitoring of new permission grants
- **Machine Learning Integration**: Advanced analytics for permission risk prediction
- **Automated Remediation**: Integration with approval workflows for permission reduction
- **Regulatory Compliance**: Enhanced reporting for industry-specific compliance requirements