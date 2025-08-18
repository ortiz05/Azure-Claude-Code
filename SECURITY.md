# Security Guidelines for Azure Automation Scripts

## 🔐 Security Overview

This repository contains production-ready Azure automation scripts that handle sensitive organizational data and perform potentially destructive operations. All scripts have been designed with security-first principles.

## 🛡️ Security Measures Implemented

### Authentication & Authorization
- **Managed Identity Support**: Primary authentication method for production
- **Least Privilege Access**: Scripts request only required permissions
- **Permission Validation**: Runtime verification of required permissions
- **No Hardcoded Credentials**: All sensitive data sourced from secure stores

### Data Protection
- **Encryption at Rest**: All reports and backups should be stored encrypted
- **Data Minimization**: Only necessary data is collected and retained
- **PII Handling**: Personal information is handled according to privacy policies
- **Audit Trails**: Comprehensive logging of all operations

### Operational Security
- **Safety Thresholds**: Built-in limits prevent accidental mass operations
- **WhatIf Mode**: Mandatory testing mode for validation
- **Input Validation**: All parameters validated before processing
- **Error Handling**: Secure error reporting without credential exposure

### Code Security
- **Static Analysis**: Scripts follow PowerShell security best practices
- **Dependency Management**: Only trusted Microsoft modules used
- **Version Control**: All changes tracked and reviewed
- **Access Control**: Repository access limited to authorized personnel
- **Automated Validation**: All scripts validated before commit with comprehensive checks
- **Security Scanning**: Continuous security analysis for vulnerabilities and hardcoded credentials

## 🔍 Security Checklist

Before deploying any automation to production:

### Pre-Deployment
- [ ] **Run credential scan** - Execute `Scripts/Validate-PowerShellScripts.ps1` and ensure NO hardcoded credentials detected
- [ ] **Run PowerShell validation script** - Execute `Scripts/Validate-PowerShellScripts.ps1` and ensure all checks pass
- [ ] **Review PSScriptAnalyzer results** - Address all errors and critical warnings
- [ ] **Validate syntax and parsing** - Ensure scripts can be parsed without errors
- [ ] **Check error handling** - Verify comprehensive try-catch blocks and ErrorAction parameters
- [ ] **Security scan results** - Confirm no hardcoded credentials or unsafe operations
- [ ] Review all parameters and their validation
- [ ] Verify permission requirements are minimal
- [ ] Test in isolated development environment
- [ ] Validate safety thresholds are appropriate
- [ ] Confirm logging captures necessary audit information
- [ ] Review exclusion lists for completeness

### During Deployment
- [ ] Use managed identity for authentication
- [ ] Configure Azure Key Vault for any secrets
- [ ] Enable Azure Monitor logging
- [ ] Set up appropriate RBAC permissions
- [ ] Configure network restrictions if applicable
- [ ] Test WhatIf mode in production tenant

### Post-Deployment
- [ ] Monitor initial executions closely
- [ ] Review generated audit logs
- [ ] Validate email notifications are working
- [ ] Confirm backup files are created and secured
- [ ] Set up alerting for failures or anomalies
- [ ] Document any customizations made

## 🚨 Risk Assessment

### Device Cleanup Automation Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Accidental mass deletion | Low | High | Safety thresholds, WhatIf mode, exclusion lists |
| Unauthorized access | Low | High | Managed identity, RBAC, audit logging |
| Data exposure | Low | Medium | Encrypted storage, access controls |
| Service disruption | Medium | Medium | Gradual rollout, monitoring, rollback procedures |
| Compliance violations | Low | High | Comprehensive audit trails, retention policies |

## 🔧 Security Configuration

### Azure Automation Account Setup
```powershell
# Enable system-assigned managed identity
Set-AzAutomationAccount -ResourceGroupName "YourRG" -Name "YourAutomation" -AssignSystemIdentity

# Configure diagnostic settings
Set-AzDiagnosticSetting -ResourceId $AutomationAccountId -WorkspaceId $LogAnalyticsId -Enabled $true
```

### Required RBAC Permissions
- **Automation Account**: Automation Contributor
- **Managed Identity**: Custom role with specific Graph permissions
- **Storage Account**: Storage Blob Data Contributor (for reports)

### Key Vault Integration
```powershell
# Store sensitive configuration
Set-AzKeyVaultSecret -VaultName "YourKeyVault" -Name "AdminEmails" -SecretValue (ConvertTo-SecureString $AdminEmailList -AsPlainText -Force)
```

## 📊 Monitoring & Alerting

### Critical Alerts to Configure
1. **Runbook Failures**: Any execution failures
2. **High Deletion Counts**: Deletions exceeding normal thresholds
3. **Permission Errors**: Authentication or authorization failures
4. **Long Execution Times**: Performance anomalies
5. **Safety Threshold Breaches**: Attempted mass deletions

### Log Analytics Queries
```kusto
// Monitor device cleanup operations
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.AUTOMATION"
| where Category == "JobLogs"
| where RunbookName_s contains "DeviceCleanup"
| project TimeGenerated, ResultType, RunbookName_s, ResultDescription
| order by TimeGenerated desc

// Alert on high deletion counts
AzureDiagnostics
| where Category == "JobLogs"
| where ResultDescription contains "Devices Processed"
| extend ProcessedCount = extract(@"Devices Processed: (\d+)", 1, ResultDescription)
| where toint(ProcessedCount) > 50  // Adjust threshold as needed
```

## ✅ PowerShell Validation Requirements

### Mandatory Pre-Commit Validation

All PowerShell scripts MUST pass comprehensive validation before being committed to the repository. This includes:

#### 1. Syntax Validation
- **PowerShell Parser**: Scripts must parse without syntax errors
- **Token Analysis**: All tokens must be valid PowerShell constructs
- **AST Validation**: Abstract Syntax Tree must be properly formed

#### 2. PSScriptAnalyzer Compliance
- **Zero Errors**: No PSScriptAnalyzer errors are permitted
- **Critical Warnings**: All security and performance warnings must be addressed
- **Best Practices**: Follow PowerShell community standards and Microsoft recommendations

#### 3. Error Handling Standards
- **Try-Catch Blocks**: Comprehensive error handling for all critical operations
- **ErrorAction Parameters**: Explicit error handling strategy for all commands
- **Write-Error Usage**: Proper error reporting without exposing sensitive information
- **Dangerous Operations**: All potentially destructive commands must include `-WhatIf` support

#### 4. Security Requirements
- **ZERO Hardcoded Credentials**: Absolutely no Client IDs, Tenant IDs, secrets, or tokens in code
- **Environment Variables**: Use `$env:AZURE_CLIENT_ID`, `$env:AZURE_TENANT_ID`, `$env:AZURE_CLIENT_SECRET` for testing
- **SecureString Usage**: Sensitive data must use SecureString where applicable
- **Parameter Validation**: All input parameters must include appropriate validation
- **Confirmation for Dangerous Operations**: Destructive operations require explicit confirmation
- **Pre-Commit Scanning**: All commits automatically scanned for credential patterns

### Validation Script Usage

Execute the validation script before any commit:

```powershell
# Run comprehensive validation
.\Scripts\Validate-PowerShellScripts.ps1 -Path . -Detailed -ReportPath ".\validation-report.csv"

# For specific projects only
.\Scripts\Validate-PowerShellScripts.ps1 -Path ".\Device-Cleanup-Automation" -Detailed

# Fail on warnings (strict mode)
.\Scripts\Validate-PowerShellScripts.ps1 -Path . -FailOnWarnings
```

### Validation Report Analysis

The validation script generates detailed reports including:

1. **Syntax Validation Results**
   - Parse errors and token issues
   - AST structure validation
   - File-level syntax scores

2. **PSScriptAnalyzer Analysis**
   - Error categorization by severity
   - Rule-specific violations
   - Best practice recommendations

3. **Error Handling Assessment**
   - Try-catch block coverage
   - ErrorAction parameter usage
   - Dangerous command safety analysis

4. **Security Scan Results**
   - Hardcoded credential detection
   - Secure coding practice validation
   - Input validation assessment

### Continuous Integration Requirements

For automated deployments, validation must be integrated into CI/CD pipelines:

```yaml
# Azure DevOps Pipeline Example
- task: PowerShell@2
  displayName: 'Validate PowerShell Scripts'
  inputs:
    targetType: 'filePath'
    filePath: 'Scripts/Validate-PowerShellScripts.ps1'
    arguments: '-Path $(Build.SourcesDirectory) -FailOnWarnings'
    pwsh: true
    
- task: PublishTestResults@2
  displayName: 'Publish Validation Results'
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: 'validation-report.xml'
```

### Common Validation Issues and Resolutions

| Issue Category | Common Problems | Resolution |
|---------------|-----------------|------------|
| **Syntax Errors** | Unmatched quotes, missing brackets | Use PowerShell ISE or VS Code with syntax highlighting |
| **PSScriptAnalyzer** | Switch parameter defaults, plural nouns | Follow PowerShell naming conventions |
| **Error Handling** | Missing try-catch, no ErrorAction | Implement comprehensive error handling |
| **Security** | Hardcoded passwords, unsafe operations | Use secure credential management |

### Validation Exemptions

In rare cases where validation rules cannot be met:

1. **Document the exception** with business justification
2. **Implement compensating controls** for security issues
3. **Add inline suppressions** for PSScriptAnalyzer with explanations
4. **Review with security team** for any security-related exemptions

```powershell
# Example: Justified PSScriptAnalyzer suppression
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
param([string]$TemporaryToken)  # Used only for non-sensitive API key
```

## 🔒 Data Governance

### Data Classification
- **Device Information**: Internal use only
- **User Information**: PII - handle according to privacy policy
- **Audit Logs**: Confidential - retain according to compliance requirements

### Retention Policies
- **Execution Logs**: 90 days minimum
- **Device Backups**: 90 days for recovery purposes
- **Audit Reports**: As required by compliance (typically 7 years)
- **Error Logs**: 30 days for troubleshooting

## 🔐 Incident Response

### Security Incident Categories
1. **Unauthorized Access**: Unexpected authentication or permission changes
2. **Data Breach**: Exposure of sensitive device or user information
3. **Malicious Activity**: Unusual deletion patterns or system abuse
4. **Service Disruption**: Automation failures affecting business operations

### Response Procedures
1. **Immediate**: Disable automation, preserve logs
2. **Investigation**: Review audit trails, identify scope
3. **Containment**: Limit access, notify stakeholders
4. **Recovery**: Restore from backups if necessary
5. **Lessons Learned**: Update procedures and controls

## 📋 Compliance Considerations

### Regulatory Requirements
- **SOX**: Maintain audit trails for all device changes
- **GDPR**: Ensure proper handling of EU user data
- **HIPAA**: Additional controls if processing healthcare data
- **SOC2**: Document security controls and procedures

### Audit Evidence
- Complete execution logs with timestamps
- Device backup files before deletion
- Email notification delivery confirmations
- Safety threshold validation records
- Permission grant and consent records

## 🔄 Security Updates

### Regular Security Tasks
- **Monthly**: Review access permissions and audit logs
- **Quarterly**: Update exclusion lists and safety thresholds
- **Semi-annually**: Validate disaster recovery procedures
- **Annually**: Complete security assessment and penetration testing

### Vulnerability Management
- Monitor Microsoft security advisories
- Test security updates in development first
- Maintain inventory of all automation components
- Document security configurations

## 📞 Security Contacts

### Escalation Matrix
1. **Technical Issues**: IT Operations Team
2. **Security Incidents**: Information Security Team
3. **Compliance Questions**: Legal/Compliance Team
4. **Business Impact**: Business Continuity Team

---

**Remember**: Security is everyone's responsibility. Report any suspicious activity or potential vulnerabilities immediately.