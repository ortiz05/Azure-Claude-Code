# Enterprise Application Certificate Monitor

Critical security automation for identifying unused Enterprise Applications with expired certificates and secrets.

## 📋 Overview

This automation combines two high-risk security indicators: applications that haven't been used in 90+ days AND have expired certificates or secrets. This combination represents a critical security vulnerability that requires immediate attention.

## 🚨 Critical Security Focus

**Why This Matters:**
- Unused applications with expired credentials are prime targets for attackers
- Expired certificates may indicate abandoned or compromised applications
- These applications often retain dangerous permissions despite being inactive
- Regulatory compliance requires proper certificate lifecycle management

## ✨ Key Features

- **Dual Risk Detection**
  - Identifies applications unused for 90+ days
  - Analyzes certificate and secret expiration status
  - Combines usage and certificate data for comprehensive risk assessment

- **Critical Security Alerting**
  - Immediate high-priority alerts for critical findings
  - Separate notification channels for security teams
  - Executive escalation for high-risk scenarios

- **Comprehensive Certificate Analysis**
  - Tracks both X.509 certificates and client secrets
  - Monitors expiration timelines and grace periods
  - Identifies applications with multiple expired credentials

- **Risk-Based Prioritization**
  - Critical: Unused apps with expired credentials
  - High: Apps with expired credentials (regardless of usage)
  - Medium: Unused apps with soon-to-expire credentials

## 📁 Project Structure

```
Enterprise-App-Certificate-Monitor/
├── Documentation/
├── Scripts/
│   └── EnterpriseAppCertificateMonitor.ps1  # Main automation script
├── Tests/
└── Reports/                                 # CSV output directory
```

## 🚀 Quick Start

### Prerequisites

1. **Required Permissions**
   - Application.Read.All (to read app credentials)
   - AuditLog.Read.All (to read sign-in logs)
   - Directory.Read.All (for directory access)
   - Mail.Send (for critical alerts)

2. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

```powershell
# Critical security scan
.\Scripts\EnterpriseAppCertificateMonitor.ps1 `
    -DaysUnused 90 `
    -SecurityAdminEmails @("security@company.com") `
    -ITAdminEmails @("admin@company.com") `
    -SendCriticalAlerts
```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| DaysUnused | Int | 90 | Days without usage threshold |
| WhatIf | Switch | False | Simulation mode |
| ITAdminEmails | String[] | [] | IT admin emails for reports |
| SecurityAdminEmails | String[] | [] | Security team emails for critical alerts |
| ExcludedApps | String[] | [] | Apps to exclude from analysis |
| ExportPath | String | C:\EnterpriseAppCertificateReports | Report output path |
| IncludeSoonToExpire | Switch | True | Include certificates expiring soon |
| CertificateExpiryWarningDays | Int | 30 | Days before expiration to warn |
| SendCriticalAlerts | Switch | True | Enable critical security alerts |

## 🚨 Risk Categories

### Critical Risk (Immediate Action Required)
- **Criteria**: Unused 90+ days AND expired certificates/secrets
- **Impact**: Potential unauthorized access through dormant applications
- **Action**: Remove or disable immediately

### High Risk (This Week)
- **Criteria**: Expired certificates/secrets (regardless of usage)
- **Impact**: Authentication failures and potential security issues
- **Action**: Renew certificates or remove applications

### Medium Risk (This Month)
- **Criteria**: Unused apps with soon-to-expire certificates
- **Impact**: Pending authentication issues
- **Action**: Evaluate necessity and renew or remove

## 📈 Generated Reports

1. **CriticalRiskApps_[timestamp].csv**
   - Applications requiring immediate action
   - Detailed credential expiration information
   - Security risk assessment details

2. **HighRiskApps_[timestamp].csv**
   - Applications with expired credentials
   - Usage analysis and risk factors

3. **MediumRiskApps_[timestamp].csv**
   - Applications with expiring certificates
   - Preventive action recommendations

4. **AllAnalyzedApps_[timestamp].csv**
   - Complete certificate and usage analysis
   - Comprehensive credential inventory

5. **CertificateMonitorSummary_[timestamp].csv**
   - Executive summary with key metrics
   - Compliance and security posture overview

## 📧 Alert System

### Critical Security Alerts
Sent immediately to security teams when critical applications are found:

- **Subject**: "🚨 CRITICAL SECURITY ALERT: [X] Apps with Expired Credentials"
- **Priority**: High
- **Recipients**: Security administrators
- **Content**: Detailed table of critical applications with action items

### Detailed Reports
Comprehensive analysis sent to IT administrators:

- **Subject**: "🔐 Enterprise App Certificate Report - [X] Critical Issues"
- **Priority**: Normal/High (based on findings)
- **Recipients**: IT administrators
- **Content**: Full analysis with recommendations and security impact

## 🔍 Certificate Analysis Details

### Monitored Credential Types
- **X.509 Certificates**: Used for authentication and signing
- **Client Secrets**: Password-based authentication credentials
- **Key Credentials**: Asymmetric key pairs for authentication

### Expiration Tracking
- **Expired**: Credentials past their expiration date
- **Expiring Soon**: Credentials expiring within warning period (default: 30 days)
- **Valid**: Credentials with future expiration dates

### Risk Factors Analyzed
- **Permission Level**: Application vs. delegated permissions
- **Publisher Trust**: Microsoft vs. third-party applications
- **Usage Patterns**: Recent activity and user engagement
- **Credential Age**: Time since credential creation/renewal

## ⚡ Emergency Response

### When Critical Applications Are Found

1. **Immediate (Same Day)**
   - Review critical applications list
   - Verify business necessity with stakeholders
   - Disable or remove unnecessary applications
   - Document security impact assessment

2. **Short-term (This Week)**
   - Audit access logs for suspicious activity
   - Review permissions granted to expired applications
   - Update certificate renewal procedures
   - Notify application owners of requirements

3. **Long-term (This Month)**
   - Implement automated certificate monitoring
   - Establish application lifecycle policies
   - Create certificate renewal workflows
   - Set up proactive alerting systems

## 📊 Sample Output

```
=========================================
Enterprise Application Certificate Monitor
=========================================
Focus: Applications unused for 90+ days with certificate issues
Analysis Period: Last 90 days
Certificate Warning Period: 30 days
Total Applications Analyzed: 180
Critical Risk Applications: 5
High Risk Applications: 12
Medium Risk Applications: 8
========================================

🚨 CRITICAL ALERT: 5 applications with expired credentials and no recent usage!
📧 Security alerts sent: Yes
⚡ IMMEDIATE ACTION REQUIRED - Review and remove these applications

⚠️ HIGH PRIORITY: 12 high-risk applications require review
📊 Review detailed reports in: C:\EnterpriseAppCertificateReports
```

## 🔧 Deployment Recommendations

### Scheduling
- **Frequency**: Weekly (for timely detection)
- **Time**: Outside business hours
- **Priority**: High (security-critical automation)

### Alerting Configuration
- **Security Team**: Critical alerts only
- **IT Team**: All reports and summaries
- **Management**: Monthly executive summaries

### Integration Points
- **SIEM Systems**: Forward critical findings
- **Ticketing Systems**: Auto-create tickets for critical apps
- **Certificate Management**: Link to renewal processes

## 📋 Compliance Benefits

### Security Frameworks
- **NIST Cybersecurity Framework**: Supports Identify and Protect functions
- **ISO 27001**: Certificate lifecycle management controls
- **SOC 2**: Access management and monitoring controls

### Audit Evidence
- Complete certificate inventory and status
- Risk assessment documentation
- Automated remediation records
- Management oversight evidence

## 🔗 Related Documentation

- [Azure AD Certificate Management](https://docs.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials)
- [Application Security Best Practices](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)
- [Certificate Lifecycle Management](https://docs.microsoft.com/azure/active-directory/develop/howto-create-service-principal-portal)

## 📞 Emergency Contact

**For critical security findings requiring immediate assistance:**

- **Security Operations Center**: [Your SOC contact]
- **IT Security Team**: [Security team contact]
- **Management Escalation**: [Management contact]

**This automation identifies critical security risks requiring prompt action. Do not delay response to critical findings.**