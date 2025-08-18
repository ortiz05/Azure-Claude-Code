# Enterprise Application Usage Monitor

Automated solution for identifying unused Enterprise Applications in Azure AD and providing comprehensive cleanup recommendations.

## 📋 Overview

This automation analyzes Azure AD sign-in logs to identify Enterprise Applications that haven't been used in the specified number of days (default: 90). It provides detailed reporting with risk assessments and cost savings analysis to help organizations optimize their application portfolio.

## ✨ Key Features

- **Comprehensive Usage Analysis**
  - Analyzes sign-in logs for application usage patterns
  - Identifies applications unused for configurable periods
  - Tracks user engagement and geographic usage

- **Intelligent Risk Assessment**
  - Multi-factor risk scoring based on permissions, publisher, and usage
  - Categorizes applications by risk level (High/Medium/Low)
  - Identifies high-privilege unused applications

- **Business Value Analysis**
  - Estimates potential cost savings from application cleanup
  - Provides ROI calculations for optimization efforts
  - Tracks licensing optimization opportunities

- **Executive Reporting**
  - Professional HTML email reports for administrators
  - Detailed CSV exports for audit trails
  - Publisher analysis and trending data

## 📁 Project Structure

```
Enterprise-App-Usage-Monitor/
├── Documentation/
├── Scripts/
│   └── EnterpriseAppUsageMonitor.ps1    # Main automation script
├── Tests/
├── Reports/                             # CSV output directory
└── Templates/
```

## 🚀 Quick Start

### Prerequisites

1. **Required Permissions**
   - Application.Read.All (to read app registrations)
   - AuditLog.Read.All (to read sign-in logs)
   - Directory.Read.All (for directory access)
   - Mail.Send (for email notifications)

2. **PowerShell Modules**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

### Basic Usage

```powershell
# Run analysis for apps unused in last 90 days
.\Scripts\EnterpriseAppUsageMonitor.ps1 `
    -DaysUnused 90 `
    -ITAdminEmails @("admin@company.com") `
    -ExportPath "C:\Reports"
```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| DaysUnused | Int | 90 | Days without usage to consider app as unused |
| WhatIf | Switch | False | Simulation mode |
| ITAdminEmails | String[] | [] | Admin emails for reports |
| ExcludedApps | String[] | [] | Apps to exclude (by name or ID) |
| ExportPath | String | C:\EnterpriseAppReports | Report output path |
| IncludeActiveApps | Switch | False | Include active apps in reports |
| SendEmailReport | Switch | True | Enable email reporting |
| MinimumRiskThreshold | Int | 10 | Threshold for high-priority alerts |

## 📈 Generated Reports

1. **UnusedEnterpriseApps_[timestamp].csv**
   - Complete inventory of unused applications
   - Risk assessments and recommendations
   - Publisher and permission analysis

2. **ActiveEnterpriseApps_[timestamp].csv** (optional)
   - Currently active applications
   - Usage statistics and trends

3. **HighRiskUnusedApps_[timestamp].csv**
   - High-risk unused applications requiring immediate attention
   - Detailed risk factor analysis

4. **EnterpriseAppSummary_[timestamp].csv**
   - Executive summary with key metrics
   - Cost savings estimates

## 🔍 Risk Assessment Criteria

### High Risk Applications
- Unused for 6+ months with application-level permissions
- Third-party apps with administrative access
- Applications with no publisher certification

### Medium Risk Applications
- Unused for 3-6 months
- Internal apps with delegated permissions
- Apps with expired or missing certifications

### Low Risk Applications
- Recently created apps (< 90 days)
- Microsoft-published applications
- Apps with limited permissions

## 📧 Email Reports

### Executive Summary Features
- **Usage metrics** with compliance rates
- **Top 10 unused applications** with risk assessment
- **Publisher analysis** showing unused apps by vendor
- **Cost optimization recommendations**
- **Security impact analysis**

### Alert Thresholds
- **High Priority**: >10 unused applications detected
- **Normal Priority**: <10 unused applications

## 💰 Business Value

### Cost Optimization
- Identifies licensing cost reduction opportunities
- Estimates potential annual savings
- Tracks optimization ROI

### Security Benefits
- Reduces attack surface by eliminating unused entry points
- Simplifies access reviews and compliance audits
- Improves overall security posture

### Operational Efficiency
- Streamlines application portfolio management
- Reduces maintenance overhead
- Improves user experience through cleaner app catalogs

## 🔧 Deployment Options

### Azure Automation
1. Import script to Azure Automation Account
2. Configure schedule (recommended: monthly)
3. Set up managed identity with required permissions
4. Configure email distribution lists

### Manual Execution
```powershell
# Monthly analysis
.\Scripts\EnterpriseAppUsageMonitor.ps1 -DaysUnused 90

# Quarterly deep analysis  
.\Scripts\EnterpriseAppUsageMonitor.ps1 -DaysUnused 180 -IncludeActiveApps
```

## 📊 Sample Output

```
=========================================
Enterprise Application Usage Monitor
=========================================
Analysis Period: Last 90 days
Total Enterprise Applications: 250
Unused Applications: 45
Active Applications: 205
High-Risk Unused Apps: 8
Application Usage Rate: 82.0%
Estimated Annual Savings: $8,100
=========================================

⚠️  ATTENTION: 45 unused enterprise applications found
🚨 HIGH PRIORITY: 8 high-risk applications require immediate review
💰 Potential cost savings: $8,100 annually
📊 Review detailed reports in: C:\EnterpriseAppReports
```

## 📋 Best Practices

1. **Regular Monitoring**: Run monthly to track trends
2. **Stakeholder Validation**: Confirm business need before app removal
3. **Gradual Cleanup**: Start with obvious unused apps
4. **Documentation**: Maintain records of cleanup decisions
5. **Exclusion Lists**: Configure exclusions for critical systems

## 🔗 Related Documentation

- [Azure AD Application Management](https://docs.microsoft.com/azure/active-directory/manage-apps)
- [Microsoft Graph Applications API](https://docs.microsoft.com/graph/api/resources/application)
- [Enterprise Application Governance](https://docs.microsoft.com/azure/active-directory/governance)

## 📞 Support

For questions or issues:
1. Review troubleshooting section in main README
2. Check Azure Automation logs for execution details
3. Verify Graph API permissions and consent
4. Create issue in repository with relevant logs