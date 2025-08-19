# Azure Automation & Infrastructure Solutions Collection

A comprehensive collection of enterprise-grade Azure automation scripts, infrastructure deployment solutions, and security monitoring tools for various administrative and operational tasks.

## 🌟 Featured Solutions

### 🏢 Infrastructure Automation
- **[Azure Files Secure Deployment](./Azure-Files-Secure-Deployment/)** - Enterprise-grade file storage with security controls
### 🔐 Security & Compliance Automation  
- **[Application Permission Auditor](./Application-Permission-Auditor/)** - Critical security automation for application permission monitoring
- **[Service Principal Credential Manager](./Service-Principal-Credential-Manager/)** - Automated credential lifecycle management
- **[Enterprise App Certificate Monitor](./Enterprise-App-Certificate-Monitor/)** - Certificate expiration and security monitoring
- **[MFA Compliance Monitor](./MFA-Compliance-Monitor/)** - Microsoft Authenticator compliance enforcement
### 🧹 Device & Resource Management
- **[Device Cleanup Automation](./Device-Cleanup-Automation/)** - Automated Entra ID device lifecycle management
- **[Enterprise App Usage Monitor](./Enterprise-App-Usage-Monitor/)** - Application usage analysis and cost optimization

## 📁 Repository Structure

```
Azure-Claude-Code/
├── README.md                                    # This comprehensive overview
├── SECURITY.md                                  # Security guidelines and standards
├── LESSONS-LEARNED.md                          # Project learnings and best practices
├── Scripts/                                    # Global utility scripts
│   ├── Pre-Commit-Hook.ps1                   # Code quality enforcement
│   ├── Setup-Git-Hooks.ps1                   # Development workflow setup
│   ├── Test-GraphAuthentication.ps1           # Authentication testing
│   └── Validate-PowerShellScripts.ps1         # Script validation utility
├── Azure-Files-Secure-Deployment/             # 🆕 Secure file storage solution
│   ├── Deployment/                           # All deployment scripts consolidated
│   │   ├── Deploy-SecureAzureFiles.ps1      # Main deployment script
│   │   ├── Validate-AzureFilesDeployment.ps1 # Security validation
│   │   ├── Create-AzureFilesDeploymentGroup.ps1 # Least-privilege group setup
│   │   ├── Onboard-AzureFiles-ServicePrincipal.ps1 # Service principal automation
│   │   └── README.md                         # Deployment guide
│   ├── Documentation/CLAUDE.md               # AI implementation guidelines
│   ├── HowTo-Mount-FileShare-Intune.md       # Intune configuration guide
│   ├── GROUP-SETUP-README.md                 # Group management documentation
│   ├── ONBOARDING-INSTRUCTIONS.md            # Complete setup guide
│   └── Examples/                              # Deployment examples
├── Application-Permission-Auditor/             # 🆕 Critical security automation
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-ApplicationPermissionAuditor.ps1
│   │   ├── Create-[Service]DeploymentGroup.ps1
│   │   ├── Grant-[Service]Permissions.ps1
│   │   └── README.md
│   ├── Scripts/ApplicationPermissionAuditor.ps1
│   ├── Documentation/CLAUDE.md
│   └── Tests/
├── Service-Principal-Credential-Manager/       # 🆕 Credential lifecycle automation
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-ServicePrincipalCredentialManager.ps1
│   │   ├── Create-[Service]DeploymentGroup.ps1
│   │   ├── Grant-[Service]Permissions.ps1
│   │   └── README.md
│   ├── Scripts/ServicePrincipalCredentialManager.ps1
│   ├── Documentation/CLAUDE.md
│   └── Tests/
├── Device-Cleanup-Automation/                  # Device lifecycle management
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-DeviceCleanupAutomation.ps1
│   │   ├── Create-DeviceCleanupDeploymentGroup.ps1
│   │   ├── Grant-ManagedIdentityPermissions.ps1
│   │   └── README.md
│   ├── Scripts/DeviceCleanupAutomation.ps1
│   ├── Documentation/CLAUDE.md
│   ├── Tests/
│   └── Reports/
├── Enterprise-App-Certificate-Monitor/         # Certificate monitoring
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-EnterpriseAppCertificateMonitor.ps1
│   │   ├── Create-[Service]DeploymentGroup.ps1
│   │   ├── Grant-[Service]Permissions.ps1
│   │   └── README.md
│   ├── Scripts/EnterpriseAppCertificateMonitor.ps1
│   ├── Documentation/CLAUDE.md
│   └── Tests/
├── Enterprise-App-Usage-Monitor/               # Application usage analytics
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-EnterpriseAppUsageMonitor.ps1
│   │   ├── Create-[Service]DeploymentGroup.ps1
│   │   ├── Grant-[Service]Permissions.ps1
│   │   └── README.md
│   ├── Scripts/EnterpriseAppUsageMonitor.ps1
│   ├── Documentation/CLAUDE.md
│   └── Tests/
├── MFA-Compliance-Monitor/                     # MFA compliance enforcement
│   ├── Azure-Automation/                     # All deployment scripts consolidated
│   │   ├── Deploy-MFAComplianceMonitor.ps1
│   │   ├── Create-MFAMonitorDeploymentGroup.ps1
│   │   ├── Grant-MFAMonitorPermissions.ps1
│   │   └── README.md
│   ├── Scripts/MFAComplianceMonitor.ps1
│   ├── Documentation/CLAUDE.md
│   └── Tests/
└── Validation-Report.csv                      # Automated quality reports
```

## 🚀 Current Solutions

### 1. Azure Files Secure Deployment 🆕
**Enterprise-grade secure file storage with industry security standards**

Transform your file storage infrastructure with this comprehensive Azure Files deployment solution that implements security controls, compliance features, and best practices out of the box.

**Key Features:**
- **Enterprise Security Controls**: HTTPS-only, TLS 1.2, disabled shared keys, customer-managed encryption
- **Network Security**: VNet integration, IP restrictions, private endpoints
- **Identity & Access**: Azure AD authentication, RBAC integration, least-privilege access
- **Compliance & Monitoring**: Soft delete, versioning, audit logging, diagnostic settings
- **Automated Deployment**: Infrastructure-as-Code with comprehensive validation
- **Intune Integration**: Modern device management with configuration profiles
- **Service Principal Automation**: Unattended deployment capabilities

**What's Included:**
- Main deployment script with security validation
- Least-privilege Azure AD group provisioning
- Service principal onboarding for automation
- Comprehensive Intune configuration guide
- Deployment validation and security scanning
- Complete examples and documentation

**[Full Documentation →](./Azure-Files-Secure-Deployment/README.md)**

### 2. Application Permission Auditor 🆕
**Critical security automation for enterprise application permission monitoring**

Proactively identify and monitor high-risk application permissions across your Microsoft 365 and Azure environment to prevent security breaches and ensure compliance.

**Key Features:**
- **High-Risk Permission Detection**: Identifies dangerous application permissions automatically
- **Real-Time Monitoring**: Continuous scanning of application permissions and OAuth consents
- **Executive Reporting**: Professional HTML reports with risk analysis and recommendations
- **Automated Alerting**: Immediate notifications for critical permission grants
- **Compliance Support**: Detailed audit trails and regulatory compliance reporting
- **Risk Scoring**: Intelligent risk assessment with business impact analysis
- **Trend Analysis**: Historical permission tracking and security posture monitoring

**Security Impact:**
- Prevents privilege escalation attacks
- Identifies over-privileged applications
- Monitors OAuth consent grants
- Tracks application permission changes
- Generates compliance audit reports

**[Full Documentation →](./Application-Permission-Auditor/README.md)**

### 3. Service Principal Credential Manager 🆕
**Automated lifecycle management for service principal credentials**

Eliminate security risks from expired or long-lived service principal credentials with intelligent automation that monitors, alerts, and optionally remediates credential issues.

**Key Features:**
- **Credential Lifecycle Monitoring**: Tracks certificates and secrets across all service principals
- **Risk-Based Alerting**: Prioritizes critical, warning, and long-lived credential issues
- **Automated Remediation**: Optional automatic credential rotation and renewal
- **Executive Dashboards**: Professional HTML reports with security posture analytics
- **Compliance Integration**: Detailed audit trails and regulatory compliance support
- **Security Intelligence**: Identifies unused credentials and over-privileged service principals

**Security Benefits:**
- Prevents authentication failures from expired credentials
- Reduces security risk from long-lived credentials
- Automates credential rotation workflows
- Provides comprehensive audit trails
- Enables proactive security management

**[Full Documentation →](./Service-Principal-Credential-Manager/README.md)**

### 4. Device Cleanup Automation
**Automated lifecycle management for Entra ID devices**

Streamline device management with intelligent automation that identifies, notifies, and removes inactive devices while maintaining security and user experience.

**Features:**
- Identifies devices inactive for configurable periods (default 90+ days)
- Separate handling for standard vs Autopilot devices
- Email notifications to device owners before cleanup
- Comprehensive CSV reporting and audit trails
- Safety thresholds and exclusion lists
- WhatIf mode for testing and validation

**[Full Documentation →](./Device-Cleanup-Automation/README.md)**

### 5. MFA Compliance Monitor
**Security automation for enforcing Microsoft Authenticator compliance**

Ensure organization-wide MFA compliance by monitoring sign-in patterns and automatically notifying users who aren't using approved MFA methods.

**Features:**
- Analyzes sign-in logs for non-compliant MFA usage
- Sends professional email notifications to users
- Detailed device and location tracking
- Admin dashboard with compliance metrics
- User exclusion lists and safety controls
- Comprehensive audit trails

**[Full Documentation →](./MFA-Compliance-Monitor/README.md)**

### 6. Enterprise App Usage Monitor
**Application usage analysis and cost optimization**

Identify unused Enterprise Applications for cost optimization and security cleanup with detailed usage analytics and business impact assessment.

**Features:**
- Analyzes application usage over configurable periods
- Risk assessment with business impact analysis
- Cost savings estimates and ROI calculations
- Publisher analysis and compliance reporting
- Executive dashboards and detailed CSV exports
- Integration with application lifecycle management

**[Full Documentation →](./Enterprise-App-Usage-Monitor/README.md)**

### 7. Enterprise App Certificate Monitor
**Critical security automation for certificate lifecycle management**

Identifies the dangerous combination of unused applications with expired certificates to prevent security vulnerabilities and authentication failures.

**Features:**
- Detects critical combination: unused apps + expired certificates
- Immediate security alerts for high-risk applications
- Comprehensive certificate lifecycle tracking
- Risk-based prioritization and escalation
- Emergency response procedures
- Compliance and audit support

**[Full Documentation →](./Enterprise-App-Certificate-Monitor/README.md)**

## 🛠️ Prerequisites & Setup

### System Requirements
- **PowerShell 7.0 or later** (enforced by all scripts)
- Azure Subscription with appropriate permissions
- Azure Automation Account (for production runbook execution)
- Microsoft Graph PowerShell SDK

### Required PowerShell Modules
All scripts include automatic validation and installation guidance for:
```powershell
# Core Azure modules
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
Install-Module -Name Az.Automation -Scope CurrentUser -Force
Install-Module -Name Az.Storage -Scope CurrentUser -Force
Install-Module -Name Az.Resources -Scope CurrentUser -Force
Install-Module -Name Az.KeyVault -Scope CurrentUser -Force

# Microsoft Graph modules
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Mail -Scope CurrentUser -Force
```

### PowerShell 7+ Compatibility 🆕
All scripts now include comprehensive compatibility validation:
- Enforces PowerShell 7.0+ requirement
- Validates required Azure PowerShell modules
- Blocks execution on Windows PowerShell (Desktop edition)
- Provides clear error messages and installation guidance

## 📦 Azure Blob Storage Integration (New!)

All Azure Automation runbooks now support direct integration with Azure Blob Storage for centralized report management and compliance archiving.

### Storage Configuration
Each automation service writes to its own dedicated container:
- **Device Cleanup**: `device-cleanup-reports`
- **MFA Compliance**: `mfa-compliance-reports`
- **Certificate Monitor**: `certificate-reports`
- **App Usage Monitor**: `app-usage-reports`
- **Permission Auditor**: `permission-audit-reports`
- **Service Principal Manager**: `service-principal-reports`

### Features
- **Managed Identity Authentication**: Secure, passwordless access to storage
- **Cool Tier Storage**: Automatic cost optimization for archived reports
- **Year/Month Organization**: Reports organized in `yyyy/MM/` folder structure
- **Backward Compatibility**: Scripts continue to write locally when storage not configured

### Usage Example
```powershell
# Run with blob storage integration
.\DeviceCleanupAutomation.ps1 `
    -StorageAccountName "stgautomationreports" `
    -StorageContainerName "device-cleanup-reports" `
    -UseManagedIdentity
```

## 🔐 Authentication & Security

### Production Authentication (Recommended)
**Managed Identity with Azure Automation**
```powershell
# Automated authentication in Azure Automation runbooks
Connect-MgGraph -Identity -NoWelcome
# For storage operations
Connect-AzAccount -Identity
```

### Development/Testing Authentication
**Service Principal with Certificate**
```powershell
# Secure certificate-based authentication
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $Thumbprint
```

### Security Best Practices 
✅ **Never commit credentials** to repositories  
✅ **Use Azure Key Vault** for secret management  
✅ **Implement least-privilege access** with custom Azure AD groups  
✅ **Enable comprehensive audit logging**  
✅ **Test in non-production environments first**  
✅ **Follow security code review processes**  

## 📊 Standard Project Architecture

Each automation solution follows this enterprise-grade structure:
```
Solution-Name/
├── Azure-Automation/               # 🆕 Production deployment automation
│   ├── Deploy-Solution.ps1        # Automated Azure Automation deployment
│   └── README.md                  # Deployment documentation
├── Documentation/
│   ├── CLAUDE.md                  # AI-readable guidelines and requirements
│   └── README.md                  # Comprehensive user documentation
├── Scripts/
│   ├── Main-Solution.ps1          # Primary automation script
│   └── Functions.ps1              # Reusable function libraries
├── Templates/                     # Email templates and reports
│   ├── AlertTemplate.html         # Professional alert notifications
│   └── ExecutiveReport.html       # Executive dashboard templates
├── Tests/
│   ├── Test-Connection.ps1        # Authentication and connectivity tests
│   └── Test-Functions.ps1         # Unit and integration tests
├── Reports/                       # CSV and analytical outputs
└── Examples/                      # Usage examples and samples
```

## 🚀 Deployment Options

### Option 1: Azure Automation (Production) 🆕
Each solution includes automated deployment scripts:
```powershell
# Deploy to Azure Automation with one command
.\Deploy-ApplicationPermissionAuditor.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-monitoring"
```

### Option 2: Local Execution (Development/Testing)
```powershell
# Run locally with WhatIf mode
.\ApplicationPermissionAuditor.ps1 -WhatIf -DaysToAnalyze 30

# Run in production mode
.\ApplicationPermissionAuditor.ps1 -DaysToAnalyze 30 -ExportPath "C:\Reports"
```

### Option 3: Scheduled Execution
All solutions support:
- Azure Automation scheduled runbooks
- Task Scheduler integration
- PowerShell Jobs and workflows

## 🔧 Configuration Management

### Global Configuration Files
- **SECURITY.md**: Security standards and requirements
- **LESSONS-LEARNED.md**: Project insights and best practices
- **Validation-Report.csv**: Automated quality and compliance reports

### Environment-Specific Configuration
Each solution supports:
- Development/testing parameter sets
- Production security configurations
- Custom organizational requirements
- Compliance and audit settings

## 📈 Quality & Governance 🆕

### Automated Quality Assurance
- **Pre-commit hooks**: Automated code quality checks
- **PowerShell script validation**: Syntax and best practice enforcement
- **Security scanning**: Credential and vulnerability detection
- **Compatibility testing**: PowerShell 7+ validation across all scripts

### Documentation Standards
Every solution includes:
- **Executive summaries**: Business value and ROI documentation
- **Technical guides**: Implementation and configuration details
- **Security documentation**: Risk assessment and mitigation strategies
- **Operational runbooks**: Troubleshooting and maintenance procedures

## 📋 Contributing Guidelines

### Adding New Solutions
1. **Follow naming convention**: `Purpose-Type-Solution`
2. **Use standard architecture**: Include all required subdirectories
3. **Implement security controls**: Follow established security patterns
4. **Add comprehensive documentation**: Include CLAUDE.md and README.md
5. **Create deployment automation**: Include Azure Automation deployment scripts
6. **Write thorough tests**: Unit tests, integration tests, and validation scripts
7. **Update main README**: Add solution to this overview

### Code Quality Standards
- **PowerShell 7+ compatibility**: All scripts must include version validation
- **Approved PowerShell verbs**: Follow PowerShell naming conventions
- **Comprehensive error handling**: Robust error management and logging
- **WhatIf support**: Safe testing and validation capabilities
- **Security best practices**: Secure coding and credential management
- **Professional documentation**: Clear, actionable documentation

## ⚠️ Security & Compliance

### Security Framework
1. **Zero Trust Architecture**: Never trust, always verify
2. **Least Privilege Access**: Minimal required permissions only
3. **Defense in Depth**: Multiple layers of security controls
4. **Continuous Monitoring**: Real-time security monitoring and alerting
5. **Incident Response**: Automated detection and response capabilities

### Compliance Support
- **Audit Trails**: Comprehensive logging and reporting
- **Regulatory Compliance**: SOX, GDPR, HIPAA support patterns
- **Risk Management**: Risk assessment and mitigation frameworks
- **Change Management**: Controlled deployment and rollback procedures

## 🧪 Testing & Validation

### Pre-Deployment Testing
1. **PowerShell 7+ compatibility verification**
2. **Module dependency validation**
3. **Authentication testing in target environment**
4. **WhatIf mode execution and validation**
5. **Security scanning and vulnerability assessment**
6. **Performance testing and optimization**

### Production Validation
1. **Gradual rollout procedures**
2. **Monitoring and alerting validation**
3. **Rollback procedure verification**
4. **User acceptance testing**
5. **Security posture assessment**

## 📞 Support & Maintenance

### Getting Help
- **Create GitHub Issues**: Use provided templates for bug reports and feature requests
- **Security Issues**: Follow responsible disclosure procedures
- **Documentation**: Check solution-specific README files
- **Community**: Contribute improvements and share experiences

### Maintenance Schedule
- **Monthly**: Security updates and dependency management
- **Quarterly**: Feature updates and enhancement releases
- **Annually**: Major version releases and architecture reviews

## 📜 License & Usage

This repository contains enterprise automation solutions for internal organizational use. Please review your organization's security and compliance policies before deploying these solutions in production environments.

## 🔄 Version History

| Version | Date | Description | Major Changes |
|---------|------|-------------|---------------|
| **3.0.0** | **2024-08** | **🆕 Major Infrastructure & Security Release** | **Azure Files Secure Deployment, Application Permission Auditor, Service Principal Credential Manager, PowerShell 7+ compatibility across all scripts** |
| 2.2.0 | 2024-07 | Enhanced Enterprise Applications | Certificate Monitor, Usage Monitor improvements |
| 2.1.0 | 2024-06 | Security & Compliance | MFA Compliance Monitor, enhanced security controls |
| 2.0.0 | 2024-05 | Multi-Solution Architecture | Enterprise App monitoring, improved project structure |
| 1.1.0 | 2024-03 | Enhanced Device Management | Improved device cleanup with better reporting |
| 1.0.0 | 2024-01 | Initial Release | Device Cleanup Automation foundation |

### Latest Release Highlights (v3.0.0) 🆕

**🏗️ Infrastructure Automation**
- Complete Azure Files secure deployment solution
- Infrastructure-as-Code with security validation
- Least-privilege access management
- Intune integration for modern device management

**🔐 Critical Security Enhancements**
- Application Permission Auditor for enterprise security
- Service Principal Credential Manager with lifecycle automation
- Comprehensive security monitoring and alerting

**⚡ Technical Improvements**
- PowerShell 7+ compatibility enforcement across all scripts
- Enhanced error handling and validation
- Improved deployment automation
- Standardized architecture across all solutions

**📚 Documentation & Quality**
- Comprehensive deployment guides
- Professional email templates
- Executive reporting dashboards
- Automated quality assurance

---

## 🎯 Roadmap & Future Enhancements

### Short Term (Next 3 months)
- Enhanced reporting dashboards
- Additional compliance frameworks
- Mobile device management integration
- Cost optimization analytics

### Long Term (6-12 months)
- AI-powered security analytics
- Advanced threat detection
- Automated incident response
- Cloud governance automation

---

**⚠️ Important**: Always test automation solutions in non-production environments before deploying to production. Ensure you have proper backups, rollback procedures, and change management processes in place.

**🛡️ Security First**: These solutions implement enterprise security best practices, but always validate they meet your organization's specific security and compliance requirements.