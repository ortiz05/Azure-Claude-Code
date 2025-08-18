# Azure Automation Scripts Collection

A comprehensive collection of Azure automation scripts and solutions for various administrative and operational tasks.

## 📁 Repository Structure

```
Azure-Claude-Code/
├── README.md                           # This file
├── Device-Cleanup-Automation/          # Entra ID device cleanup solution
│   ├── Documentation/
│   │   └── CLAUDE.md                  # Detailed guidelines and requirements
│   ├── Scripts/
│   │   └── DeviceCleanupAutomation.ps1 # Main automation script
│   ├── Tests/
│   │   ├── Test-GraphConnection.ps1    # Connection testing script
│   │   └── Test-DeviceCleanupFunctions.ps1 # Function testing
│   └── Reports/                        # CSV reports output directory
├── [Future-Project-2]/                 # Placeholder for next automation
├── [Future-Project-3]/                 # Placeholder for next automation
└── ...
```

## 🚀 Current Projects

### 1. Device Cleanup Automation
Automated solution for cleaning up inactive devices from Entra ID (Azure Active Directory).

**Features:**
- Identifies devices inactive for 90+ days
- Separate handling for standard vs Autopilot devices
- Email notifications to device owners
- Comprehensive CSV reporting
- Safety thresholds and exclusion lists
- WhatIf mode for testing

**[Full Documentation →](./Device-Cleanup-Automation/Documentation/CLAUDE.md)**

### 2. MFA Compliance Monitor
Security automation for enforcing Microsoft Authenticator compliance across your organization.

**Features:**
- Analyzes sign-in logs for non-compliant MFA usage
- Sends professional email notifications to users
- Detailed device and location tracking
- Admin dashboard with compliance metrics
- User exclusion lists and safety controls
- Comprehensive audit trails

**[Full Documentation →](./MFA-Compliance-Monitor/README.md)**

### 3. Enterprise App Usage Monitor
Identifies unused Enterprise Applications for cost optimization and security cleanup.

**Features:**
- Analyzes application usage over configurable periods
- Risk assessment with business impact analysis
- Cost savings estimates and ROI calculations
- Publisher analysis and compliance reporting
- Executive dashboards and detailed CSV exports
- Integration with application lifecycle management

**[Full Documentation →](./Enterprise-App-Usage-Monitor/README.md)**

### 4. Enterprise App Certificate Monitor
**🚨 CRITICAL SECURITY AUTOMATION** - Identifies unused applications with expired certificates.

**Features:**
- Detects critical combination: unused apps + expired certificates
- Immediate security alerts for high-risk applications
- Comprehensive certificate lifecycle tracking
- Risk-based prioritization and escalation
- Emergency response procedures
- Compliance and audit support

**[Full Documentation →](./Enterprise-App-Certificate-Monitor/README.md)**

### 5. Future Projects (Planned)
- User Account Lifecycle Management
- Azure Resource Tagging Automation
- Cost Optimization Scripts
- Conditional Access Policy Compliance
- Guest User Access Reviews
- Service Principal Credential Management

## 🛠️ Prerequisites

### General Requirements
- Azure Subscription
- Azure Automation Account (for runbook execution)
- PowerShell 7.0 or higher
- Microsoft Graph PowerShell SDK

### Required PowerShell Modules
```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser
Install-Module -Name Az.Accounts -Scope CurrentUser
Install-Module -Name Az.Automation -Scope CurrentUser
```

## 🔐 Authentication Setup

### Using Managed Identity (Recommended for Production)
1. Create an Azure Automation Account
2. Enable system-assigned managed identity
3. Grant required Graph API permissions
4. Use `Connect-MgGraph -Identity` in scripts

### Using Service Principal (Development/Testing)
1. Register an application in Azure AD
2. Create client secret
3. Grant required API permissions with admin consent
4. Store credentials securely (use Azure Key Vault in production)

## 📊 Standard Project Structure

Each automation project follows this structure:
```
Project-Name/
├── Documentation/
│   ├── CLAUDE.md         # AI-readable guidelines
│   └── README.md         # User documentation
├── Scripts/
│   ├── Main-Script.ps1   # Primary automation script
│   └── Functions.ps1     # Reusable functions
├── Tests/
│   └── Test-*.ps1        # Test scripts
├── Reports/              # Output directory
└── Examples/             # Usage examples
```

## 🔧 Usage Guidelines

### Running Scripts Locally
```powershell
# Navigate to project directory
cd Device-Cleanup-Automation/Scripts

# Run in WhatIf mode first
.\DeviceCleanupAutomation.ps1 -WhatIf -InactiveDays 90

# Run in production mode
.\DeviceCleanupAutomation.ps1 -InactiveDays 90 -ExportPath "C:\Reports"
```

### Deploying to Azure Automation
1. Create runbook in Azure Automation Account
2. Import script content
3. Configure schedule
4. Set up parameters
5. Link to managed identity

## 📝 Contributing Guidelines

### Adding New Automation Projects
1. Create new folder following naming convention: `Purpose-Type-Automation`
2. Include standard subdirectories (Documentation, Scripts, Tests, Reports)
3. Create CLAUDE.md with detailed requirements
4. Write comprehensive README.md
5. Include test scripts
6. Add project to main README

### Code Standards
- Use approved verbs for PowerShell functions
- Include proper error handling
- Add verbose output for debugging
- Implement WhatIf support where applicable
- Include comprehensive commenting
- Follow security best practices

## ⚠️ Security Considerations

1. **Never commit credentials** to the repository
2. Use Azure Key Vault for secret management
3. Implement least-privilege access
4. Enable audit logging
5. Test in non-production first
6. Review code for security vulnerabilities

## 📚 Documentation Standards

Each project must include:
- **CLAUDE.md**: AI-readable guidelines and requirements
- **README.md**: Human-readable documentation
- **Inline comments**: Explain complex logic
- **Parameter descriptions**: Document all parameters
- **Examples**: Provide usage examples

## 🐛 Testing Requirements

Before deploying any automation:
1. Test with WhatIf mode
2. Validate in development environment
3. Test error handling scenarios
4. Verify safety thresholds
5. Check logging and reporting
6. Validate rollback procedures

## 📧 Support & Contact

For issues, questions, or contributions:
- Create an issue in this repository
- Follow the issue template
- Include relevant logs and error messages

## 📜 License

This repository is for internal use. Please review your organization's policies before using these scripts.

## 🔄 Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2024-01 | Initial repository setup with Device Cleanup Automation |

---

**Note**: Always test scripts in a non-production environment before deploying to production. Ensure you have proper backups and rollback procedures in place.