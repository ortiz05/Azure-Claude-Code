# Azure Files Secure Deployment - AI Agent Guide

## Automation Overview
**Purpose**: Deploy enterprise-grade Azure Files storage with comprehensive security controls, compliance features, and modern management integration.

**Type**: Infrastructure-as-Code Deployment (not recurring automation)
**Deployment Method**: Manual execution with OAuth authentication (recommended) or Service Principal for CI/CD

## Core Security Architecture

### Enterprise Security Controls (Built-in)
- **HTTPS-only traffic enforcement** - `RequireHttpsTrafficOnly = $true`
- **TLS 1.2 minimum encryption** - `MinimumTlsVersion = "TLS1_2"`
- **Disabled shared key access** - `AllowSharedKeyAccess = $false` (forces Azure AD auth)
- **Public blob access disabled** - `AllowBlobPublicAccess = $false`
- **Cross-tenant replication disabled** - `AllowCrossTenantReplication = $false`
- **Soft delete enabled** - 30-day recovery window for deleted files
- **Blob versioning enabled** - Complete audit trail of file changes

### Network Security Integration
- **VNet service endpoint configuration** - Secure network connectivity
- **IP restriction implementation** - Firewall rules for allowed IP ranges
- **Private endpoint support** - Maximum security isolation
- **Subnet integration** - Integration with existing network architecture

### Advanced Security Features
- **Customer-managed encryption** - Integration with Azure Key Vault for encryption keys
- **Azure AD authentication** - Identity-based file share access controls
- **Premium storage options** - Enhanced performance and security features
- **Monitoring and logging** - Integration with Log Analytics for security monitoring

## Key Scripts & Functions

### Main Deployment Script
**File**: `Deploy-SecureAzureFiles.ps1`
**Purpose**: Primary deployment automation with comprehensive security validation

**Critical Parameters** (All Required):
- `SubscriptionId` - Azure subscription ID (GUID format)
- `TenantId` - Azure AD tenant ID (MANDATORY for targeted authentication)
- `ResourceGroupName` - Target resource group (1-90 characters)
- `StorageAccountName` - Globally unique storage account name (3-24 chars, lowercase)
- `Location` - Azure region

**Authentication Pattern**:
```powershell
# Always requires explicit tenant targeting to prevent multi-tenant auth issues
Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
```

### Least-Privilege Group Provisioning
**File**: `Create-AzureFilesDeploymentGroup.ps1`
**Purpose**: Creates Azure AD security group with minimal required permissions

**Security Benefits**:
- **Resource group scoped permissions only** - No tenant-wide access
- **Built-in Azure roles only** - Microsoft-maintained, well-documented permissions
- **No Azure AD admin rights** - Group members can't modify directory
- **Easily auditable** - Clear role assignments and group membership

**Assigned Roles**:
- `Storage Account Contributor` - Create/manage storage accounts and file shares
- `Network Contributor` - Configure VNet service endpoints (optional)

### Service Principal Automation
**File**: `Onboard-AzureFiles-ServicePrincipal.ps1`
**Purpose**: Creates service principal for unattended deployment scenarios

**When to Use**: ONLY for automated deployment (CI/CD pipelines, API calls)
**When NOT to Use**: Manual deployment (use OAuth authentication instead)

### Validation & Security Scanning
**File**: `Validate-AzureFilesDeployment.ps1`
**Purpose**: Post-deployment security assessment and compliance validation

## Authentication Approaches

### Recommended: Manual Deployment with OAuth
```powershell
# For human operators - browser authentication prompt
.\Deploy-SecureAzureFiles.ps1 -SubscriptionId "xxx" -TenantId "xxx" -ResourceGroupName "xxx" -StorageAccountName "xxx" -Location "xxx"
```

### Automation: Service Principal with Certificate
```powershell
# For CI/CD and unattended scenarios only
# First create service principal:
.\Onboard-AzureFiles-ServicePrincipal.ps1 -TenantId "xxx" -SubscriptionId "xxx"
# Then use generated deployment script
```

## Integration Patterns

### Intune Modern Device Management
**File**: `HowTo-Mount-FileShare-Intune.md`
**Approach**: Uses Administrative Templates and OMA-URI configurations (NOT legacy net use commands)

**Configuration Profile Types**:
- **Administrative Templates** - Group Policy-based file share mapping
- **OMA-URI Settings** - Direct registry configuration for advanced scenarios
- **Settings Catalog** - Modern Intune configuration experience

### Azure Key Vault Integration
- Customer-managed encryption keys for sensitive data
- Automatic key rotation support
- Integration with Key Vault access policies

### Log Analytics Integration
- Diagnostic settings for security monitoring
- Custom log queries for compliance reporting
- Integration with Azure Security Center

## Security Validation Patterns

### Pre-Deployment Checks
- PowerShell 7+ compatibility validation
- Required Azure module verification
- Permission validation with fail-fast error handling
- Network connectivity and DNS resolution testing

### Post-Deployment Validation
- Security configuration verification
- Network access control testing
- Azure AD authentication validation
- Backup configuration confirmation

## Multi-Tenant Support

### MSP and Enterprise Scenarios
- **TenantId parameter is MANDATORY** - Prevents multi-tenant authentication confusion
- Support for cross-tenant deployment scenarios
- Clear tenant isolation and security boundaries
- Backward compatibility maintained for existing deployments

### Tenant-Specific Configurations
- Tenant-aware resource naming conventions
- Isolated permission scopes per tenant
- Customer-specific security requirements

## Error Handling & Troubleshooting

### Common Authentication Issues
- **Multi-tenant access conflicts** - Resolved by mandatory TenantId parameter
- **Guest account authentication** - Explicit tenant targeting prevents wrong tenant selection
- **Subscription-tenant mismatches** - Validation ensures consistent tenant context

### Storage Account Issues
- **Name already exists** - Storage account names must be globally unique
- **VNet service endpoint not configured** - Script automatically configures endpoints
- **Key Vault access denied** - Ensure proper permissions on Key Vault for managed identity

### Network Connectivity
- **SMB port 445 testing** - `Test-NetConnection -Port 445`
- **HTTPS connectivity verification** - `Test-NetConnection -Port 443`
- **DNS resolution validation** - Ensure storage account FQDN resolves correctly

## Compliance & Governance

### Security Standards Implemented
- **HTTPS-only enforcement** - Industry standard for secure communications
- **Modern TLS requirements** - TLS 1.2 minimum for encryption standards
- **Identity-based authentication** - Azure AD integration eliminates shared key risks
- **Network isolation** - VNet integration and private endpoints for enhanced security

### Audit and Compliance Features
- **Complete deployment logging** - All actions logged for audit trails
- **Configuration validation** - Post-deployment security verification
- **Role-based access control** - Granular permission management
- **Change tracking** - File versioning and soft delete for compliance

## AI Agent Guidelines

### When Working on Azure Files Infrastructure
1. **Always require TenantId parameter** - Never make it optional in infrastructure scripts
2. **Implement security-first design** - All security controls should be enabled by default
3. **Use least-privilege group patterns** - Create dedicated Azure AD groups instead of requiring Global Admin
4. **Follow modern device management** - Integrate with Intune using configuration profiles
5. **Validate networking integration** - Ensure VNet service endpoints and private endpoint support
6. **Implement comprehensive error handling** - Provide actionable error messages with fix instructions

### Testing and Validation Requirements
- **WhatIf mode support** - Safe testing capabilities for all operations
- **PowerShell 7+ compatibility** - Enforce version requirements and module validation
- **Multi-scenario testing** - Basic, VNet-integrated, premium storage, and IP-restricted deployments
- **Security validation** - Verify all security controls are properly configured

### Documentation Standards
- **Update all deployment examples** - Include TenantId in all sample commands
- **Maintain parameter documentation** - Clear requirements and validation patterns
- **Security justification** - Document why each security control is implemented
- **Integration guidance** - Clear instructions for Intune, Key Vault, and monitoring integration

## Version History & Evolution

### Current Version: 3.0.0
- **Added**: TenantId mandatory parameter for targeted authentication
- **Enhanced**: Multi-tenant support with backward compatibility
- **Improved**: Least-privilege group provisioning automation
- **Added**: Comprehensive Intune integration documentation
- **Enhanced**: PowerShell 7+ compatibility validation

### Future Enhancements
- **Automated backup configuration** - Integration with Azure Backup services
- **Enhanced monitoring** - Custom dashboards and alerting rules
- **Policy automation** - Azure Policy integration for governance
- **Advanced networking** - Private DNS zone automation and hybrid connectivity

---

**Critical Success Factors for AI Agents**:
1. **Security First**: Always implement all security controls - never compromise on security for convenience
2. **Explicit Authentication**: Always require TenantId to prevent authentication issues
3. **Modern Management**: Use Intune configuration profiles, not legacy approaches
4. **Comprehensive Validation**: Test all deployment scenarios and security configurations
5. **Clear Documentation**: Maintain examples and guidance for enterprise deployment patterns