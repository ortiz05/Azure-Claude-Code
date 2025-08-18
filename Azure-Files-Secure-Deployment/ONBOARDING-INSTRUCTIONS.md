# Azure Files Automation - Secure Onboarding Instructions

## 🎯 Purpose
This onboarding script creates a dedicated Service Principal with minimal required permissions for deploying Azure Files infrastructure. It follows security best practices including certificate-based authentication, least privilege access, and secure credential storage.

## 🔒 Security Features
- **Least Privilege**: Only assigns minimum required Azure RBAC roles
- **Certificate Authentication**: Uses 4096-bit RSA certificates (recommended)
- **No Global Permissions**: Scoped to specific subscription or resource group
- **Secure Storage**: Optional Key Vault integration for credential storage
- **Audit Trail**: Tagged Service Principal for governance tracking
- **Time-Limited**: Certificates expire after configured period (default 365 days)

## 📋 Prerequisites

### Required Permissions
- **Global Administrator** role in Azure AD (for initial setup only)
- **Owner** or **User Access Administrator** role on target subscription
- **Key Vault Contributor** (optional, if using Key Vault storage)

### Required Tools
- **Azure PowerShell** modules (Az.Accounts, Az.Resources, Az.KeyVault)
- **PowerShell 5.1** or later (PowerShell 7+ recommended)
- **Certificate store access** (for certificate generation)

### Install Required Modules
```powershell
# Install Azure PowerShell modules if not present
Install-Module -Name Az -Scope CurrentUser -Force
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
Install-Module -Name Az.Resources -Scope CurrentUser -Force
Install-Module -Name Az.KeyVault -Scope CurrentUser -Force
```

## 🚀 Running the Onboarding Script

### Step 1: Gather Required Information
```powershell
# Required parameters
$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"        # Your Azure AD Tenant ID
$SubscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # Target subscription ID

# Optional parameters
$ResourceGroupName = "rg-storage-prod"  # Optional: Scope to specific RG
$KeyVaultName = "kv-secrets-prod"       # Optional: Store credentials in Key Vault
```

### Step 2: Basic Execution (Certificate Authentication)
```powershell
# Run with default certificate authentication (RECOMMENDED)
.\Onboard-AzureFilesAutomation.ps1 `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId
```

### Step 3: Advanced Execution Options

#### Option A: Scope to Resource Group
```powershell
# Limit permissions to specific resource group
.\Onboard-AzureFilesAutomation.ps1 `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName "rg-storage-prod"
```

#### Option B: With Key Vault Storage
```powershell
# Store credentials securely in Key Vault
.\Onboard-AzureFilesAutomation.ps1 `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -KeyVaultName "kv-secrets-prod"
```

#### Option C: Custom Certificate Settings
```powershell
# Custom certificate configuration
.\Onboard-AzureFilesAutomation.ps1 `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -CertificateSubject "CN=AzureFilesAutomationProd" `
    -CertificateValidityDays 90  # Shorter validity for higher security
```

#### Option D: Test Mode (WhatIf)
```powershell
# Test without making changes
.\Onboard-AzureFilesAutomation.ps1 `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -WhatIf
```

## 📝 Script Execution Flow

1. **Authentication**: Connects to Azure with your Global Admin account
2. **Validation**: Verifies Global Admin privileges
3. **Certificate Creation**: Generates 4096-bit RSA certificate
4. **Service Principal**: Creates SP with descriptive name and tags
5. **Role Assignment**: Assigns only required RBAC roles
6. **Credential Export**: Exports certificates with password protection
7. **Documentation**: Generates deployment scripts and README
8. **Key Vault Storage**: Optionally stores credentials securely

## 📁 Output Files

After successful execution, find these files in `.\AzureFilesOnboarding\`:

| File | Description | Security Classification |
|------|-------------|------------------------|
| `ONBOARDING-README.md` | Complete documentation and usage instructions | Internal Use |
| `Deploy-AzureFiles-WithServicePrincipal.ps1` | Ready-to-use deployment script | Internal Use |
| `Onboarding-Azure-Files-Automation.cer` | Public certificate for Azure AD | Safe to Share |
| `Onboarding-Azure-Files-Automation.pfx` | Private certificate with password | **HIGHLY SENSITIVE** |

## 🔐 Post-Onboarding Security Tasks

### 1. Secure the Private Certificate
```powershell
# Import to Windows Certificate Store (recommended)
$PfxPath = ".\AzureFilesOnboarding\Onboarding-Azure-Files-Automation.pfx"
$Password = Read-Host "Enter PFX password" -AsSecureString
Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $Password

# Delete the PFX file after importing
Remove-Item $PfxPath -Force
```

### 2. Verify Service Principal
```powershell
# Check Service Principal was created
Get-AzADServicePrincipal -DisplayName "Onboarding-Azure-Files-Automation"

# Verify role assignments
Get-AzRoleAssignment -ObjectId (Get-AzADServicePrincipal -DisplayName "Onboarding-Azure-Files-Automation").Id
```

### 3. Test Authentication
```powershell
# Test Service Principal authentication
$TenantId = "your-tenant-id"
$ApplicationId = "generated-app-id"  # From output
$Thumbprint = "certificate-thumbprint"  # From output

Connect-AzAccount `
    -ServicePrincipal `
    -TenantId $TenantId `
    -ApplicationId $ApplicationId `
    -CertificateThumbprint $Thumbprint

# Verify connection
Get-AzContext
```

## 🔄 Certificate Rotation

### Schedule Regular Rotation (Every 90 Days)
```powershell
# Generate new certificate
$NewCert = New-SelfSignedCertificate `
    -Subject "CN=AzureFilesAutomationProd" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddDays(90)

# Update Service Principal
$SP = Get-AzADServicePrincipal -DisplayName "Onboarding-Azure-Files-Automation"
New-AzADServicePrincipalCredential `
    -ObjectId $SP.Id `
    -CertValue ([System.Convert]::ToBase64String($NewCert.GetRawCertData())) `
    -EndDate $NewCert.NotAfter `
    -StartDate $NewCert.NotBefore

# Remove old certificate after verification
```

## 🚨 Troubleshooting

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "Not a Global Administrator" | Insufficient privileges | Run as Global Admin or use `-SkipGlobalAdminValidation` (not recommended) |
| "Failed to create certificate" | Certificate store access denied | Run PowerShell as Administrator |
| "Role assignment failed" | Propagation delay | Wait 5-10 minutes and retry |
| "Key Vault access denied" | Missing Key Vault permissions | Ensure you have Key Vault Contributor role |
| "Service Principal already exists" | Previous onboarding attempt | Script will prompt to reset credentials |

### Validation Commands
```powershell
# Check Azure connection
Get-AzContext

# Verify Global Admin role
$CurrentUser = Get-AzADUser -SignedIn
Get-AzADDirectoryRoleMember -DirectoryRoleDisplayName "Global Administrator" | 
    Where-Object {$_.Id -eq $CurrentUser.Id}

# List existing Service Principals
Get-AzADServicePrincipal | Where-Object {$_.DisplayName -like "*Azure-Files*"}

# Check role assignments
Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" | 
    Where-Object {$_.ObjectType -eq "ServicePrincipal"}
```

## 🔍 Monitoring and Compliance

### Track Service Principal Usage
```powershell
# Monitor activity in Azure Activity Log
Get-AzLog -StartTime (Get-Date).AddDays(-7) | 
    Where-Object {$_.Caller -like "*Onboarding-Azure-Files*"}

# Check authentication events
Get-AzADServicePrincipalSignInActivity -ServicePrincipalId $SP.Id
```

### Regular Security Reviews
1. **Monthly**: Review Service Principal activity logs
2. **Quarterly**: Validate role assignments still appropriate
3. **Before Certificate Expiry**: Rotate certificates (30 days before)
4. **Annually**: Complete security audit of all Service Principals

## 🧹 Cleanup (If Needed)

### Remove Service Principal and Permissions
```powershell
# Get Service Principal
$SP = Get-AzADServicePrincipal -DisplayName "Onboarding-Azure-Files-Automation"

# Remove all role assignments
Get-AzRoleAssignment -ObjectId $SP.Id | Remove-AzRoleAssignment

# Delete Service Principal
Remove-AzADServicePrincipal -ObjectId $SP.Id -Force

# Clean up Key Vault secrets (if used)
$Secrets = @("AzureFiles-SP-AppId", "AzureFiles-SP-TenantId", "AzureFiles-SP-Thumbprint")
foreach ($Secret in $Secrets) {
    Remove-AzKeyVaultSecret -VaultName $KeyVaultName -Name $Secret -Force
}
```

## 📞 Support

For issues or questions:
1. Review the generated `ONBOARDING-README.md` for specific details
2. Check Azure Activity Logs for detailed error messages
3. Verify prerequisites and permissions are correct
4. Ensure network connectivity to Azure endpoints

## ⚠️ Security Warnings

- **NEVER** commit the PFX file or credentials to source control
- **NEVER** share the private certificate password
- **ALWAYS** use certificate authentication over client secrets
- **ALWAYS** scope permissions to minimum required level
- **REGULARLY** rotate certificates and review permissions
- **MONITOR** Service Principal usage for anomalies

---
*This is a security-sensitive process. Follow your organization's security policies and procedures.*