# Onboard-AzureFiles-ServicePrincipal.ps1
# Creates a Service Principal for AUTOMATED Azure Files deployment
# 
# ⚠️  ONLY NEEDED FOR: Service Principal authentication (CI/CD, API automation)
# ❌  NOT NEEDED FOR: Manual deployment with your Global Admin account (OAuth)
# 
# Use this script ONLY if you need unattended/automated deployment.
# For manual deployment, simply run Deploy-SecureAzureFiles.ps1 directly.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "Onboarding-Azure-Files-Automation",
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "",  # Optional: Scope permissions to specific RG
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Certificate", "ClientSecret")]
    [string]$AuthenticationType = "Certificate",
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateSubject = "CN=AzureFilesAutomationSP",
    
    [Parameter(Mandatory = $false)]
    [int]$CertificateValidityDays = 365,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = "",  # Optional: Store credentials in Key Vault
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AzureFilesOnboarding",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipGlobalAdminValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# Security banner
Write-Host @"
=========================================
 AZURE FILES AUTOMATION ONBOARDING
 Security-First Service Principal Setup
=========================================
"@ -ForegroundColor Cyan

Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Subscription ID: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Service Principal Name: $ServicePrincipalName" -ForegroundColor Yellow
Write-Host "Authentication Type: $AuthenticationType" -ForegroundColor Yellow
Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
Write-Host "=========================================`n" -ForegroundColor Cyan

# Required Azure RBAC roles for Azure Files deployment
$RequiredRoles = @(
    @{
        Name = "Storage Account Contributor"
        Reason = "Create and manage storage accounts"
        Scope = "Subscription or Resource Group"
    },
    @{
        Name = "Network Contributor"
        Reason = "Configure VNet integration and service endpoints"
        Scope = "Subscription or Resource Group"
    },
    @{
        Name = "Key Vault Contributor"
        Reason = "Configure customer-managed encryption (optional)"
        Scope = "Key Vault resource (if used)"
    },
    @{
        Name = "Log Analytics Contributor"
        Reason = "Configure monitoring and diagnostics (optional)"
        Scope = "Log Analytics workspace (if used)"
    }
)

# Function to validate Global Admin privileges
function Test-GlobalAdminPrivileges {
    if ($SkipGlobalAdminValidation) {
        Write-Warning "Skipping Global Admin validation (not recommended for production)"
        return $true
    }
    
    try {
        Write-Host "Validating Global Administrator privileges..." -ForegroundColor Yellow
        
        $CurrentUser = Get-AzADUser -SignedIn
        $GlobalAdminRole = Get-AzADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
        
        if ($GlobalAdminRole) {
            $GlobalAdmins = Get-AzADDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id
            $IsGlobalAdmin = $GlobalAdmins | Where-Object {$_.Id -eq $CurrentUser.Id}
            
            if ($IsGlobalAdmin) {
                Write-Host "✓ Confirmed: Running as Global Administrator" -ForegroundColor Green
                Write-Host "  User: $($CurrentUser.UserPrincipalName)" -ForegroundColor Gray
                return $true
            }
        }
        
        Write-Error "Current user is not a Global Administrator. Please run as Global Admin or use -SkipGlobalAdminValidation (not recommended)."
        return $false
        
    } catch {
        Write-Error "Failed to validate Global Admin privileges: $($_.Exception.Message)"
        return $false
    }
}

# Function to connect to Azure
function Connect-ToAzureTenant {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        
        # Check existing connection
        $Context = Get-AzContext
        if ($Context -and $Context.Tenant.Id -eq $TenantId -and $Context.Subscription.Id -eq $SubscriptionId) {
            Write-Host "✓ Already connected to correct tenant and subscription" -ForegroundColor Green
            return $true
        }
        
        # Connect with specific tenant and subscription
        Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId
        
        # Verify connection
        $Context = Get-AzContext
        if ($Context.Tenant.Id -ne $TenantId) {
            throw "Connected to wrong tenant. Expected: $TenantId, Got: $($Context.Tenant.Id)"
        }
        
        Write-Host "✓ Connected to Azure" -ForegroundColor Green
        Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
        Write-Host "  Subscription: $($Context.Subscription.Name)" -ForegroundColor Gray
        return $true
        
    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        return $false
    }
}

# Function to create certificate for authentication
function New-ServicePrincipalCertificate {
    param(
        [string]$Subject,
        [int]$ValidityDays
    )
    
    try {
        Write-Host "Creating self-signed certificate..." -ForegroundColor Yellow
        
        $CertParameters = @{
            Subject = $Subject
            CertStoreLocation = "Cert:\CurrentUser\My"
            KeyExportPolicy = "Exportable"
            KeySpec = "Signature"
            KeyLength = 4096  # Enhanced security with 4096-bit key
            KeyAlgorithm = "RSA"
            HashAlgorithm = "SHA256"
            NotAfter = (Get-Date).AddDays($ValidityDays)
            Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        }
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create certificate with subject: $Subject" -ForegroundColor Yellow
            return $null
        }
        
        $Certificate = New-SelfSignedCertificate @CertParameters
        
        Write-Host "✓ Certificate created successfully" -ForegroundColor Green
        Write-Host "  Thumbprint: $($Certificate.Thumbprint)" -ForegroundColor Gray
        Write-Host "  Expires: $($Certificate.NotAfter)" -ForegroundColor Gray
        
        return $Certificate
        
    } catch {
        Write-Error "Failed to create certificate: $($_.Exception.Message)"
        return $null
    }
}

# Function to create service principal
function New-AutomationServicePrincipal {
    param(
        [string]$DisplayName,
        [string]$AuthType,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    try {
        Write-Host "Creating Service Principal..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create Service Principal: $DisplayName" -ForegroundColor Yellow
            return $null
        }
        
        # Check if SP already exists
        $ExistingSP = Get-AzADServicePrincipal -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if ($ExistingSP) {
            Write-Warning "Service Principal already exists: $DisplayName"
            $Response = Read-Host "Do you want to reset its credentials? (y/n)"
            if ($Response -ne 'y') {
                return $ExistingSP
            }
            # Remove existing SP to recreate
            Remove-AzADServicePrincipal -ObjectId $ExistingSP.Id -Force
            Start-Sleep -Seconds 5  # Wait for deletion to propagate
        }
        
        if ($AuthType -eq "Certificate") {
            # Create SP with certificate
            $CertValue = [System.Convert]::ToBase64String($Certificate.GetRawCertData())
            $ServicePrincipal = New-AzADServicePrincipal `
                -DisplayName $DisplayName `
                -CertValue $CertValue `
                -EndDate $Certificate.NotAfter `
                -StartDate $Certificate.NotBefore
        } else {
            # Create SP with client secret
            $ServicePrincipal = New-AzADServicePrincipal `
                -DisplayName $DisplayName
        }
        
        Write-Host "✓ Service Principal created successfully" -ForegroundColor Green
        Write-Host "  Application ID: $($ServicePrincipal.AppId)" -ForegroundColor Gray
        Write-Host "  Object ID: $($ServicePrincipal.Id)" -ForegroundColor Gray
        
        # Add application tags for governance
        Update-AzADServicePrincipal -ObjectId $ServicePrincipal.Id -Tag @(
            "AzureFilesAutomation",
            "ManagedDeployment",
            "CreatedBy:OnboardingScript",
            "CreatedDate:$(Get-Date -Format 'yyyy-MM-dd')"
        )
        
        return $ServicePrincipal
        
    } catch {
        Write-Error "Failed to create Service Principal: $($_.Exception.Message)"
        return $null
    }
}

# Function to assign required roles
function Set-ServicePrincipalRoles {
    param(
        [object]$ServicePrincipal,
        [string]$SubscriptionId,
        [string]$ResourceGroupName
    )
    
    try {
        Write-Host "Assigning Azure RBAC roles..." -ForegroundColor Yellow
        
        # Determine scope
        if ($ResourceGroupName) {
            $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
            Write-Host "Scope: Resource Group - $ResourceGroupName" -ForegroundColor Gray
        } else {
            $Scope = "/subscriptions/$SubscriptionId"
            Write-Host "Scope: Subscription" -ForegroundColor Gray
        }
        
        # Core required roles for Azure Files deployment
        $RolesToAssign = @(
            "Storage Account Contributor",
            "Network Contributor"
        )
        
        foreach ($RoleName in $RolesToAssign) {
            Write-Host "  Assigning role: $RoleName" -ForegroundColor Gray
            
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would assign role: $RoleName" -ForegroundColor Yellow
                continue
            }
            
            # Check if role assignment already exists
            $ExistingAssignment = Get-AzRoleAssignment `
                -ObjectId $ServicePrincipal.Id `
                -RoleDefinitionName $RoleName `
                -Scope $Scope `
                -ErrorAction SilentlyContinue
            
            if (-not $ExistingAssignment) {
                New-AzRoleAssignment `
                    -ObjectId $ServicePrincipal.Id `
                    -RoleDefinitionName $RoleName `
                    -Scope $Scope `
                    -ErrorAction Stop | Out-Null
                
                Write-Host "    ✓ Assigned: $RoleName" -ForegroundColor Green
            } else {
                Write-Host "    ℹ Already assigned: $RoleName" -ForegroundColor Gray
            }
        }
        
        # Optional roles with specific scopes
        if ($KeyVaultName) {
            Write-Host "  Assigning Key Vault Contributor role..." -ForegroundColor Gray
            $KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
            if ($KeyVault) {
                New-AzRoleAssignment `
                    -ObjectId $ServicePrincipal.Id `
                    -RoleDefinitionName "Key Vault Contributor" `
                    -Scope $KeyVault.ResourceId `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        }
        
        Write-Host "✓ Role assignments completed" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to assign roles: $($_.Exception.Message)"
        return $false
    }
}

# Function to export certificate
function Export-ServicePrincipalCertificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$OutputPath,
        [string]$ServicePrincipalName
    )
    
    try {
        Write-Host "Exporting certificate..." -ForegroundColor Yellow
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Export certificate without private key (public certificate)
        $CerPath = Join-Path $OutputPath "$ServicePrincipalName.cer"
        $CerBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($CerPath, $CerBytes)
        
        # Export certificate with private key (for secure storage)
        $PfxPath = Join-Path $OutputPath "$ServicePrincipalName.pfx"
        $SecurePassword = Read-Host "Enter password for PFX file" -AsSecureString
        $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $SecurePassword) | 
            Set-Content -Path $PfxPath -Encoding Byte
        
        Write-Host "✓ Certificate exported" -ForegroundColor Green
        Write-Host "  Public certificate: $CerPath" -ForegroundColor Gray
        Write-Host "  Private certificate: $PfxPath" -ForegroundColor Gray
        
        return @{
            CerPath = $CerPath
            PfxPath = $PfxPath
            SecurePassword = $SecurePassword
        }
        
    } catch {
        Write-Error "Failed to export certificate: $($_.Exception.Message)"
        return $null
    }
}

# Function to store credentials in Key Vault
function Save-CredentialsToKeyVault {
    param(
        [string]$KeyVaultName,
        [object]$ServicePrincipal,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [SecureString]$ClientSecret
    )
    
    if (-not $KeyVaultName) {
        Write-Host "No Key Vault specified - skipping secure storage" -ForegroundColor Gray
        return $true
    }
    
    try {
        Write-Host "Storing credentials in Key Vault..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would store credentials in Key Vault: $KeyVaultName" -ForegroundColor Yellow
            return $true
        }
        
        # Store Application ID
        $AppIdSecret = ConvertTo-SecureString $ServicePrincipal.AppId -AsPlainText -Force
        Set-AzKeyVaultSecret `
            -VaultName $KeyVaultName `
            -Name "AzureFiles-SP-AppId" `
            -SecretValue $AppIdSecret `
            -Tag @{Purpose="AzureFilesAutomation"; Type="ApplicationId"} | Out-Null
        
        # Store Tenant ID
        $TenantIdSecret = ConvertTo-SecureString $TenantId -AsPlainText -Force
        Set-AzKeyVaultSecret `
            -VaultName $KeyVaultName `
            -Name "AzureFiles-SP-TenantId" `
            -SecretValue $TenantIdSecret `
            -Tag @{Purpose="AzureFilesAutomation"; Type="TenantId"} | Out-Null
        
        if ($Certificate) {
            # Store certificate thumbprint
            $ThumbprintSecret = ConvertTo-SecureString $Certificate.Thumbprint -AsPlainText -Force
            Set-AzKeyVaultSecret `
                -VaultName $KeyVaultName `
                -Name "AzureFiles-SP-Thumbprint" `
                -SecretValue $ThumbprintSecret `
                -Tag @{Purpose="AzureFilesAutomation"; Type="CertificateThumbprint"} | Out-Null
        }
        
        if ($ClientSecret) {
            # Store client secret
            Set-AzKeyVaultSecret `
                -VaultName $KeyVaultName `
                -Name "AzureFiles-SP-Secret" `
                -SecretValue $ClientSecret `
                -Tag @{Purpose="AzureFilesAutomation"; Type="ClientSecret"} | Out-Null
        }
        
        Write-Host "✓ Credentials stored in Key Vault" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to store credentials in Key Vault: $($_.Exception.Message)"
        return $false
    }
}

# Function to generate deployment script
function New-DeploymentScript {
    param(
        [object]$ServicePrincipal,
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$AuthType,
        [string]$CertificateThumbprint,
        [string]$OutputPath
    )
    
    try {
        Write-Host "Generating deployment script..." -ForegroundColor Yellow
        
        $ScriptPath = Join-Path $OutputPath "Deploy-AzureFiles-WithServicePrincipal.ps1"
        
        $ScriptContent = @"
# Deploy-AzureFiles-WithServicePrincipal.ps1
# Auto-generated script for Azure Files deployment using Service Principal
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

param(
    [Parameter(Mandatory = `$true)]
    [string]`$ResourceGroupName,
    
    [Parameter(Mandatory = `$true)]
    [string]`$StorageAccountName,
    
    [Parameter(Mandatory = `$true)]
    [string]`$Location,
    
    [Parameter(Mandatory = `$false)]
    [string]`$FileShareName = "secure-fileshare"
)

`$ErrorActionPreference = "Stop"

Write-Host "Connecting to Azure using Service Principal..." -ForegroundColor Yellow

# Service Principal details (DO NOT COMMIT TO SOURCE CONTROL)
`$TenantId = "$TenantId"
`$SubscriptionId = "$SubscriptionId"
`$ApplicationId = "$($ServicePrincipal.AppId)"

$(if ($AuthType -eq "Certificate") {
@"
# Certificate authentication
`$CertificateThumbprint = "$CertificateThumbprint"

# Connect using certificate
Connect-AzAccount ``
    -ServicePrincipal ``
    -TenantId `$TenantId ``
    -ApplicationId `$ApplicationId ``
    -CertificateThumbprint `$CertificateThumbprint ``
    -SubscriptionId `$SubscriptionId
"@
} else {
@"
# Client secret authentication
`$SecureSecret = Read-Host "Enter Service Principal secret" -AsSecureString
`$Credential = New-Object System.Management.Automation.PSCredential(`$ApplicationId, `$SecureSecret)

# Connect using client secret
Connect-AzAccount ``
    -ServicePrincipal ``
    -TenantId `$TenantId ``
    -Credential `$Credential ``
    -SubscriptionId `$SubscriptionId
"@
})

Write-Host "✓ Connected to Azure" -ForegroundColor Green

# Run the main deployment script
`$DeploymentScript = Join-Path `$PSScriptRoot "..\..\Deploy-SecureAzureFiles.ps1"
if (Test-Path `$DeploymentScript) {
    & `$DeploymentScript ``
        -SubscriptionId `$SubscriptionId ``
        -ResourceGroupName `$ResourceGroupName ``
        -StorageAccountName `$StorageAccountName ``
        -Location `$Location ``
        -FileShareName `$FileShareName
} else {
    Write-Error "Deployment script not found: `$DeploymentScript"
}
"@
        
        $ScriptContent | Out-File -FilePath $ScriptPath -Encoding UTF8
        Write-Host "✓ Deployment script generated: $ScriptPath" -ForegroundColor Green
        
        return $ScriptPath
        
    } catch {
        Write-Error "Failed to generate deployment script: $($_.Exception.Message)"
        return $null
    }
}

# Function to generate documentation
function New-OnboardingDocumentation {
    param(
        [object]$ServicePrincipal,
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$AuthType,
        [string]$OutputPath,
        [hashtable]$CertificateInfo
    )
    
    try {
        Write-Host "Generating documentation..." -ForegroundColor Yellow
        
        $DocPath = Join-Path $OutputPath "ONBOARDING-README.md"
        
        $Documentation = @"
# Azure Files Automation - Service Principal Onboarding

## Overview
This Service Principal has been created specifically for Azure Files deployment automation with minimal required permissions.

## Service Principal Details
- **Name**: $($ServicePrincipal.DisplayName)
- **Application ID**: $($ServicePrincipal.AppId)
- **Object ID**: $($ServicePrincipal.Id)
- **Tenant ID**: $TenantId
- **Subscription ID**: $SubscriptionId
- **Authentication Type**: $AuthType
- **Created Date**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Assigned Permissions
The following Azure RBAC roles have been assigned:

| Role | Scope | Purpose |
|------|-------|---------|
| Storage Account Contributor | Subscription/RG | Create and manage storage accounts |
| Network Contributor | Subscription/RG | Configure VNet integration |
$(if ($KeyVaultName) { "| Key Vault Contributor | Key Vault | Customer-managed encryption |" })

## Authentication Methods

### Using Certificate (Recommended)
```powershell
Connect-AzAccount ``
    -ServicePrincipal ``
    -TenantId "$TenantId" ``
    -ApplicationId "$($ServicePrincipal.AppId)" ``
    -CertificateThumbprint "THUMBPRINT" ``
    -SubscriptionId "$SubscriptionId"
```

### Using Client Secret
```powershell
`$SecureSecret = ConvertTo-SecureString "YOUR-SECRET" -AsPlainText -Force
`$Credential = New-Object PSCredential("$($ServicePrincipal.AppId)", `$SecureSecret)

Connect-AzAccount ``
    -ServicePrincipal ``
    -TenantId "$TenantId" ``
    -Credential `$Credential ``
    -SubscriptionId "$SubscriptionId"
```

## Certificate Management
$(if ($CertificateInfo) {
@"
- **Public Certificate**: ``$($CertificateInfo.CerPath)``
- **Private Certificate (PFX)**: ``$($CertificateInfo.PfxPath)``
- **Certificate Expiry**: Check certificate expiration and rotate before expiry
"@
})

## Security Best Practices

1. **Credential Storage**
   - Store certificates in secure certificate store
   - Use Azure Key Vault for production environments
   - Never commit credentials to source control

2. **Access Control**
   - Regularly review role assignments
   - Use Just-In-Time (JIT) access when possible
   - Monitor Service Principal usage in Azure Activity Logs

3. **Rotation Schedule**
   - Rotate certificates/secrets every 90 days
   - Update deployment scripts after rotation
   - Test in non-production environment first

## Deployment Usage

1. Use the generated deployment script:
   ``````powershell
   .\Deploy-AzureFiles-WithServicePrincipal.ps1 ``
       -ResourceGroupName "rg-storage" ``
       -StorageAccountName "stgsecure001" ``
       -Location "East US 2" ``
       -FileShareName "company-files"
   ``````

2. Or integrate with CI/CD pipeline (Azure DevOps, GitHub Actions)

## Monitoring and Compliance

### Activity Monitoring
```powershell
# Check Service Principal activity
Get-AzLog -StartTime (Get-Date).AddDays(-7) | 
    Where-Object {`$_.Caller -eq "$($ServicePrincipal.AppId)"}
```

### Role Assignment Audit
```powershell
# Review current role assignments
Get-AzRoleAssignment -ObjectId "$($ServicePrincipal.Id)"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Authentication failed | Verify certificate is installed/thumbprint is correct |
| Insufficient permissions | Check role assignments are active |
| Certificate expired | Rotate certificate and update Service Principal |

## Support
For issues or questions:
1. Review Azure Activity Logs for detailed error messages
2. Verify Service Principal status in Azure AD
3. Check role assignment propagation (may take up to 30 minutes)

## Cleanup (if needed)
To remove this Service Principal and its permissions:
```powershell
Remove-AzADServicePrincipal -ObjectId "$($ServicePrincipal.Id)" -Force
```

---
*Generated by Secure Onboarding Script*
*Classification: Internal Use Only*
"@
        
        $Documentation | Out-File -FilePath $DocPath -Encoding UTF8
        Write-Host "✓ Documentation generated: $DocPath" -ForegroundColor Green
        
        return $DocPath
        
    } catch {
        Write-Error "Failed to generate documentation: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
try {
    # Step 1: Connect to Azure
    if (-not (Connect-ToAzureTenant)) {
        throw "Failed to connect to Azure"
    }
    
    # Step 2: Validate Global Admin privileges
    if (-not (Test-GlobalAdminPrivileges)) {
        throw "Global Administrator validation failed"
    }
    
    # Step 3: Create authentication credentials
    $Certificate = $null
    $ClientSecret = $null
    
    if ($AuthenticationType -eq "Certificate") {
        $Certificate = New-ServicePrincipalCertificate -Subject $CertificateSubject -ValidityDays $CertificateValidityDays
        if (-not $Certificate -and -not $WhatIf) {
            throw "Failed to create certificate"
        }
    }
    
    # Step 4: Create Service Principal
    $ServicePrincipal = New-AutomationServicePrincipal `
        -DisplayName $ServicePrincipalName `
        -AuthType $AuthenticationType `
        -Certificate $Certificate
    
    if (-not $ServicePrincipal -and -not $WhatIf) {
        throw "Failed to create Service Principal"
    }
    
    # Step 5: Assign required roles
    if ($ServicePrincipal) {
        $RolesAssigned = Set-ServicePrincipalRoles `
            -ServicePrincipal $ServicePrincipal `
            -SubscriptionId $SubscriptionId `
            -ResourceGroupName $ResourceGroupName
        
        if (-not $RolesAssigned -and -not $WhatIf) {
            throw "Failed to assign roles"
        }
    }
    
    # Step 6: Export credentials and generate artifacts
    if (-not $WhatIf) {
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Export certificate if used
        $CertificateInfo = $null
        if ($Certificate) {
            $CertificateInfo = Export-ServicePrincipalCertificate `
                -Certificate $Certificate `
                -OutputPath $OutputPath `
                -ServicePrincipalName $ServicePrincipalName
        }
        
        # Store in Key Vault if specified
        if ($KeyVaultName) {
            Save-CredentialsToKeyVault `
                -KeyVaultName $KeyVaultName `
                -ServicePrincipal $ServicePrincipal `
                -Certificate $Certificate `
                -ClientSecret $ClientSecret
        }
        
        # Generate deployment script
        $DeploymentScript = New-DeploymentScript `
            -ServicePrincipal $ServicePrincipal `
            -TenantId $TenantId `
            -SubscriptionId $SubscriptionId `
            -AuthType $AuthenticationType `
            -CertificateThumbprint $(if ($Certificate) { $Certificate.Thumbprint } else { "" }) `
            -OutputPath $OutputPath
        
        # Generate documentation
        $Documentation = New-OnboardingDocumentation `
            -ServicePrincipal $ServicePrincipal `
            -TenantId $TenantId `
            -SubscriptionId $SubscriptionId `
            -AuthType $AuthenticationType `
            -OutputPath $OutputPath `
            -CertificateInfo $CertificateInfo
    }
    
    # Summary
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " ONBOARDING COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    
    if (-not $WhatIf) {
        Write-Host "`n📋 Service Principal Details:" -ForegroundColor Cyan
        Write-Host "  Name: $($ServicePrincipal.DisplayName)" -ForegroundColor White
        Write-Host "  Application ID: $($ServicePrincipal.AppId)" -ForegroundColor White
        Write-Host "  Object ID: $($ServicePrincipal.Id)" -ForegroundColor White
        
        Write-Host "`n🔐 Authentication:" -ForegroundColor Cyan
        if ($Certificate) {
            Write-Host "  Type: Certificate" -ForegroundColor White
            Write-Host "  Thumbprint: $($Certificate.Thumbprint)" -ForegroundColor White
            Write-Host "  Expires: $($Certificate.NotAfter)" -ForegroundColor White
        } else {
            Write-Host "  Type: Client Secret" -ForegroundColor White
        }
        
        Write-Host "`n📁 Output Files:" -ForegroundColor Cyan
        Write-Host "  Directory: $OutputPath" -ForegroundColor White
        Write-Host "  - ONBOARDING-README.md (Documentation)" -ForegroundColor Gray
        Write-Host "  - Deploy-AzureFiles-WithServicePrincipal.ps1 (Deployment script)" -ForegroundColor Gray
        if ($Certificate) {
            Write-Host "  - $ServicePrincipalName.cer (Public certificate)" -ForegroundColor Gray
            Write-Host "  - $ServicePrincipalName.pfx (Private certificate - KEEP SECURE)" -ForegroundColor Gray
        }
        
        Write-Host "`n⚠️ Important Security Notes:" -ForegroundColor Yellow
        Write-Host "  1. Store the PFX file and password securely" -ForegroundColor White
        Write-Host "  2. Never commit credentials to source control" -ForegroundColor White
        Write-Host "  3. Rotate certificates before expiration" -ForegroundColor White
        Write-Host "  4. Monitor Service Principal usage in Azure logs" -ForegroundColor White
        Write-Host "  5. Review role assignments quarterly" -ForegroundColor White
        
        Write-Host "`n🚀 Next Steps:" -ForegroundColor Cyan
        Write-Host "  1. Review the generated documentation in: $OutputPath\ONBOARDING-README.md" -ForegroundColor White
        Write-Host "  2. Test the deployment script in a non-production environment" -ForegroundColor White
        Write-Host "  3. Store credentials securely (Azure Key Vault recommended)" -ForegroundColor White
        Write-Host "  4. Configure monitoring and alerts for Service Principal activity" -ForegroundColor White
    } else {
        Write-Host "`n[WHATIF] No changes were made" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Onboarding failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have Global Administrator privileges" -ForegroundColor Gray
    Write-Host "2. Check Azure connectivity and correct Tenant/Subscription IDs" -ForegroundColor Gray
    Write-Host "3. Ensure required Azure providers are registered" -ForegroundColor Gray
    Write-Host "4. Review error messages above for specific issues" -ForegroundColor Gray
    exit 1
}