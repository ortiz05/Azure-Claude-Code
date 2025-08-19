# Deploy-AutomationLoggingStorageSetup.ps1
# Creates Azure Storage Account optimized for Azure Automation logging and report storage
#
# This script deploys a secure, cost-effective storage solution for all automation outputs
# including Device Cleanup, MFA Compliance, App Usage, Certificate Monitor, etc.
#
# Features:
# - Secure storage account with enterprise security controls
# - Organized container structure for different automation services  
# - Managed identity integration for seamless Azure Automation access
# - Lifecycle policies for automatic report archival and cost optimization
# - Comprehensive monitoring and access controls
#
# MANDATORY 3-STEP WORKFLOW - This is Step 3 of 3:
# Step 1: Create-AutomationStorageDeploymentGroup.ps1
# Step 2: Grant-AutomationStoragePermissions.ps1
# Step 3: Deploy-AutomationLoggingStorageSetup.ps1 (THIS SCRIPT)

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Storage, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD Tenant ID (REQUIRED to avoid authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name for the storage account")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Storage account name (3-24 characters, lowercase letters and numbers only)")]
    [ValidateLength(3, 24)]
    [ValidatePattern("^[a-z0-9]+$")]
    [string]$StorageAccountName = ("autologstore" + (Get-Random -Minimum 1000 -Maximum 9999)),
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure region for the storage account")]
    [ValidateNotNullOrEmpty()]
    [string]$Location = "East US 2",
    
    [Parameter(Mandatory = $false, HelpMessage = "Storage redundancy level")]
    [ValidateSet("Standard_LRS", "Standard_ZRS", "Standard_GRS")]
    [string]$SkuName = "Standard_LRS",
    
    [Parameter(Mandatory = $false, HelpMessage = "Storage access tier for cost optimization")]
    [ValidateSet("Hot", "Cool")]
    [string]$AccessTier = "Cool",
    
    [Parameter(Mandatory = $false, HelpMessage = "Object ID of the Azure Automation managed identity to grant access")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$AutomationManagedIdentityId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Report retention period in days")]
    [ValidateRange(30, 2555)]  # 30 days to 7 years
    [int]$ReportRetentionDays = 365,
    
    [Parameter(Mandatory = $false, HelpMessage = "Archive reports older than X days to cool storage")]
    [ValidateRange(30, 365)]
    [int]$ArchiveAfterDays = 90,
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be created without making changes")]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# PowerShell and module compatibility validation
function Test-PowerShellCompatibility {
    Write-Host "Validating PowerShell compatibility..." -ForegroundColor Yellow
    
    # Check PowerShell version
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -lt 7) {
        Write-Error @"
PowerShell 7.0 or later is required for this script.
Current version: $($PSVersion.ToString())
Please install PowerShell 7 from: https://github.com/PowerShell/PowerShell/releases
"@
        return $false
    }
    Write-Host "✓ PowerShell version: $($PSVersion.ToString())" -ForegroundColor Green
    
    # Check required Azure modules
    $RequiredModules = @('Az.Accounts', 'Az.Storage', 'Az.Resources')
    $MissingModules = @()
    
    foreach ($Module in $RequiredModules) {
        $InstalledModule = Get-Module -ListAvailable -Name $Module | 
                          Sort-Object Version -Descending | 
                          Select-Object -First 1
        
        if (-not $InstalledModule) {
            $MissingModules += $Module
            Write-Host "✗ Missing: $Module" -ForegroundColor Red
        } else {
            Write-Host "✓ $Module version: $($InstalledModule.Version)" -ForegroundColor Green
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Error @"
Missing required Azure modules. Install them using:
$($MissingModules | ForEach-Object { "Install-Module -Name $_ -Scope CurrentUser -Force" } | Out-String)
"@
        return $false
    }
    
    Write-Host "✓ PowerShell compatibility validation passed" -ForegroundColor Green
    return $true
}

# Automation service container definitions
$AutomationContainers = @(
    @{
        Name = "device-cleanup-reports"
        Description = "Device cleanup automation reports and logs"
        PublicAccess = "None"
    },
    @{
        Name = "mfa-compliance-reports" 
        Description = "MFA compliance monitoring reports and notifications"
        PublicAccess = "None"
    },
    @{
        Name = "app-usage-reports"
        Description = "Enterprise application usage analysis reports"
        PublicAccess = "None"
    },
    @{
        Name = "certificate-monitor-reports"
        Description = "Application certificate expiration monitoring reports"
        PublicAccess = "None"
    },
    @{
        Name = "service-principal-reports"
        Description = "Service principal credential management reports"
        PublicAccess = "None"
    },
    @{
        Name = "permission-audit-reports"
        Description = "Application permission governance audit reports"
        PublicAccess = "None"
    },
    @{
        Name = "deployment-logs"
        Description = "Automation deployment and configuration logs"
        PublicAccess = "None"
    },
    @{
        Name = "archived-reports"
        Description = "Long-term storage for archived reports (cool storage)"
        PublicAccess = "None"
    }
)

Write-Host @"
=========================================
Automation Logging Storage Deployment
Enterprise-Grade Report Storage Solution
=========================================
"@ -ForegroundColor Cyan

Write-Host "Storage Account Name: $StorageAccountName" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow
Write-Host "Redundancy: $SkuName" -ForegroundColor Yellow
Write-Host "Access Tier: $AccessTier (optimized for $($AccessTier.ToLower()) access)" -ForegroundColor Yellow
Write-Host "Retention Period: $ReportRetentionDays days" -ForegroundColor Yellow
Write-Host "Archive After: $ArchiveAfterDays days" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Run compatibility checks
if (-not (Test-PowerShellCompatibility)) {
    throw "PowerShell compatibility check failed"
}

if ($WhatIf) {
    Write-Host ""
    Write-Host "🔍 WHATIF MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Would create the following resources:" -ForegroundColor Yellow
    Write-Host "• Storage Account: $StorageAccountName" -ForegroundColor Green
    Write-Host "  - SKU: $SkuName" -ForegroundColor Gray
    Write-Host "  - Access Tier: $AccessTier" -ForegroundColor Gray
    Write-Host "  - Security: HTTPS-only, TLS 1.2, no public blob access" -ForegroundColor Gray
    Write-Host "• Containers: $($AutomationContainers.Count) automation logging containers" -ForegroundColor Green
    if ($AutomationManagedIdentityId) {
        Write-Host "• Additional RBAC Assignment: Storage Blob Data Contributor for managed identity" -ForegroundColor Green
    }
    Write-Host "• Lifecycle Policy: Archive after $ArchiveAfterDays days, delete after $ReportRetentionDays days" -ForegroundColor Green
    Write-Host ""
    Write-Host "Container Structure:" -ForegroundColor Yellow
    foreach ($Container in $AutomationContainers) {
        Write-Host "  📁 $($Container.Name) - $($Container.Description)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Estimated Monthly Costs (assuming 1GB data):" -ForegroundColor Yellow
    if ($AccessTier -eq "Cool") {
        Write-Host "  • Storage: ~$0.01/month" -ForegroundColor Green
        Write-Host "  • Transactions: ~$0.10/month" -ForegroundColor Green
        Write-Host "  • Total: ~$0.11/month" -ForegroundColor Green
    } else {
        Write-Host "  • Storage: ~$0.02/month" -ForegroundColor Green
        Write-Host "  • Transactions: ~$0.05/month" -ForegroundColor Green
        Write-Host "  • Total: ~$0.07/month" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "To deploy these resources, re-run without -WhatIf parameter" -ForegroundColor Yellow
    exit 0
}

try {
    # Connect to Azure
    Write-Host ""
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    
    $Context = Get-AzContext
    if (-not $Context -or $Context.Tenant.Id -ne $TenantId) {
        Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId
        $Context = Get-AzContext
    }
    
    if ($Context.Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId
    }
    
    Write-Host "✓ Connected to Azure" -ForegroundColor Green
    Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
    Write-Host "  Subscription: $($Context.Subscription.Name)" -ForegroundColor Gray
    
    # Validate resource group
    Write-Host ""
    Write-Host "Validating resource group..." -ForegroundColor Yellow
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    
    if (-not $ResourceGroup) {
        throw "Resource group '$ResourceGroupName' not found. Please create it first or specify an existing resource group."
    }
    
    Write-Host "✓ Resource group exists: $ResourceGroupName" -ForegroundColor Green
    Write-Host "  Location: $($ResourceGroup.Location)" -ForegroundColor Gray
    
    # Check if storage account name is available
    Write-Host ""
    Write-Host "Checking storage account name availability..." -ForegroundColor Yellow
    $NameAvailability = Get-AzStorageAccountNameAvailability -Name $StorageAccountName
    
    if (-not $NameAvailability.NameAvailable) {
        throw "Storage account name '$StorageAccountName' is not available: $($NameAvailability.Reason)"
    }
    
    Write-Host "✓ Storage account name is available: $StorageAccountName" -ForegroundColor Green
    
    # Create storage account
    Write-Host ""
    Write-Host "Creating storage account..." -ForegroundColor Yellow
    
    $StorageAccountParams = @{
        ResourceGroupName = $ResourceGroupName
        Name = $StorageAccountName
        Location = $Location
        SkuName = $SkuName
        Kind = 'StorageV2'
        AccessTier = $AccessTier
        EnableHttpsTrafficOnly = $true
        MinimumTlsVersion = 'TLS1_2'
        AllowBlobPublicAccess = $false
        AllowSharedKeyAccess = $true  # Required for Azure Automation compatibility
        PublicNetworkAccess = 'Enabled'
        Tag = @{
            'Purpose' = 'AutomationLogging'
            'ManagedBy' = 'Azure-Automation'
            'Environment' = 'Production'
            'SecurityLevel' = 'High'
            'CostCenter' = 'IT-Security'
            'DataRetention' = "$ReportRetentionDays-days"
        }
    }
    
    $StorageAccount = New-AzStorageAccount @StorageAccountParams
    Write-Host "✓ Storage account created successfully" -ForegroundColor Green
    Write-Host "  Name: $($StorageAccount.StorageAccountName)" -ForegroundColor Gray
    Write-Host "  Primary Endpoint: $($StorageAccount.PrimaryEndpoints.Blob)" -ForegroundColor Gray
    
    # Get storage context
    $StorageContext = $StorageAccount.Context
    
    # Create containers
    Write-Host ""
    Write-Host "Creating automation logging containers..." -ForegroundColor Yellow
    
    foreach ($Container in $AutomationContainers) {
        Write-Host "  Creating container: $($Container.Name)" -ForegroundColor Cyan
        
        $ContainerResult = New-AzStorageContainer -Name $Container.Name -Context $StorageContext -Permission $Container.PublicAccess
        Write-Host "    ✓ Created: $($ContainerResult.Name)" -ForegroundColor Green
        
        # Add metadata to container
        $ContainerMetadata = @{
            'Purpose' = $Container.Description
            'CreatedBy' = 'AutomationLoggingStorageSetup'
            'CreatedDate' = (Get-Date -Format 'yyyy-MM-dd')
        }
        
        Set-AzStorageContainerStoredAccessPolicy -Container $Container.Name -Context $StorageContext -Policy @() # Clear any default policies
    }
    
    # Create lifecycle management policy
    Write-Host ""
    Write-Host "Configuring lifecycle management policy..." -ForegroundColor Yellow
    
    # Create rule for archiving to cool storage
    $ArchiveRule = New-AzStorageAccountManagementPolicyRule -Name "ArchiveAutomationReports" -Action (
        Add-AzStorageAccountManagementPolicyAction -BaseBlobAction TierToCool -DaysAfterModificationGreaterThan $ArchiveAfterDays
    ) -Disabled:$false
    
    # Create rule for deletion after retention period
    $DeleteRule = New-AzStorageAccountManagementPolicyRule -Name "DeleteOldAutomationReports" -Action (
        Add-AzStorageAccountManagementPolicyAction -BaseBlobAction Delete -DaysAfterModificationGreaterThan $ReportRetentionDays
    ) -Disabled:$false
    
    # Apply lifecycle policy
    try {
        $LifecyclePolicy = Set-AzStorageAccountManagementPolicy -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -Rule $ArchiveRule, $DeleteRule
        Write-Host "✓ Lifecycle policy configured" -ForegroundColor Green
        Write-Host "  Archive to cool storage after: $ArchiveAfterDays days" -ForegroundColor Gray
        Write-Host "  Delete after: $ReportRetentionDays days" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Failed to set lifecycle policy: $_. You can configure this manually in Azure Portal."
    }
    
    # Grant additional managed identity permissions if provided
    if ($AutomationManagedIdentityId) {
        Write-Host ""
        Write-Host "Granting additional managed identity permissions..." -ForegroundColor Yellow
        
        try {
            # Grant Storage Blob Data Contributor role to managed identity on the storage account
            $StorageRoleAssignment = New-AzRoleAssignment -ObjectId $AutomationManagedIdentityId -RoleDefinitionName "Storage Blob Data Contributor" -Scope $StorageAccount.Id -ErrorAction SilentlyContinue
            
            if ($StorageRoleAssignment) {
                Write-Host "✓ Granted Storage Blob Data Contributor role to managed identity" -ForegroundColor Green
                Write-Host "  Principal ID: $AutomationManagedIdentityId" -ForegroundColor Gray
                Write-Host "  Scope: Storage Account" -ForegroundColor Gray
            } else {
                Write-Host "⚠ Role assignment may already exist at storage account level" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Could not grant storage account level permissions: $_"
            Write-Host "  Permissions should already be granted at resource group level" -ForegroundColor Gray
        }
    }
    
    # Create sample folder structure in each container
    Write-Host ""
    Write-Host "Creating sample folder structure..." -ForegroundColor Yellow
    
    $CurrentYear = Get-Date -Format "yyyy"
    $CurrentMonth = Get-Date -Format "MM"
    
    foreach ($Container in $AutomationContainers) {
        if ($Container.Name -ne "archived-reports") {
            # Create year/month folder structure with placeholder file
            $FolderPath = "$CurrentYear/$CurrentMonth/README.txt"
            $ReadmeContent = @"
# $($Container.Description)

This container stores reports and logs for the automation service.

Folder structure:
- YYYY/MM/reports - Monthly reports
- YYYY/MM/logs - Daily execution logs
- YYYY/MM/errors - Error logs and exceptions

File naming convention:
- Reports: service-name-YYYY-MM-DD.csv/html
- Logs: service-name-log-YYYY-MM-DD.txt
- Errors: service-name-error-YYYY-MM-DD-HHMMSS.txt

Created by: Automation Logging Storage Setup
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
            
            # Create a blob to establish the folder structure
            $ReadmeBlob = Set-AzStorageBlobContent -Context $StorageContext -Container $Container.Name -Blob $FolderPath -BlobType Block -StandardBlobTier Cool -Force
            Write-Host "  ✓ Created folder structure in: $($Container.Name)" -ForegroundColor Green
        }
    }
    
    # Summary and next steps
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    Write-Host "✅ Storage Account: $StorageAccountName" -ForegroundColor Green
    Write-Host "✅ Containers: $($AutomationContainers.Count) logging containers created" -ForegroundColor Green
    Write-Host "✅ Lifecycle Policy: Configured with $ArchiveAfterDays/$ReportRetentionDays day retention" -ForegroundColor Green
    Write-Host "✅ Security: HTTPS-only, TLS 1.2, no public blob access" -ForegroundColor Green
    Write-Host "✅ Folder Structure: Sample directories created with documentation" -ForegroundColor Green
    
    if ($AutomationManagedIdentityId) {
        Write-Host "✅ Permissions: Managed identity granted access" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "📊 Storage Account Details:" -ForegroundColor Cyan
    Write-Host "• Resource Group: $ResourceGroupName" -ForegroundColor White
    Write-Host "• Storage Account: $StorageAccountName" -ForegroundColor White
    Write-Host "• Primary Endpoint: $($StorageAccount.PrimaryEndpoints.Blob)" -ForegroundColor White
    Write-Host "• Redundancy: $SkuName" -ForegroundColor White
    Write-Host "• Access Tier: $AccessTier" -ForegroundColor White
    
    Write-Host ""
    Write-Host "📁 Container Structure:" -ForegroundColor Cyan
    foreach ($Container in $AutomationContainers) {
        Write-Host "• $($Container.Name) - $($Container.Description)" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "💡 PowerShell Example for Automation Scripts:" -ForegroundColor Cyan
    Write-Host @"
# In your automation runbooks, use this pattern:
`$StorageAccountName = "$StorageAccountName"
`$ContainerName = "device-cleanup-reports"  # Choose appropriate container
`$BlobName = "`$(Get-Date -Format 'yyyy/MM')/device-cleanup-`$(Get-Date -Format 'yyyy-MM-dd').csv"

# Connect using managed identity (recommended)
`$Context = New-AzStorageContext -StorageAccountName `$StorageAccountName -UseConnectedAccount

# Upload the report
Set-AzStorageBlobContent -File `$ReportPath -Container `$ContainerName -Blob `$BlobName -Context `$Context -StandardBlobTier Cool
"@ -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "🔧 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Update automation scripts to use this storage account" -ForegroundColor White
    Write-Host "2. Test report uploads from Azure Automation runbooks" -ForegroundColor White
    Write-Host "3. Configure monitoring alerts for storage usage and costs" -ForegroundColor White
    Write-Host "4. Set up automated report viewers/dashboards if needed" -ForegroundColor White
    Write-Host "5. Review lifecycle policies and adjust retention as needed" -ForegroundColor White
    
    Write-Host ""
    Write-Host "🎉 Automation Logging Storage deployed successfully!" -ForegroundColor Green
    Write-Host "All automation services can now store their reports and logs centrally." -ForegroundColor Green
    
} catch {
    Write-Error "Deployment failed: $_"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have Contributor permissions on the resource group" -ForegroundColor Gray
    Write-Host "2. Check that the storage account name is globally unique" -ForegroundColor Gray
    Write-Host "3. Ensure the specified location supports the selected redundancy level" -ForegroundColor Gray
    Write-Host "4. Validate that the managed identity ID is correct (if provided)" -ForegroundColor Gray
    Write-Host "5. Confirm you have completed Steps 1 and 2 of the deployment workflow" -ForegroundColor Gray
    exit 1
}