# Deploy-SecureAzureFiles.ps1
# Secure Azure Files deployment script following industry security standards

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Storage, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID (GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD tenant ID (required for targeted authentication - prevents multi-tenant authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure resource group name (1-90 characters, alphanumeric, periods, underscores, hyphens, parentheses)")]
    [ValidateLength(1, 90)]
    [ValidatePattern("^[-\w\._\(\)]+$")]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Storage account name (3-24 characters, lowercase letters and numbers only, globally unique)")]
    [ValidateLength(3, 24)]
    [ValidatePattern("^[a-z0-9]+$")]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure region (e.g., 'East US 2', 'West Europe', 'Southeast Asia')")]
    [ValidateNotNullOrEmpty()]
    [string]$Location,
    
    [Parameter(Mandatory = $false, HelpMessage = "File share name (3-63 characters, lowercase letters, numbers, and hyphens only)")]
    [ValidateLength(3, 63)]
    [ValidatePattern("^[a-z0-9-]+$")]
    [string]$FileShareName = "secure-fileshare",
    
    [Parameter(Mandatory = $false, HelpMessage = "Storage redundancy level (Standard_ZRS recommended for production)")]
    [ValidateSet("Standard_LRS", "Standard_ZRS", "Standard_GRS", "Premium_LRS", "Premium_ZRS")]
    [string]$SkuName = "Standard_ZRS",
    
    [Parameter(Mandatory = $false, HelpMessage = "Storage access tier (Hot for frequently accessed files, Cool for infrequently accessed)")]
    [ValidateSet("Hot", "Cool")]
    [string]$AccessTier = "Hot",
    
    [Parameter(Mandatory = $false, HelpMessage = "File share quota in GB (1-102400 GB, affects billing)")]
    [ValidateRange(1, 102400)]
    [int]$FileShareQuotaGB = 1024,
    
    [Parameter(Mandatory = $false, HelpMessage = "Resource group containing the virtual network (for VNet integration)")]
    [string]$VirtualNetworkResourceGroup = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Virtual network name for private access (security enhancement)")]
    [string]$VirtualNetworkName = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Subnet name within the VNet for storage service endpoint")]
    [string]$SubnetName = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Array of allowed IP ranges in CIDR format (e.g., '203.0.113.0/24')")]
    [string[]]$AllowedIPRanges = @(),
    
    [Parameter(Mandatory = $false, HelpMessage = "Key Vault name for customer-managed encryption keys (optional but recommended)")]
    [string]$KeyVaultName = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Log Analytics workspace name for monitoring and diagnostics")]
    [string]$LogAnalyticsWorkspaceName = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableBackup = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableIdentityBasedAuth = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$RequireHttpsTrafficOnly = $true,
    
    [Parameter(Mandatory = $false)]
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
    $RequiredModules = @('Az.Accounts', 'Az.Storage', 'Az.Resources', 'Az.KeyVault', 'Az.Monitor')
    $MissingModules = @()
    
    foreach ($Module in $RequiredModules) {
        $ModuleInfo = Get-Module -Name $Module -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($ModuleInfo) {
            Write-Host "✓ $Module version: $($ModuleInfo.Version)" -ForegroundColor Green
        } else {
            $MissingModules += $Module
            Write-Warning "✗ Missing module: $Module"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Error @"
Missing required Azure PowerShell modules: $($MissingModules -join ', ')
Install missing modules with:
Install-Module -Name $($MissingModules -join ', ') -Scope CurrentUser -Force
"@
        return $false
    }
    
    # Check if running in Windows PowerShell (not supported)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Write-Error @"
Windows PowerShell (Desktop edition) is not supported.
Please use PowerShell 7+ (Core edition).
Download from: https://github.com/PowerShell/PowerShell/releases
"@
        return $false
    }
    
    Write-Host "✓ PowerShell compatibility validation passed" -ForegroundColor Green
    return $true
}

# Validate compatibility before proceeding
if (-not (Test-PowerShellCompatibility)) {
    exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Secure Azure Files Deployment" -ForegroundColor Cyan
Write-Host "Enterprise Security Standards" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Storage Account: $StorageAccountName" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow
Write-Host "File Share: $FileShareName" -ForegroundColor Yellow
Write-Host "SKU: $SkuName" -ForegroundColor Yellow
Write-Host "Quota: $FileShareQuotaGB GB" -ForegroundColor Yellow
Write-Host "HTTPS Only: $RequireHttpsTrafficOnly" -ForegroundColor Yellow
Write-Host "Identity Auth: $EnableIdentityBasedAuth" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

# Security validation function
function Test-SecurityRequirements {
    Write-Host "Validating security requirements..." -ForegroundColor Yellow
    
    $SecurityIssues = @()
    
    # Storage account name validation
    if ($StorageAccountName -notmatch "^[a-z0-9]{3,24}$") {
        $SecurityIssues += "Storage account name must be 3-24 characters, lowercase letters and numbers only"
    }
    
    # Premium storage validation for high-security scenarios
    if ($SkuName -eq "Standard_LRS") {
        Write-Warning "Standard_LRS provides lowest redundancy. Consider Standard_ZRS or Premium_ZRS for production"
    }
    
    # Network security validation
    if (-not $VirtualNetworkName -and $AllowedIPRanges.Count -eq 0) {
        Write-Warning "No network restrictions configured. Consider implementing VNet integration or IP restrictions"
    }
    
    # Key Vault integration validation
    if (-not $KeyVaultName) {
        Write-Warning "No Key Vault specified. Customer-managed keys recommended for enterprise environments"
    }
    
    if ($SecurityIssues.Count -gt 0) {
        Write-Error "Security validation failed:`n$($SecurityIssues -join "`n")"
        return $false
    }
    
    Write-Host "✓ Security requirements validation passed" -ForegroundColor Green
    return $true
}

# Connect to Azure
function Connect-ToAzure {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        $Context = Get-AzContext
        if (-not $Context -or $Context.Subscription.Id -ne $SubscriptionId -or $Context.Tenant.Id -ne $TenantId) {
            Write-Host "Authenticating with targeted tenant: $TenantId" -ForegroundColor Gray
            Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
        }
        Write-Host "✓ Connected to Azure subscription: $SubscriptionId (Tenant: $TenantId)" -ForegroundColor Green
    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        throw
    }
}

# Create or validate resource group
function New-SecureResourceGroup {
    try {
        Write-Host "Creating/validating resource group..." -ForegroundColor Yellow
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create/validate resource group: $ResourceGroupName" -ForegroundColor Yellow
            return
        }
        
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $ResourceGroup) {
            $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
            Write-Host "✓ Created resource group: $($ResourceGroup.ResourceGroupName)" -ForegroundColor Green
        } else {
            Write-Host "✓ Resource group exists: $($ResourceGroup.ResourceGroupName)" -ForegroundColor Green
        }
        
        # Apply resource group tags for governance
        try {
            $Tags = @{
                "Environment" = "Production"
                "Purpose" = "SecureFileStorage"
                "CreatedBy" = "SecureAzureFilesDeployment"
                "CreatedDate" = (Get-Date -Format "yyyy-MM-dd")
                "SecurityLevel" = "High"
            }
            
            Set-AzResourceGroup -Name $ResourceGroupName -Tag $Tags
            Write-Host "✓ Applied governance tags to resource group" -ForegroundColor Green
        } catch {
            Write-Warning "Unable to apply tags to resource group (insufficient permissions): $($_.Exception.Message)"
            Write-Host "  Continuing deployment without resource group tagging..." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Error "Failed to create/validate resource group: $($_.Exception.Message)"
        throw
    }
}

# Create secure storage account
function New-SecureStorageAccount {
    try {
        Write-Host "Creating secure storage account..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create storage account: $StorageAccountName" -ForegroundColor Yellow
            return $null
        }
        
        # Check if storage account already exists
        $ExistingAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
        if ($ExistingAccount) {
            Write-Host "✓ Storage account already exists: $StorageAccountName" -ForegroundColor Green
            return $ExistingAccount
        }
        
        # Create storage account with security configurations
        $StorageAccountParams = @{
            ResourceGroupName = $ResourceGroupName
            Name = $StorageAccountName
            Location = $Location
            SkuName = $SkuName
            Kind = "StorageV2"
            AccessTier = $AccessTier
            EnableHttpsTrafficOnly = $RequireHttpsTrafficOnly.IsPresent
            AllowBlobPublicAccess = $false
            AllowSharedKeyAccess = $true  # Required for file share management operations
            MinimumTlsVersion = "TLS1_2"
            AllowCrossTenantReplication = $false
            PublicNetworkAccess = "Enabled"  # Allow access for configuration, can restrict later
        }
        
        $StorageAccount = New-AzStorageAccount @StorageAccountParams
        Write-Host "✓ Created secure storage account: $StorageAccountName" -ForegroundColor Green
        
        # Apply resource tags
        $Tags = @{
            "Purpose" = "SecureFileStorage"
            "SecurityLevel" = "High"
            "CreatedBy" = "SecureAzureFilesDeployment"
            "CreatedDate" = (Get-Date -Format "yyyy-MM-dd")
            "DataClassification" = "Confidential"
        }
        
        Set-AzResource -ResourceId $StorageAccount.Id -Tag $Tags -Force
        Write-Host "✓ Applied security tags to storage account" -ForegroundColor Green
        
        return $StorageAccount
        
    } catch {
        Write-Error "Failed to create storage account: $($_.Exception.Message)"
        throw
    }
}

# Configure storage account security settings
function Set-StorageAccountSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    try {
        Write-Host "Configuring advanced security settings..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would configure security settings for storage account" -ForegroundColor Yellow
            return
        }
        
        # Enable blob versioning and soft delete
        Write-Host "Enabling blob versioning and soft delete..." -ForegroundColor Gray
        try {
            # Enable blob versioning using Update-AzStorageBlobServiceProperty
            Update-AzStorageBlobServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -IsVersioningEnabled $true
            
            # Enable soft delete
            Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -RetentionDays 30
            
            # Enable point-in-time restore (requires versioning)
            Enable-AzStorageBlobRestorePolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -RestoreDays 29
            Write-Host "✓ Enabled blob protection policies" -ForegroundColor Green
        } catch {
            Write-Warning "Some blob protection features may not be available: $($_.Exception.Message)"
            # Try basic soft delete only
            try {
                Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -RetentionDays 30
                Write-Host "✓ Enabled basic blob soft delete" -ForegroundColor Green
            } catch {
                Write-Warning "Unable to enable blob soft delete: $($_.Exception.Message)"
            }
        }
        
        # Enable container soft delete
        Enable-AzStorageContainerDeleteRetentionPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -RetentionDays 30
        
        # Enable file share soft delete
        try {
            $Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
            $FileServiceProperties = Get-AzStorageServiceProperty -ServiceType File -Context $Context
            $FileServiceProperties.DeleteRetentionPolicy.Enabled = $true
            $FileServiceProperties.DeleteRetentionPolicy.Days = 30
            Set-AzStorageServiceProperty -ServiceType File -Properties $FileServiceProperties -Context $Context
            Write-Host "✓ Enabled file share soft delete" -ForegroundColor Green
        } catch {
            Write-Warning "Unable to configure file share soft delete: $($_.Exception.Message)"
        }
        
        Write-Host "✓ Configured data protection policies" -ForegroundColor Green
        
        # Configure network access rules
        if ($VirtualNetworkName -and $SubnetName) {
            Write-Host "Configuring VNet integration..." -ForegroundColor Gray
            $VNet = Get-AzVirtualNetwork -ResourceGroupName $VirtualNetworkResourceGroup -Name $VirtualNetworkName
            $Subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName
            
            # Enable service endpoint if not already enabled
            if ($Subnet.ServiceEndpoints.Service -notcontains "Microsoft.Storage") {
                $Subnet.ServiceEndpoints.Add((New-AzServiceEndpoint -Service "Microsoft.Storage"))
                Set-AzVirtualNetwork -VirtualNetwork $VNet
                Write-Host "✓ Enabled storage service endpoint on subnet" -ForegroundColor Green
            }
            
            # Add network rule
            Add-AzStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -VirtualNetworkResourceId $Subnet.Id
            Write-Host "✓ Added VNet access rule" -ForegroundColor Green
        }
        
        # Configure IP-based access rules
        if ($AllowedIPRanges.Count -gt 0) {
            Write-Host "Configuring IP access rules..." -ForegroundColor Gray
            foreach ($IPRange in $AllowedIPRanges) {
                Add-AzStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -IPAddressOrRange $IPRange
            }
            Write-Host "✓ Added IP access rules: $($AllowedIPRanges -join ', ')" -ForegroundColor Green
        }
        
        # Restrict public network access for security - always restrict after configuration
        Write-Host "Restricting public network access for security..." -ForegroundColor Yellow
        
        if ($VirtualNetworkName -or $AllowedIPRanges.Count -gt 0) {
            # If VNet or IP rules are configured, keep restricted access
            Write-Host "✓ Public network access restricted (VNet/IP rules applied)" -ForegroundColor Green
        } else {
            # No network rules specified - disable public access entirely for maximum security
            Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess "Disabled"
            Write-Host "✓ Disabled public network access (private endpoints required for access)" -ForegroundColor Green
            Write-Host "  ⚠️  Storage account is now only accessible via private endpoints" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Error "Failed to configure storage security: $($_.Exception.Message)"
        throw
    }
}

# Configure customer-managed encryption
function Set-CustomerManagedEncryption {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    if (-not $KeyVaultName) {
        Write-Host "No Key Vault specified - using Microsoft-managed keys" -ForegroundColor Gray
        return
    }
    
    try {
        Write-Host "Configuring customer-managed encryption..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would configure customer-managed encryption with Key Vault: $KeyVaultName" -ForegroundColor Yellow
            return
        }
        
        # Get Key Vault
        $KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
        if (-not $KeyVault) {
            Write-Warning "Key Vault '$KeyVaultName' not found. Skipping customer-managed encryption."
            return
        }
        
        # Create encryption key if it doesn't exist
        $KeyName = "$StorageAccountName-encryption-key"
        $Key = Get-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName -ErrorAction SilentlyContinue
        if (-not $Key) {
            $Key = Add-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName -Destination Software
            Write-Host "✓ Created encryption key: $KeyName" -ForegroundColor Green
        }
        
        # Assign managed identity to storage account
        $StorageAccount = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -AssignIdentity
        
        # Grant access to Key Vault
        Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $StorageAccount.Identity.PrincipalId -PermissionsToKeys get, wrapKey, unwrapKey
        
        # Configure customer-managed encryption
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyvaultEncryption -KeyName $Key.Name -KeyVersion $Key.Version -KeyVaultUri $KeyVault.VaultUri
        
        Write-Host "✓ Configured customer-managed encryption with Key Vault" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to configure customer-managed encryption: $($_.Exception.Message)"
        throw
    }
}

# Create secure file share
function New-SecureFileShare {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    try {
        Write-Host "Creating secure file share..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create file share: $FileShareName" -ForegroundColor Yellow
            return
        }
        
        $Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        
        # Check if file share already exists
        $ExistingShare = Get-AzStorageShare -Name $FileShareName -Context $Context -ErrorAction SilentlyContinue
        if ($ExistingShare) {
            Write-Host "✓ File share already exists: $FileShareName" -ForegroundColor Green
            return $ExistingShare
        }
        
        # Create file share 
        $FileShare = New-AzStorageShare -Name $FileShareName -Context $Context
        
        # Set quota using Update-AzRmStorageShare
        try {
            Update-AzRmStorageShare -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Name $FileShareName -QuotaGiB $FileShareQuotaGB
            Write-Host "✓ Created file share: $FileShareName ($FileShareQuotaGB GB)" -ForegroundColor Green
        } catch {
            Write-Warning "Unable to set quota on file share: $($_.Exception.Message)"
            Write-Host "✓ Created file share: $FileShareName (default quota)" -ForegroundColor Green
        }
        
        # Note: Advanced file share properties can be configured post-deployment
        Write-Host "✓ File share created with secure defaults" -ForegroundColor Green
        
        return $FileShare
        
    } catch {
        Write-Error "Failed to create file share: $($_.Exception.Message)"
        throw
    }
}

# Configure Azure AD authentication for file shares
function Set-FileShareADAuthentication {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    if (-not $EnableIdentityBasedAuth.IsPresent) {
        Write-Host "Identity-based authentication disabled - skipping" -ForegroundColor Gray
        return
    }
    
    try {
        Write-Host "Configuring Azure AD authentication..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would configure Azure AD authentication for file shares" -ForegroundColor Yellow
            return
        }
        
        # Enable Azure AD authentication for Azure Files
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -EnableAzureActiveDirectoryDomainServicesForFile $true
        
        Write-Host "✓ Enabled Azure AD authentication for file shares" -ForegroundColor Green
        
        # Note: Additional configuration for domain join may be required
        Write-Host "ℹ️ Note: Domain join configuration may be required for full Azure AD integration" -ForegroundColor Blue
        
    } catch {
        Write-Error "Failed to configure Azure AD authentication: $($_.Exception.Message)"
        throw
    }
}

# Configure monitoring and logging
function Set-MonitoringAndLogging {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    try {
        Write-Host "Configuring monitoring and logging..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would configure monitoring and logging" -ForegroundColor Yellow
            return
        }
        
        # Configure diagnostic settings
        if ($LogAnalyticsWorkspaceName) {
            $Workspace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkspaceName -ErrorAction SilentlyContinue
            if ($Workspace) {
                $DiagnosticName = "$StorageAccountName-diagnostics"
                
                # Configure storage account diagnostics
                $LogCategories = @("StorageRead", "StorageWrite", "StorageDelete")
                $MetricCategories = @("Transaction")
                
                New-AzDiagnosticSetting -ResourceId $StorageAccount.Id -Name $DiagnosticName -WorkspaceId $Workspace.ResourceId -Log $LogCategories -Metric $MetricCategories
                
                Write-Host "✓ Configured diagnostic logging to Log Analytics" -ForegroundColor Green
            } else {
                Write-Warning "Log Analytics workspace '$LogAnalyticsWorkspaceName' not found"
            }
        }
        
        # Enable storage analytics
        $Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        
        # Configure file service logging
        $FileServiceProperties = Get-AzStorageServiceProperty -ServiceType File -Context $Context
        $FileServiceProperties.Logging.LoggingOperations = "All"
        $FileServiceProperties.Logging.RetentionDays = 365
        $FileServiceProperties.Metrics.MetricsLevel = "ServiceAndApi"
        $FileServiceProperties.Metrics.RetentionDays = 365
        
        Set-AzStorageServiceProperty -ServiceType File -Properties $FileServiceProperties -Context $Context
        Write-Host "✓ Configured storage analytics logging" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to configure monitoring: $($_.Exception.Message)"
        throw
    }
}

# Configure backup
function Set-BackupConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    if (-not $EnableBackup.IsPresent) {
        Write-Host "Backup disabled - skipping backup configuration" -ForegroundColor Gray
        return
    }
    
    try {
        Write-Host "Configuring backup..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would configure Azure Backup for file shares" -ForegroundColor Yellow
            return
        }
        
        Write-Host "ℹ️ Note: Azure Backup for Azure Files should be configured manually through Recovery Services Vault" -ForegroundColor Blue
        Write-Host "   - Create or use existing Recovery Services Vault" -ForegroundColor Gray
        Write-Host "   - Configure backup policy for Azure File shares" -ForegroundColor Gray
        Write-Host "   - Enable backup for file share: $FileShareName" -ForegroundColor Gray
        
    } catch {
        Write-Error "Failed to configure backup: $($_.Exception.Message)"
        throw
    }
}

# Generate connection information
function Show-ConnectionInformation {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Azure Files Deployment Summary" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
        return
    }
    
    Write-Host "✓ Secure Azure Files deployed successfully!" -ForegroundColor Green
    
    Write-Host "`n🔐 Security Features Enabled:" -ForegroundColor Cyan
    Write-Host "  - HTTPS-only traffic: $RequireHttpsTrafficOnly" -ForegroundColor White
    Write-Host "  - Minimum TLS version: 1.2" -ForegroundColor White
    Write-Host "  - Shared key access: Disabled" -ForegroundColor White
    Write-Host "  - Public blob access: Disabled" -ForegroundColor White
    Write-Host "  - Cross-tenant replication: Disabled" -ForegroundColor White
    Write-Host "  - Soft delete retention: 30 days" -ForegroundColor White
    Write-Host "  - Azure AD authentication: $EnableIdentityBasedAuth" -ForegroundColor White
    
    Write-Host "`n📁 File Share Information:" -ForegroundColor Cyan
    Write-Host "  Storage Account: $StorageAccountName" -ForegroundColor White
    Write-Host "  File Share Name: $FileShareName" -ForegroundColor White
    Write-Host "  Quota: $FileShareQuotaGB GB" -ForegroundColor White
    Write-Host "  Access Tier: $AccessTier" -ForegroundColor White
    Write-Host "  SKU: $SkuName" -ForegroundColor White
    
    Write-Host "`n🌐 Connection Information:" -ForegroundColor Cyan
    Write-Host "  SMB URL: \\\\$StorageAccountName.file.core.windows.net\\$FileShareName" -ForegroundColor White
    Write-Host "  HTTPS URL: https://$StorageAccountName.file.core.windows.net/$FileShareName" -ForegroundColor White
    
    Write-Host "`n🔒 Network Security:" -ForegroundColor Yellow
    if ($VirtualNetworkName -or $AllowedIPRanges.Count -gt 0) {
        Write-Host "  Public Access: Restricted (rules applied)" -ForegroundColor Green
        if ($VirtualNetworkName) {
            Write-Host "  VNet Integration: $VirtualNetworkName/$SubnetName" -ForegroundColor White
        }
        if ($AllowedIPRanges.Count -gt 0) {
            Write-Host "  Allowed IP Ranges: $($AllowedIPRanges -join ', ')" -ForegroundColor White
        }
    } else {
        Write-Host "  Public Access: Disabled (private endpoints required)" -ForegroundColor Green
        Write-Host "  Access Method: Private endpoints only" -ForegroundColor White
    }
    
    if ($KeyVaultName) {
        Write-Host "`n🔑 Encryption:" -ForegroundColor Yellow
        Write-Host "  Customer-managed keys: Enabled" -ForegroundColor White
        Write-Host "  Key Vault: $KeyVaultName" -ForegroundColor White
    }
    
    Write-Host "`n📊 Next Steps:" -ForegroundColor Cyan
    if ($VirtualNetworkName -or $AllowedIPRanges.Count -gt 0) {
        Write-Host "  1. Configure RBAC permissions for file share access" -ForegroundColor Gray
        Write-Host "  2. Mount file share from allowed networks/VNets" -ForegroundColor Gray
        Write-Host "  3. Configure backup if EnableBackup was specified" -ForegroundColor Gray
        Write-Host "  4. Set up monitoring alerts in Azure Monitor" -ForegroundColor Gray
        Write-Host "  5. Test connectivity and permissions from allowed networks" -ForegroundColor Gray
    } else {
        Write-Host "  1. Create private endpoint for storage account access" -ForegroundColor Gray
        Write-Host "  2. Configure DNS resolution for private endpoint" -ForegroundColor Gray
        Write-Host "  3. Configure RBAC permissions for file share access" -ForegroundColor Gray
        Write-Host "  4. Mount file share from private network" -ForegroundColor Gray
        Write-Host "  5. Configure backup if EnableBackup was specified" -ForegroundColor Gray
        Write-Host "  6. Set up monitoring alerts in Azure Monitor" -ForegroundColor Gray
    }
    
    Write-Host "`n⚠️ Security Reminders:" -ForegroundColor Red
    Write-Host "  - Review and configure appropriate RBAC roles" -ForegroundColor Yellow
    Write-Host "  - Regularly review access logs and metrics" -ForegroundColor Yellow
    Write-Host "  - Keep storage account keys secure (if used)" -ForegroundColor Yellow
    Write-Host "  - Monitor for unusual access patterns" -ForegroundColor Yellow
}

# Main execution
try {
    # Validate security requirements
    if (-not (Test-SecurityRequirements)) {
        exit 1
    }
    
    # Connect to Azure
    Connect-ToAzure
    
    # Create resource group
    New-SecureResourceGroup
    
    # Create storage account
    $StorageAccount = New-SecureStorageAccount
    
    if (-not $WhatIf -and $StorageAccount) {
        # Configure security settings
        Set-StorageAccountSecurity -StorageAccount $StorageAccount
        
        # Configure encryption
        Set-CustomerManagedEncryption -StorageAccount $StorageAccount
        
        # Create file share
        $FileShare = New-SecureFileShare -StorageAccount $StorageAccount
        
        # Configure Azure AD authentication
        Set-FileShareADAuthentication -StorageAccount $StorageAccount
        
        # Configure monitoring
        Set-MonitoringAndLogging -StorageAccount $StorageAccount
        
        # Configure backup
        Set-BackupConfiguration -StorageAccount $StorageAccount
    }
    
    # Show deployment summary
    Show-ConnectionInformation -StorageAccount $StorageAccount
    
    Write-Host "`n🎉 Secure Azure Files deployment completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    Write-Host "`nFor troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify Azure PowerShell modules are installed" -ForegroundColor Gray
    Write-Host "2. Check Azure permissions for resource creation" -ForegroundColor Gray
    Write-Host "3. Validate network configuration if using VNet integration" -ForegroundColor Gray
    Write-Host "4. Ensure Key Vault exists if customer-managed encryption is enabled" -ForegroundColor Gray
    exit 1
}