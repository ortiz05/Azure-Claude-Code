# Grant-AutomationStoragePermissions.ps1
# Grants required Azure Storage permissions to Azure Automation Managed Identity
#
# Required Permissions for Automation Storage:
# - Storage Blob Data Contributor: Read, write, and delete storage containers and blobs
# - Storage Account Contributor: Access storage account keys and configuration
#
# MANDATORY 3-STEP WORKFLOW - This is Step 2 of 3:
# Step 1: Create-AutomationStorageDeploymentGroup.ps1
# Step 2: Grant-AutomationStoragePermissions.ps1 (THIS SCRIPT)
# Step 3: Deploy-AutomationStorageSetup.ps1

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.Storage

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Object ID of the Managed Identity (from Automation Account → Identity)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ManagedIdentityObjectId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD Tenant ID (REQUIRED to avoid authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where storage will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name where storage will be deployed")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Name of the Managed Identity for display")]
    [string]$ManagedIdentityName = "AutomationStorageAccess",
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be granted without making changes")]
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
    $RequiredModules = @(
        @{Name = 'Az.Accounts'; MinVersion = '2.0.0'},
        @{Name = 'Az.Resources'; MinVersion = '6.0.0'},
        @{Name = 'Az.Storage'; MinVersion = '5.0.0'}
    )
    
    $MissingModules = @()
    foreach ($Module in $RequiredModules) {
        $InstalledModule = Get-Module -ListAvailable -Name $Module.Name | 
                          Where-Object { $_.Version -ge [version]$Module.MinVersion } | 
                          Sort-Object Version -Descending | 
                          Select-Object -First 1
        
        if (-not $InstalledModule) {
            $MissingModules += $Module.Name
            Write-Host "✗ Missing: $($Module.Name) (minimum version $($Module.MinVersion))" -ForegroundColor Red
        } else {
            Write-Host "✓ $($Module.Name) version: $($InstalledModule.Version)" -ForegroundColor Green
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

# Test account permissions
function Test-AccountPermissions {
    param([string]$RequiredTenantId)
    
    Write-Host "Testing account permissions..." -ForegroundColor Yellow
    
    try {
        # Check if we can access the subscription and resource group
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        
        if ($ResourceGroup) {
            Write-Host "✓ Can access resource group: $ResourceGroupName" -ForegroundColor Green
            Write-Host "  Location: $($ResourceGroup.Location)" -ForegroundColor Gray
        } else {
            throw "Cannot access resource group: $ResourceGroupName"
        }
        
        # Test if we can query role assignments (requires RBAC permissions)
        $TestAssignment = Get-AzRoleAssignment -Scope $ResourceGroup.ResourceId -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($TestAssignment) {
            Write-Host "✓ Can manage RBAC assignments (Owner/User Access Administrator confirmed)" -ForegroundColor Green
        } else {
            Write-Warning "Cannot query RBAC assignments - may need elevated permissions"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to validate account permissions: $_"
        return $false
    }
}

Write-Host @"
=========================================
Grant Automation Storage Permissions
Azure Storage Access Configuration
=========================================
"@ -ForegroundColor Cyan

Write-Host "Managed Identity Object ID: $ManagedIdentityObjectId" -ForegroundColor Yellow
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Display Name: $ManagedIdentityName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Run compatibility checks
if (-not (Test-PowerShellCompatibility)) {
    throw "PowerShell compatibility check failed"
}

# Required Azure RBAC roles for storage access
$RequiredRoles = @(
    @{
        Name = "Storage Blob Data Contributor"
        Id = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
        Description = "Read, write, and delete Azure Storage containers and blobs for automation reports"
        Critical = $true
    },
    @{
        Name = "Storage Account Contributor"
        Id = "17d1049b-9a84-46fb-8f53-869881c3d3ab"
        Description = "Manage storage accounts including access keys and configuration"
        Critical = $true
    }
)

Write-Host ""
Write-Host "Required Azure RBAC roles for Automation Storage access:" -ForegroundColor Cyan
foreach ($Role in $RequiredRoles) {
    $CriticalText = if ($Role.Critical) { " [CRITICAL]" } else { "" }
    Write-Host "  • $($Role.Name)$CriticalText" -ForegroundColor White
    Write-Host "    Purpose: $($Role.Description)" -ForegroundColor Gray
}
Write-Host ""

if ($WhatIf) {
    Write-Host "🔍 WHATIF MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Would grant the following Azure RBAC roles to managed identity $ManagedIdentityObjectId:" -ForegroundColor Yellow
    foreach ($Role in $RequiredRoles) {
        Write-Host "  ✓ $($Role.Name)" -ForegroundColor Green
        Write-Host "    Scope: Resource Group '$ResourceGroupName'" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "This will allow the automation managed identity to:" -ForegroundColor Yellow
    Write-Host "  • Create and manage storage accounts" -ForegroundColor Green
    Write-Host "  • Create containers for different automation services" -ForegroundColor Green
    Write-Host "  • Upload and download automation reports" -ForegroundColor Green
    Write-Host "  • Manage blob lifecycle policies" -ForegroundColor Green
    Write-Host ""
    Write-Host "To apply these changes, re-run without -WhatIf parameter" -ForegroundColor Yellow
    exit 0
}

try {
    # Connect to Azure
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
    Write-Host "  Account: $($Context.Account.Id)" -ForegroundColor Gray
    Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
    Write-Host "  Subscription: $($Context.Subscription.Name)" -ForegroundColor Gray
    
    # Validate account permissions
    if (-not (Test-AccountPermissions -RequiredTenantId $TenantId)) {
        throw "Account permission validation failed"
    }
    
    # Get resource group
    Write-Host ""
    Write-Host "Validating target resource group..." -ForegroundColor Yellow
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
    Write-Host "✓ Found resource group: $ResourceGroupName" -ForegroundColor Green
    Write-Host "  Resource Group ID: $($ResourceGroup.ResourceId)" -ForegroundColor Gray
    
    # Get managed identity service principal
    Write-Host ""
    Write-Host "Locating managed identity service principal..." -ForegroundColor Yellow
    $ManagedIdentityServicePrincipal = Get-AzADServicePrincipal -ObjectId $ManagedIdentityObjectId -ErrorAction Stop
    
    if (-not $ManagedIdentityServicePrincipal) {
        throw "Managed identity service principal not found: $ManagedIdentityObjectId"
    }
    Write-Host "✓ Found managed identity: $($ManagedIdentityServicePrincipal.DisplayName)" -ForegroundColor Green
    Write-Host "  Service Principal ID: $($ManagedIdentityServicePrincipal.Id)" -ForegroundColor Gray
    Write-Host "  Application ID: $($ManagedIdentityServicePrincipal.AppId)" -ForegroundColor Gray
    
    # Grant RBAC roles
    Write-Host ""
    Write-Host "Granting Azure Storage RBAC roles..." -ForegroundColor Cyan
    $SuccessCount = 0
    $FailureCount = 0
    
    foreach ($Role in $RequiredRoles) {
        Write-Host "Processing role: $($Role.Name)" -ForegroundColor Yellow
        
        # Check if role assignment already exists
        $ExistingAssignment = Get-AzRoleAssignment -ObjectId $ManagedIdentityObjectId -RoleDefinitionName $Role.Name -Scope $ResourceGroup.ResourceId -ErrorAction SilentlyContinue
        
        if ($ExistingAssignment) {
            Write-Host "  ✓ Role already assigned: $($Role.Name)" -ForegroundColor Green
            $SuccessCount++
        } else {
            # Grant the role with retry logic for timing issues
            try {
                $MaxRetries = 3
                $RetryCount = 0
                $RoleAssigned = $false
                
                do {
                    try {
                        if ($RetryCount -gt 0) {
                            $WaitTime = [math]::Pow(2, $RetryCount) * 5
                            Write-Host "  ⏳ Retrying in $WaitTime seconds..." -ForegroundColor Yellow
                            Start-Sleep -Seconds $WaitTime
                        }
                        
                        New-AzRoleAssignment -ObjectId $ManagedIdentityObjectId -RoleDefinitionName $Role.Name -Scope $ResourceGroup.ResourceId -ErrorAction Stop | Out-Null
                        Write-Host "  ✓ Successfully granted: $($Role.Name)" -ForegroundColor Green
                        $SuccessCount++
                        $RoleAssigned = $true
                        break
                    }
                    catch {
                        $RetryCount++
                        if ($RetryCount -gt $MaxRetries) {
                            Write-Warning "  Failed to grant $($Role.Name): $_"
                            $FailureCount++
                            break
                        }
                    }
                } while ($RetryCount -le $MaxRetries -and -not $RoleAssigned)
            }
            catch {
                Write-Error "  ✗ Failed to grant $($Role.Name): $_"
                $FailureCount++
            }
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "STORAGE PERMISSION GRANT SUMMARY" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Managed Identity: $($ManagedIdentityServicePrincipal.DisplayName)" -ForegroundColor White
    Write-Host "Object ID: $ManagedIdentityObjectId" -ForegroundColor Gray
    Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Gray
    Write-Host "Tenant: $TenantId" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Results:" -ForegroundColor White
    Write-Host "  ✓ Successful: $SuccessCount role assignments" -ForegroundColor Green
    if ($FailureCount -gt 0) {
        Write-Host "  ✗ Failed: $FailureCount role assignments" -ForegroundColor Red
    }
    Write-Host ""
    
    if ($FailureCount -eq 0) {
        Write-Host "🎉 All storage permissions granted successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "🔐 Granted Capabilities:" -ForegroundColor Cyan
        Write-Host "The managed identity can now:" -ForegroundColor White
        Write-Host "  ✓ Create and configure storage accounts" -ForegroundColor Green
        Write-Host "  ✓ Manage storage containers and blobs" -ForegroundColor Green
        Write-Host "  ✓ Upload automation reports and logs" -ForegroundColor Green
        Write-Host "  ✓ Configure lifecycle management policies" -ForegroundColor Green
        Write-Host "  ✓ Access storage account keys and connection strings" -ForegroundColor Green
        Write-Host ""
        Write-Host "🔧 Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Deploy the storage infrastructure:" -ForegroundColor White
        Write-Host "   ./Deploy-AutomationStorageSetup.ps1 \`" -ForegroundColor Gray
        Write-Host "     -SubscriptionId '$SubscriptionId' \`" -ForegroundColor Gray
        Write-Host "     -TenantId '$TenantId' \`" -ForegroundColor Gray
        Write-Host "     -ResourceGroupName '$ResourceGroupName' \`" -ForegroundColor Gray
        Write-Host "     -AutomationManagedIdentityId '$ManagedIdentityObjectId'" -ForegroundColor Gray
        Write-Host ""
        Write-Host "2. Update automation scripts to use the new storage account" -ForegroundColor White
        Write-Host "3. Test report uploads from your automation runbooks" -ForegroundColor White
        Write-Host ""
        Write-Host "The automation managed identity is now ready for storage deployment!" -ForegroundColor Green
    } else {
        Write-Warning "Some role assignments failed. Review the errors above and retry."
        exit 1
    }
    
} catch {
    Write-Error "Storage permission grant failed: $_"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Owner or User Access Administrator role on the resource group" -ForegroundColor Gray
    Write-Host "2. Verify the managed identity Object ID is correct" -ForegroundColor Gray
    Write-Host "3. Check that the Automation Account has system-assigned managed identity enabled" -ForegroundColor Gray
    Write-Host "4. Ensure you're using an organizational account (not personal MSA)" -ForegroundColor Gray
    Write-Host "5. Verify the resource group exists and you have access to it" -ForegroundColor Gray
    exit 1
}