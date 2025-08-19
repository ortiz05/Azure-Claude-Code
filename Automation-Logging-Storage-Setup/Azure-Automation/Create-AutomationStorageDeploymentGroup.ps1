# Create-AutomationStorageDeploymentGroup.ps1
# Creates Azure AD security group with permissions for Automation Storage Setup deployment
# 
# Purpose: Provision a dedicated group with least-privilege access for storage infrastructure
# Scope: Azure RBAC permissions for storage account and container management
#
# MANDATORY 3-STEP WORKFLOW - This is Step 1 of 3:
# Step 1: Create-AutomationStorageDeploymentGroup.ps1 (THIS SCRIPT)
# Step 2: Grant-AutomationStoragePermissions.ps1
# Step 3: Deploy-AutomationStorageSetup.ps1

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD Tenant ID (REQUIRED to avoid authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where the storage will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name where Azure Storage will be deployed")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD group name for Automation Storage permissions")]
    [ValidateLength(1, 256)]
    [string]$GroupName = "AutomationStorage-Deployment-Users",
    
    [Parameter(Mandatory = $false, HelpMessage = "Group description")]
    [string]$GroupDescription = "Automation Storage deployment permissions for Azure Storage infrastructure management",
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be created without making changes")]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# PowerShell and module compatibility validation
function Test-PowerShellCompatibility {
    Write-Host "Validating PowerShell compatibility..." -ForegroundColor Yellow
    
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7.0 or later is required. Current version: $($PSVersion.ToString())"
        return $false
    }
    Write-Host "✓ PowerShell version: $($PSVersion.ToString())" -ForegroundColor Green
    
    $RequiredModules = @('Az.Accounts', 'Az.Resources')
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
Missing required modules. Install them using:
$($MissingModules | ForEach-Object { "Install-Module -Name $_ -Scope CurrentUser -Force" } | Out-String)
"@
        return $false
    }
    
    Write-Host "✓ PowerShell compatibility validation passed" -ForegroundColor Green
    return $true
}

Write-Host @"
=========================================
Automation Storage Deployment Group Setup
Azure Infrastructure Permissions
=========================================
"@ -ForegroundColor Cyan

Write-Host "Group Name: $GroupName" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Tenant: $TenantId" -ForegroundColor Yellow
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
    Write-Host "• Azure AD Group: $GroupName" -ForegroundColor Green
    Write-Host "• Group Description: $GroupDescription" -ForegroundColor Green
    Write-Host "• RBAC Roles on Resource Group '$ResourceGroupName':" -ForegroundColor Green
    Write-Host "  - Storage Account Contributor (manage storage accounts)" -ForegroundColor Gray
    Write-Host "  - Storage Blob Data Contributor (manage containers and blobs)" -ForegroundColor Gray
    Write-Host "  - Reader (view resource group contents)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Next steps after group creation:" -ForegroundColor Yellow
    Write-Host "1. Add authorized users to the group" -ForegroundColor Gray
    Write-Host "2. Run Grant-AutomationStoragePermissions.ps1 for managed identity access" -ForegroundColor Gray
    Write-Host "3. Run Deploy-AutomationStorageSetup.ps1 to create storage infrastructure" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To create these resources, re-run without -WhatIf parameter" -ForegroundColor Yellow
    exit 0
}

try {
    # Connect to Azure
    Write-Host ""
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    
    $Context = Get-AzContext
    if (-not $Context -or $Context.Tenant.Id -ne $TenantId) {
        Write-Host "Please authenticate with an account that has:" -ForegroundColor Yellow
        Write-Host "  - User Administrator or Global Administrator (to create groups)" -ForegroundColor Gray
        Write-Host "  - Owner or User Access Administrator (for Azure RBAC)" -ForegroundColor Gray
        Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
    }
    
    $Context = Get-AzContext
    if ($Context.Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId
    }
    
    Write-Host "✓ Connected to Azure" -ForegroundColor Green
    Write-Host "  Account: $($Context.Account.Id)" -ForegroundColor Gray
    Write-Host "  Subscription: $($Context.Subscription.Name)" -ForegroundColor Gray
    Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
    
    # Validate resource group exists
    Write-Host ""
    Write-Host "Validating target resource group..." -ForegroundColor Yellow
    $TargetResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    
    if (-not $TargetResourceGroup) {
        throw "Resource group '$ResourceGroupName' not found. Please create it first or specify an existing resource group."
    }
    
    Write-Host "✓ Target resource group exists: $ResourceGroupName" -ForegroundColor Green
    Write-Host "  Location: $($TargetResourceGroup.Location)" -ForegroundColor Gray
    Write-Host "  Resource Group ID: $($TargetResourceGroup.ResourceId)" -ForegroundColor Gray
    
    # Check if group already exists
    Write-Host ""
    Write-Host "Checking if Azure AD group exists..." -ForegroundColor Yellow
    $ExistingGroup = Get-AzADGroup -DisplayName $GroupName -ErrorAction SilentlyContinue
    
    if ($ExistingGroup) {
        Write-Host "✓ Group already exists: $GroupName" -ForegroundColor Green
        Write-Host "  Object ID: $($ExistingGroup.Id)" -ForegroundColor Gray
        Write-Host "  Description: $($ExistingGroup.Description)" -ForegroundColor Gray
        $DeploymentGroup = $ExistingGroup
    } else {
        # Create Azure AD group
        Write-Host ""
        Write-Host "Creating Azure AD deployment group..." -ForegroundColor Yellow
        
        $GroupParams = @{
            DisplayName = $GroupName
            Description = $GroupDescription
            SecurityEnabled = $true
            MailEnabled = $false
        }
        
        $DeploymentGroup = New-AzADGroup @GroupParams
        Write-Host "✓ Azure AD group created successfully" -ForegroundColor Green
        Write-Host "  Group Name: $($DeploymentGroup.DisplayName)" -ForegroundColor Gray
        Write-Host "  Object ID: $($DeploymentGroup.Id)" -ForegroundColor Gray
        
        # Wait for group propagation
        Write-Host "⏳ Waiting for group propagation (30 seconds)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
    }
    
    # Define required RBAC roles for storage deployment
    $RequiredRoles = @(
        @{
            Name = "Storage Account Contributor"
            Description = "Manage storage accounts and their configuration"
            Scope = $TargetResourceGroup.ResourceId
        },
        @{
            Name = "Storage Blob Data Contributor" 
            Description = "Read, write, and delete Azure Storage containers and blobs"
            Scope = $TargetResourceGroup.ResourceId
        },
        @{
            Name = "Reader"
            Description = "View all resources but not make any changes"
            Scope = $TargetResourceGroup.ResourceId
        }
    )
    
    # Assign RBAC roles
    Write-Host ""
    Write-Host "Assigning RBAC roles to deployment group..." -ForegroundColor Yellow
    
    $SuccessfulAssignments = 0
    $FailedAssignments = 0
    
    foreach ($Role in $RequiredRoles) {
        Write-Host "  Assigning role: $($Role.Name)" -ForegroundColor Cyan
        
        try {
            # Check if role assignment already exists
            $ExistingAssignment = Get-AzRoleAssignment -ObjectId $DeploymentGroup.Id -RoleDefinitionName $Role.Name -Scope $Role.Scope -ErrorAction SilentlyContinue
            
            if ($ExistingAssignment) {
                Write-Host "    ✓ Role already assigned: $($Role.Name)" -ForegroundColor Green
                $SuccessfulAssignments++
            } else {
                # Assign the role with retry logic for timing issues
                $MaxRetries = 3
                $RetryCount = 0
                $RoleAssigned = $false
                
                do {
                    try {
                        if ($RetryCount -gt 0) {
                            $WaitTime = [math]::Pow(2, $RetryCount) * 5
                            Write-Host "    ⏳ Retrying in $WaitTime seconds..." -ForegroundColor Yellow
                            Start-Sleep -Seconds $WaitTime
                        }
                        
                        New-AzRoleAssignment -ObjectId $DeploymentGroup.Id -RoleDefinitionName $Role.Name -Scope $Role.Scope -ErrorAction Stop | Out-Null
                        Write-Host "    ✓ Role assigned successfully: $($Role.Name)" -ForegroundColor Green
                        $SuccessfulAssignments++
                        $RoleAssigned = $true
                        break
                    }
                    catch {
                        $RetryCount++
                        if ($RetryCount -gt $MaxRetries) {
                            Write-Warning "    Failed to assign role $($Role.Name): $_"
                            $FailedAssignments++
                            break
                        }
                    }
                } while ($RetryCount -le $MaxRetries -and -not $RoleAssigned)
            }
        }
        catch {
            Write-Warning "  Failed to assign role $($Role.Name): $_"
            $FailedAssignments++
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT GROUP SETUP SUMMARY" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    Write-Host "✅ Azure AD Group: $($DeploymentGroup.DisplayName)" -ForegroundColor Green
    Write-Host "  Object ID: $($DeploymentGroup.Id)" -ForegroundColor Gray
    Write-Host "  Description: $($DeploymentGroup.Description)" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "📋 RBAC Role Assignments:" -ForegroundColor Cyan
    Write-Host "  ✓ Successful: $SuccessfulAssignments roles" -ForegroundColor Green
    if ($FailedAssignments -gt 0) {
        Write-Host "  ✗ Failed: $FailedAssignments roles" -ForegroundColor Red
    }
    Write-Host "  Target Scope: $ResourceGroupName" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "🔧 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Add authorized users to the group:" -ForegroundColor White
    Write-Host "   Azure Portal → Azure AD → Groups → $GroupName → Members" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Grant automation managed identity permissions:" -ForegroundColor White
    Write-Host "   ./Grant-AutomationStoragePermissions.ps1 \`" -ForegroundColor Gray
    Write-Host "     -ManagedIdentityObjectId 'your-managed-identity-id' \`" -ForegroundColor Gray
    Write-Host "     -TenantId '$TenantId'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Deploy the storage infrastructure:" -ForegroundColor White
    Write-Host "   ./Deploy-AutomationStorageSetup.ps1 \`" -ForegroundColor Gray
    Write-Host "     -SubscriptionId '$SubscriptionId' \`" -ForegroundColor Gray
    Write-Host "     -TenantId '$TenantId' \`" -ForegroundColor Gray
    Write-Host "     -ResourceGroupName '$ResourceGroupName'" -ForegroundColor Gray
    
    if ($FailedAssignments -eq 0) {
        Write-Host ""
        Write-Host "🎉 Deployment group setup completed successfully!" -ForegroundColor Green
        Write-Host "The group is ready for Automation Storage deployment." -ForegroundColor Green
    } else {
        Write-Warning "Some role assignments failed. Please review and retry manually if needed."
        exit 1
    }
    
} catch {
    Write-Error "Deployment group setup failed: $_"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have User Administrator or Global Administrator role" -ForegroundColor Gray
    Write-Host "2. Verify you have Owner or User Access Administrator on the resource group" -ForegroundColor Gray
    Write-Host "3. Check that the resource group exists and you have access" -ForegroundColor Gray
    Write-Host "4. Ensure you're using an organizational account (not personal MSA)" -ForegroundColor Gray
    exit 1
}