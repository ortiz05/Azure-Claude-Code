# Create-AzureFilesDeploymentGroup.ps1
# Creates Azure AD security group with minimal permissions for Azure Files deployment
# 
# Purpose: Provision a dedicated group with least-privilege access for Azure Files deployment
# Scope: Resource Group level permissions only (no tenant-wide access)

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where resources will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD tenant ID (optional - will use current tenant if not specified)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId = "",
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name where Azure Files will be deployed")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD group name for deployment permissions")]
    [ValidateLength(1, 256)]
    [string]$GroupName = "AzureFiles-Deployment-$ResourceGroupName",
    
    [Parameter(Mandatory = $false, HelpMessage = "Group description")]
    [string]$GroupDescription = "Azure Files deployment permissions for resource group: $ResourceGroupName",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include VNet permissions (needed if using VNet integration)")]
    [switch]$IncludeNetworkPermissions = $true,
    
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
    $RequiredModules = @('Az.Accounts', 'Az.Resources')
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

Write-Host @"
========================================
 AZURE FILES DEPLOYMENT GROUP SETUP
 Least Privilege Security Group Creation
========================================
"@ -ForegroundColor Cyan

Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
if ($TenantId) {
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
} else {
    Write-Host "Tenant ID: (using current tenant)" -ForegroundColor Yellow
}
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Group Name: $GroupName" -ForegroundColor Yellow
Write-Host "Include Network Permissions: $IncludeNetworkPermissions" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Required built-in Azure roles for Azure Files deployment
$RequiredRoles = @(
    @{
        Name = "Storage Account Contributor"
        Reason = "Create and manage storage accounts and file shares"
        Required = $true
    },
    @{
        Name = "Network Contributor" 
        Reason = "Configure VNet service endpoints and network security"
        Required = $IncludeNetworkPermissions
    }
)

function Connect-ToAzure {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        
        $Context = Get-AzContext
        $NeedsConnection = $false
        
        if (-not $Context) {
            $NeedsConnection = $true
        } elseif ($Context.Subscription.Id -ne $SubscriptionId) {
            $NeedsConnection = $true
        } elseif ($TenantId -and $Context.Tenant.Id -ne $TenantId) {
            $NeedsConnection = $true
        }
        
        if ($NeedsConnection) {
            Write-Host "Please authenticate with an account that has:" -ForegroundColor Yellow
            Write-Host "  - User Administrator or Global Administrator (to create groups)" -ForegroundColor Gray
            Write-Host "  - Owner or User Access Administrator (to assign roles)" -ForegroundColor Gray
            
            if ($TenantId) {
                Write-Host "  - Connecting to tenant: $TenantId" -ForegroundColor Gray
                Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
            } else {
                Connect-AzAccount -SubscriptionId $SubscriptionId
            }
        }
        
        $Context = Get-AzContext
        Write-Host "✓ Connected to Azure subscription: $SubscriptionId" -ForegroundColor Green
        Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
        return $true
        
    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        return $false
    }
}

function Test-RequiredPermissions {
    try {
        Write-Host "Validating permissions..." -ForegroundColor Yellow
        
        # Test Azure AD permissions (group creation)
        try {
            Get-AzADGroup -First 1 -ErrorAction Stop | Out-Null
            Write-Host "✓ Azure AD group read access confirmed" -ForegroundColor Green
        } catch {
            Write-Warning "May not have permissions to create Azure AD groups"
            Write-Host "Required role: User Administrator or Global Administrator" -ForegroundColor Yellow
        }
        
        # Test role assignment permissions
        try {
            $ResourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
            Get-AzRoleAssignment -Scope $ResourceGroupScope -First 1 -ErrorAction Stop | Out-Null
            Write-Host "✓ Role assignment access confirmed" -ForegroundColor Green
        } catch {
            Write-Warning "May not have permissions to assign roles"
            Write-Host "Required role: Owner or User Access Administrator" -ForegroundColor Yellow
        }
        
        return $true
        
    } catch {
        Write-Error "Permission validation failed: $($_.Exception.Message)"
        return $false
    }
}

function New-AzureFilesDeploymentGroup {
    try {
        Write-Host "Creating Azure AD security group..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create group: $GroupName" -ForegroundColor Yellow
            return @{ Id = "whatif-group-id"; DisplayName = $GroupName }
        }
        
        # Check if group already exists
        $ExistingGroup = Get-AzADGroup -DisplayName $GroupName -ErrorAction SilentlyContinue
        if ($ExistingGroup) {
            Write-Host "✓ Group already exists: $GroupName" -ForegroundColor Green
            return $ExistingGroup
        }
        
        # Create new security group
        $Group = New-AzADGroup `
            -DisplayName $GroupName `
            -Description $GroupDescription `
            -SecurityEnabled $true `
            -MailEnabled $false
        
        Write-Host "✓ Created Azure AD group: $GroupName" -ForegroundColor Green
        Write-Host "  Group ID: $($Group.Id)" -ForegroundColor Gray
        
        return $Group
        
    } catch {
        Write-Error "Failed to create group: $($_.Exception.Message)"
        return $null
    }
}

function Set-ResourceGroupPermissions {
    param(
        [Parameter(Mandatory = $true)]
        $Group
    )
    
    try {
        Write-Host "Assigning resource group permissions..." -ForegroundColor Yellow
        
        # Define the resource group scope
        $ResourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        
        # Verify resource group exists
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $ResourceGroup) {
            Write-Host "Resource group '$ResourceGroupName' does not exist. Creating it..." -ForegroundColor Yellow
            
            if ($WhatIf) {
                Write-Host "[WHATIF] Would create resource group: $ResourceGroupName" -ForegroundColor Yellow
            } else {
                # Prompt for location since we need to create the RG
                $Location = Read-Host "Enter Azure region for resource group (e.g., 'East US 2')"
                New-AzResourceGroup -Name $ResourceGroupName -Location $Location
                Write-Host "✓ Created resource group: $ResourceGroupName" -ForegroundColor Green
            }
        }
        
        # Assign each required role
        foreach ($Role in $RequiredRoles) {
            if (-not $Role.Required) {
                Write-Host "  Skipping role: $($Role.Name) (not required for this configuration)" -ForegroundColor Gray
                continue
            }
            
            Write-Host "  Assigning role: $($Role.Name)" -ForegroundColor Gray
            Write-Host "    Purpose: $($Role.Reason)" -ForegroundColor DarkGray
            
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would assign role: $($Role.Name)" -ForegroundColor Yellow
                continue
            }
            
            # Check if role assignment already exists
            $ExistingAssignment = Get-AzRoleAssignment `
                -ObjectId $Group.Id `
                -RoleDefinitionName $Role.Name `
                -Scope $ResourceGroupScope `
                -ErrorAction SilentlyContinue
            
            if ($ExistingAssignment) {
                Write-Host "  ✓ Role already assigned: $($Role.Name)" -ForegroundColor Green
            } else {
                try {
                    New-AzRoleAssignment `
                        -ObjectId $Group.Id `
                        -RoleDefinitionName $Role.Name `
                        -Scope $ResourceGroupScope
                    
                    Write-Host "  ✓ Assigned role: $($Role.Name)" -ForegroundColor Green
                } catch {
                    Write-Warning "  Failed to assign role $($Role.Name): $($_.Exception.Message)"
                }
            }
        }
        
        Write-Host "✓ Role assignments completed" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to assign permissions: $($_.Exception.Message)"
        return $false
    }
}

function Show-GroupSummary {
    param(
        [Parameter(Mandatory = $true)]
        $Group
    )
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " DEPLOYMENT GROUP CREATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
        return
    }
    
    Write-Host "`n📋 Group Details:" -ForegroundColor Cyan
    Write-Host "  Name: $($Group.DisplayName)" -ForegroundColor White
    Write-Host "  ID: $($Group.Id)" -ForegroundColor White
    Write-Host "  Type: Security Group" -ForegroundColor White
    Write-Host "  Description: $GroupDescription" -ForegroundColor White
    
    Write-Host "`n🔐 Assigned Permissions:" -ForegroundColor Cyan
    Write-Host "  Scope: /subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" -ForegroundColor White
    foreach ($Role in $RequiredRoles) {
        if ($Role.Required) {
            Write-Host "  ✓ $($Role.Name)" -ForegroundColor Green
            Write-Host "    Purpose: $($Role.Reason)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n👥 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Add users to the group:" -ForegroundColor White
    Write-Host "     Add-AzADGroupMember -TargetGroupId $($Group.Id) -MemberUserPrincipalName 'user@company.com'" -ForegroundColor Gray
    Write-Host "  2. Users can now deploy Azure Files to resource group: $ResourceGroupName" -ForegroundColor White
    Write-Host "  3. Run the deployment script:" -ForegroundColor White
    Write-Host "     .\Deploy-SecureAzureFiles.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName ..." -ForegroundColor Gray
    
    Write-Host "`n🛡️ Security Benefits:" -ForegroundColor Yellow
    Write-Host "  ✓ No tenant-wide permissions" -ForegroundColor Green
    Write-Host "  ✓ Scoped to single resource group only" -ForegroundColor Green
    Write-Host "  ✓ Uses built-in Azure roles (Microsoft maintained)" -ForegroundColor Green
    Write-Host "  ✓ No Azure AD admin rights included" -ForegroundColor Green
    Write-Host "  ✓ Easily auditable permissions" -ForegroundColor Green
    
    Write-Host "`n⚠️ Important Notes:" -ForegroundColor Yellow
    Write-Host "  - Group members can ONLY deploy to resource group: $ResourceGroupName" -ForegroundColor White
    Write-Host "  - No access to other subscriptions or resource groups" -ForegroundColor White
    Write-Host "  - Azure AD permission configuration still requires separate admin approval" -ForegroundColor White
    Write-Host "  - Regular access reviews recommended (quarterly)" -ForegroundColor White
}

function Show-AddUserInstructions {
    param($Group)
    
    if ($WhatIf) { return }
    
    Write-Host "`n📝 Quick Commands to Add Users:" -ForegroundColor Cyan
    
    # Add current user option
    try {
        $CurrentUser = Get-AzADUser -SignedIn
        Write-Host "`nAdd yourself to the group:" -ForegroundColor Yellow
        Write-Host "Add-AzADGroupMember -TargetGroupId '$($Group.Id)' -MemberObjectId '$($CurrentUser.Id)'" -ForegroundColor Gray
    } catch {
        Write-Host "`nAdd users by email:" -ForegroundColor Yellow
        Write-Host "Add-AzADGroupMember -TargetGroupId '$($Group.Id)' -MemberUserPrincipalName 'user@company.com'" -ForegroundColor Gray
    }
    
    Write-Host "`nAdd multiple users:" -ForegroundColor Yellow
    Write-Host @"
`$Users = @('user1@company.com', 'user2@company.com', 'user3@company.com')
foreach (`$User in `$Users) {
    Add-AzADGroupMember -TargetGroupId '$($Group.Id)' -MemberUserPrincipalName `$User
    Write-Host "Added: `$User"
}
"@ -ForegroundColor Gray

    Write-Host "`nVerify group membership:" -ForegroundColor Yellow
    Write-Host "Get-AzADGroupMember -GroupId '$($Group.Id)' | Select-Object DisplayName, UserPrincipalName" -ForegroundColor Gray
}

# Main execution
try {
    # Step 1: Connect to Azure
    if (-not (Connect-ToAzure)) {
        throw "Failed to connect to Azure"
    }
    
    # Step 2: Validate permissions
    if (-not (Test-RequiredPermissions)) {
        Write-Warning "Permission validation failed. Continuing anyway..."
    }
    
    # Step 3: Create the deployment group
    $Group = New-AzureFilesDeploymentGroup
    if (-not $Group) {
        throw "Failed to create deployment group"
    }
    
    # Step 4: Assign resource group permissions
    $PermissionsSet = Set-ResourceGroupPermissions -Group $Group
    if (-not $PermissionsSet -and -not $WhatIf) {
        throw "Failed to assign permissions"
    }
    
    # Step 5: Show summary and instructions
    Show-GroupSummary -Group $Group
    Show-AddUserInstructions -Group $Group
    
    Write-Host "`n🎉 Azure Files deployment group setup completed!" -ForegroundColor Green
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have User Administrator or Global Administrator role (for group creation)" -ForegroundColor Gray
    Write-Host "2. Verify you have Owner or User Access Administrator role on the subscription/resource group" -ForegroundColor Gray
    Write-Host "3. Check if the resource group name is valid and doesn't conflict with existing groups" -ForegroundColor Gray
    Write-Host "4. Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
    exit 1
}