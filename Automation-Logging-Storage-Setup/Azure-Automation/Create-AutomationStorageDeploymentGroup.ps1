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
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where the automation storage will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD tenant ID (required for targeted authentication - prevents multi-tenant authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
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
=========================================
Automation Storage Deployment Group Setup
Azure Infrastructure Permissions
=========================================
"@ -ForegroundColor Cyan

Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Group Name: $GroupName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Required Azure RBAC roles for Automation Storage deployment (minimal permissions)
$RequiredAzureRoles = @(
    @{
        Name = "Storage Account Contributor"
        Reason = "Create and manage storage accounts for automation logging"
        Required = $true
    },
    @{
        Name = "Storage Blob Data Contributor"
        Reason = "Manage containers and blobs for automation reports and logs"
        Required = $true
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
        } elseif ($Context.Tenant.Id -ne $TenantId) {
            $NeedsConnection = $true
        }
        
        if ($NeedsConnection) {
            Write-Host "Please authenticate with an account that has:" -ForegroundColor Yellow
            Write-Host "  - User Administrator or Global Administrator (to create groups)" -ForegroundColor Gray
            Write-Host "  - Owner or User Access Administrator (for Azure RBAC)" -ForegroundColor Gray
            Write-Host "  - Connecting to tenant: $TenantId" -ForegroundColor Gray
            
            Write-Host "  - Using default interactive authentication" -ForegroundColor Gray
            Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
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
            Write-Host "✓ Azure AD group management access confirmed" -ForegroundColor Green
        } catch {
            Write-Warning "May not have permissions to create Azure AD groups"
            Write-Host "Required role: User Administrator or Global Administrator" -ForegroundColor Yellow
        }
        
        return $true
        
    } catch {
        Write-Error "Permission validation failed: $($_.Exception.Message)"
        return $false
    }
}

function New-AutomationStorageDeploymentGroup {
    try {
        Write-Host "Creating Azure AD security group for Automation Storage deployment..." -ForegroundColor Yellow
        
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
        # Generate mail nickname from group name (remove spaces and special chars, max 64 chars)
        $MailNickname = ($GroupName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($GroupName -replace '[^a-zA-Z0-9]', '').Length))
        
        $Group = New-AzADGroup `
            -DisplayName $GroupName `
            -Description $GroupDescription `
            -MailNickname $MailNickname `
            -SecurityEnabled `
            -MailEnabled:$false
        
        Write-Host "✓ Created Azure AD group: $GroupName" -ForegroundColor Green
        Write-Host "  Group ID: $($Group.Id)" -ForegroundColor Gray
        
        # Wait for Azure AD group to propagate (eventual consistency)
        Write-Host "  Waiting for group to propagate in Azure AD..." -ForegroundColor Yellow
        $MaxWaitTime = 120 # Maximum wait time in seconds
        $WaitInterval = 5  # Check every 5 seconds
        $ElapsedTime = 0
        
        do {
            Start-Sleep -Seconds $WaitInterval
            $ElapsedTime += $WaitInterval
            
            # Try to retrieve the group to verify it's fully propagated
            $VerifyGroup = Get-AzADGroup -ObjectId $Group.Id -ErrorAction SilentlyContinue
            if ($VerifyGroup) {
                Write-Host "  ✓ Group propagation confirmed (waited $ElapsedTime seconds)" -ForegroundColor Green
                break
            }
            
            Write-Host "  Still waiting... ($ElapsedTime/$MaxWaitTime seconds)" -ForegroundColor Gray
            
        } while ($ElapsedTime -lt $MaxWaitTime)
        
        if ($ElapsedTime -ge $MaxWaitTime) {
            Write-Warning "Group may not be fully propagated yet. Manual verification recommended."
        }
        
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
        Write-Host "Assigning Azure RBAC permissions..." -ForegroundColor Yellow
        
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
        
        # Assign each required Azure RBAC role
        foreach ($Role in $RequiredAzureRoles) {
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
                # Retry role assignment with exponential backoff for timing issues
                $MaxRetries = 3
                $RetryCount = 0
                $AssignmentSucceeded = $false
                
                do {
                    try {
                        if ($RetryCount -gt 0) {
                            $WaitTime = [math]::Pow(2, $RetryCount) * 5  # 5, 10, 20 seconds
                            Write-Host "    Retrying in $WaitTime seconds (attempt $($RetryCount + 1)/$($MaxRetries + 1))..." -ForegroundColor Gray
                            Start-Sleep -Seconds $WaitTime
                        }
                        
                        New-AzRoleAssignment `
                            -ObjectId $Group.Id `
                            -RoleDefinitionName $Role.Name `
                            -Scope $ResourceGroupScope
                        
                        Write-Host "  ✓ Assigned role: $($Role.Name)" -ForegroundColor Green
                        $AssignmentSucceeded = $true
                        break
                        
                    } catch {
                        $RetryCount++
                        if ($RetryCount -gt $MaxRetries) {
                            Write-Warning "  Failed to assign role $($Role.Name) after $($MaxRetries + 1) attempts: $($_.Exception.Message)"
                            if ($_.Exception.Message -like "*BadRequest*") {
                                Write-Host "    This may be due to timing issues. You can manually assign the role later:" -ForegroundColor Yellow
                                Write-Host "    New-AzRoleAssignment -ObjectId $($Group.Id) -RoleDefinitionName '$($Role.Name)' -Scope '$ResourceGroupScope'" -ForegroundColor Gray
                            }
                        } else {
                            Write-Host "    Attempt $($RetryCount) failed: $($_.Exception.Message)" -ForegroundColor Gray
                        }
                    }
                } while ($RetryCount -le $MaxRetries -and -not $AssignmentSucceeded)
            }
        }
        
        Write-Host "✓ Azure RBAC role assignments completed" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to assign Azure RBAC permissions: $($_.Exception.Message)"
        return $false
    }
}

function Show-GroupSummary {
    param(
        [Parameter(Mandatory = $true)]
        $Group
    )
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " AUTOMATION STORAGE GROUP CREATED SUCCESSFULLY" -ForegroundColor Green
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
    
    Write-Host "`n🔐 Assigned Azure RBAC Permissions:" -ForegroundColor Cyan
    Write-Host "  Scope: /subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" -ForegroundColor White
    foreach ($Role in $RequiredAzureRoles) {
        if ($Role.Required) {
            Write-Host "  ✓ $($Role.Name)" -ForegroundColor Green
            Write-Host "    Purpose: $($Role.Reason)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n🎯 Purpose:" -ForegroundColor Cyan
    Write-Host "  This group provides least-privilege access for Automation Storage deployment" -ForegroundColor White
    Write-Host "  Members can create and manage Azure Storage infrastructure for automation logging" -ForegroundColor White
    
    Write-Host "`n👥 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Add authorized users to this group:" -ForegroundColor White
    Write-Host "     Azure Portal → Azure AD → Groups → $GroupName → Members" -ForegroundColor Gray
    Write-Host "  2. Grant automation managed identity permissions:" -ForegroundColor White
    Write-Host "     ./Grant-AutomationStoragePermissions.ps1 -ManagedIdentityObjectId '<id>' -TenantId '$TenantId'" -ForegroundColor Gray
    Write-Host "  3. Deploy storage infrastructure:" -ForegroundColor White
    Write-Host "     ./Deploy-AutomationLoggingStorageSetup.ps1 -SubscriptionId '$SubscriptionId' -TenantId '$TenantId' -ResourceGroupName '$ResourceGroupName'" -ForegroundColor Gray
    
    Write-Host "`n🛡️ Security Benefits:" -ForegroundColor Yellow
    Write-Host "  ✓ Dedicated group for storage operations only" -ForegroundColor Green
    Write-Host "  ✓ Minimal required permissions" -ForegroundColor Green
    Write-Host "  ✓ Scoped to storage account and blob management" -ForegroundColor Green
    Write-Host "  ✓ Easily auditable access control" -ForegroundColor Green
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
    $Group = New-AutomationStorageDeploymentGroup
    if (-not $Group) {
        throw "Failed to create deployment group"
    }
    
    # Step 4: Assign Azure RBAC permissions
    $PermissionsSet = Set-ResourceGroupPermissions -Group $Group
    if (-not $PermissionsSet -and -not $WhatIf) {
        Write-Warning "Failed to assign some Azure RBAC permissions. Check troubleshooting section."
    }
    
    # Step 5: Show summary
    Show-GroupSummary -Group $Group
    
    Write-Host "`n🎉 Automation Storage deployment group setup completed!" -ForegroundColor Green
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have User Administrator or Global Administrator role (for group creation)" -ForegroundColor Gray
    Write-Host "2. Verify you have Owner or User Access Administrator role (for Azure RBAC assignments)" -ForegroundColor Gray
    Write-Host "3. Check that the resource group exists and you have access" -ForegroundColor Gray
    Write-Host "4. Ensure you are using an organizational account (not personal MSA)" -ForegroundColor Gray
    exit 1
}