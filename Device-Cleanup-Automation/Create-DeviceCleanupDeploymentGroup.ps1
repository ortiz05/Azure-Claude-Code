# Create-DeviceCleanupDeploymentGroup.ps1
# Creates Azure AD security group with minimal permissions for Device Cleanup Automation
# 
# Purpose: Provision a dedicated group with least-privilege access for Device Cleanup deployment
# Scope: Microsoft Graph API permissions for device lifecycle management

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where the automation will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD tenant ID (required for targeted authentication - prevents multi-tenant authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD group name for Device Cleanup automation permissions")]
    [ValidateLength(1, 256)]
    [string]$GroupName = "DeviceCleanup-Automation-Users",
    
    [Parameter(Mandatory = $false, HelpMessage = "Group description")]
    [string]$GroupDescription = "Device Cleanup Automation permissions for enterprise device lifecycle management",
    
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
 DEVICE CLEANUP DEPLOYMENT GROUP SETUP
 Least Privilege Security Group Creation
========================================
"@ -ForegroundColor Cyan

Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Group Name: $GroupName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Required Microsoft Graph permissions for Device Cleanup Automation
$RequiredGraphPermissions = @(
    @{
        Name = "Device.ReadWrite.All"
        Type = "Application"
        Reason = "Read and delete device objects in Azure AD"
        Required = $true
    },
    @{
        Name = "User.Read.All"
        Type = "Application" 
        Reason = "Read user information for device ownership and notifications"
        Required = $true
    },
    @{
        Name = "Directory.ReadWrite.All"
        Type = "Application"
        Reason = "Modify directory objects for device cleanup operations"
        Required = $true
    },
    @{
        Name = "Mail.Send"
        Type = "Application"
        Reason = "Send email notifications to users and administrators"
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
            Write-Host "  - Application Administrator (to grant Graph permissions)" -ForegroundColor Gray
            Write-Host "  - Connecting to tenant: $TenantId" -ForegroundColor Gray
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

function New-DeviceCleanupDeploymentGroup {
    try {
        Write-Host "Creating Azure AD security group for Device Cleanup Automation..." -ForegroundColor Yellow
        
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

function Show-GraphPermissionInstructions {
    param(
        [Parameter(Mandatory = $true)]
        $Group
    )
    
    Write-Host "`n🔐 Microsoft Graph API Permissions Required:" -ForegroundColor Cyan
    Write-Host "The following permissions must be granted to service principals added to this group:" -ForegroundColor White
    
    foreach ($Permission in $RequiredGraphPermissions) {
        if ($Permission.Required) {
            Write-Host "  ✓ $($Permission.Name) ($($Permission.Type))" -ForegroundColor Green
            Write-Host "    Purpose: $($Permission.Reason)" -ForegroundColor Gray
        }
    }
    
    if (-not $WhatIf) {
        Write-Host "`n📋 Manual Steps Required:" -ForegroundColor Yellow
        Write-Host "1. In Azure Portal, go to Azure Active Directory > App Registrations" -ForegroundColor White
        Write-Host "2. Select your service principal/application" -ForegroundColor White
        Write-Host "3. Go to API Permissions > Add a permission > Microsoft Graph > Application permissions" -ForegroundColor White
        Write-Host "4. Add each permission listed above" -ForegroundColor White
        Write-Host "5. Click 'Grant admin consent' for the permissions" -ForegroundColor White
        Write-Host "6. Add the service principal to group: $GroupName" -ForegroundColor White
        
        Write-Host "`n💡 PowerShell Commands (Alternative):" -ForegroundColor Cyan
        Write-Host "# To grant permissions via PowerShell (requires Global Admin):" -ForegroundColor Gray
        Write-Host "Connect-MgGraph -Scopes 'Application.ReadWrite.All'" -ForegroundColor Gray
        Write-Host "# Then grant each permission using New-MgServicePrincipalAppRoleAssignment" -ForegroundColor Gray
    }
}

function Show-GroupSummary {
    param(
        [Parameter(Mandatory = $true)]
        $Group
    )
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " DEVICE CLEANUP GROUP CREATED SUCCESSFULLY" -ForegroundColor Green
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
    
    Write-Host "`n🎯 Purpose:" -ForegroundColor Cyan
    Write-Host "  This group provides access for Device Cleanup Automation service principals" -ForegroundColor White
    Write-Host "  Members can perform automated device lifecycle management operations" -ForegroundColor White
    
    Write-Host "`n👥 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Grant Microsoft Graph permissions to your service principal (see instructions above)" -ForegroundColor White
    Write-Host "  2. Add service principals to this group:" -ForegroundColor White
    Write-Host "     Add-AzADGroupMember -TargetGroupId $($Group.Id) -MemberObjectId '<ServicePrincipalId>'" -ForegroundColor Gray
    Write-Host "  3. Deploy Device Cleanup Automation using Azure Automation" -ForegroundColor White
    Write-Host "  4. Test device cleanup operations in a safe environment first" -ForegroundColor White
    
    Write-Host "`n🛡️ Security Benefits:" -ForegroundColor Yellow
    Write-Host "  ✓ Dedicated group for device cleanup operations only" -ForegroundColor Green
    Write-Host "  ✓ No Global Admin rights required for group members" -ForegroundColor Green
    Write-Host "  ✓ Scoped permissions for device lifecycle management" -ForegroundColor Green
    Write-Host "  ✓ Easily auditable access control" -ForegroundColor Green
    Write-Host "  ✓ Supports multiple service principals if needed" -ForegroundColor Green
    
    Write-Host "`n⚠️ Important Notes:" -ForegroundColor Yellow
    Write-Host "  - Service principals in this group can DELETE devices from Azure AD" -ForegroundColor Red
    Write-Host "  - Always test in non-production environment first" -ForegroundColor White
    Write-Host "  - Review device cleanup policies and safety thresholds" -ForegroundColor White
    Write-Host "  - Monitor automation logs for unusual activity" -ForegroundColor White
    Write-Host "  - Regular access reviews recommended (quarterly)" -ForegroundColor White
}

function Show-ServicePrincipalInstructions {
    param($Group)
    
    if ($WhatIf) { return }
    
    Write-Host "`n📝 Quick Commands to Add Service Principals:" -ForegroundColor Cyan
    Write-Host "`nAdd a service principal to the group:" -ForegroundColor Yellow
    Write-Host "Add-AzADGroupMember -TargetGroupId '$($Group.Id)' -MemberObjectId '<ServicePrincipalObjectId>'" -ForegroundColor Gray
    
    Write-Host "`nFind service principal Object ID:" -ForegroundColor Yellow
    Write-Host "Get-AzADServicePrincipal -DisplayName 'YourAppName' | Select-Object Id, DisplayName" -ForegroundColor Gray
    
    Write-Host "`nVerify group membership:" -ForegroundColor Yellow
    Write-Host "Get-AzADGroupMember -GroupId '$($Group.Id)' | Select-Object DisplayName, Id" -ForegroundColor Gray
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
    $Group = New-DeviceCleanupDeploymentGroup
    if (-not $Group) {
        throw "Failed to create deployment group"
    }
    
    # Step 4: Show Graph permission instructions
    Show-GraphPermissionInstructions -Group $Group
    
    # Step 5: Show summary and instructions
    Show-GroupSummary -Group $Group
    Show-ServicePrincipalInstructions -Group $Group
    
    Write-Host "`n🎉 Device Cleanup deployment group setup completed!" -ForegroundColor Green
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have User Administrator or Global Administrator role (for group creation)" -ForegroundColor Gray
    Write-Host "2. Verify you have Application Administrator role (for Graph API permissions)" -ForegroundColor Gray
    Write-Host "3. Check if the group name conflicts with existing groups" -ForegroundColor Gray
    Write-Host "4. Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
    exit 1
}