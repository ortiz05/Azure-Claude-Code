# Create-MFAMonitorDeploymentGroup.ps1
# Creates Azure AD security group with permissions for MFA Compliance Monitor deployment
# 
# Purpose: Provision a dedicated group with least-privilege access for MFA monitoring
# Scope: Microsoft Graph API permissions for compliance monitoring and reporting

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID where the automation will be deployed")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD tenant ID")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name where Azure Automation will be deployed")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD group name for MFA Monitor permissions")]
    [ValidateLength(1, 256)]
    [string]$GroupName = "MFAComplianceMonitor-Automation-Users",
    
    [Parameter(Mandatory = $false, HelpMessage = "Group description")]
    [string]$GroupDescription = "MFA Compliance Monitor automation permissions for authentication method compliance tracking",
    
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
        $ModuleInfo = Get-Module -Name $Module -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($ModuleInfo) {
            Write-Host "✓ $Module version: $($ModuleInfo.Version)" -ForegroundColor Green
        } else {
            $MissingModules += $Module
            Write-Warning "✗ Missing module: $Module"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Error "Missing required modules: $($MissingModules -join ', ')"
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
 MFA COMPLIANCE MONITOR GROUP SETUP
 Least Privilege Security Configuration
========================================
"@ -ForegroundColor Cyan

Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Group Name: $GroupName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Required Microsoft Graph permissions for MFA Compliance Monitor
$RequiredGraphPermissions = @(
    @{
        Name = "AuditLog.Read.All"
        Type = "Application"
        Reason = "Read authentication method registration and usage audit logs"
        Required = $true
    },
    @{
        Name = "User.Read.All"
        Type = "Application" 
        Reason = "Read user profiles and authentication methods"
        Required = $true
    },
    @{
        Name = "Directory.Read.All"
        Type = "Application"
        Reason = "Read directory objects and group memberships for reporting"
        Required = $true
    },
    @{
        Name = "Mail.Send"
        Type = "Application"
        Reason = "Send compliance notifications to users and administrators"
        Required = $true
    }
)

# Required Azure RBAC roles for MFA Monitor deployment
$RequiredAzureRoles = @(
    @{
        Name = "Automation Contributor"
        Reason = "Create and manage Azure Automation runbooks for MFA monitoring"
        Required = $true
    },
    @{
        Name = "Contributor"
        Reason = "Create and manage Azure resources for automation infrastructure"
        Required = $true
    },
    @{
        Name = "User Access Administrator"
        Reason = "Grant Graph API permissions to managed identity"
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

function New-MFAMonitorDeploymentGroup {
    try {
        Write-Host "Creating Azure AD security group for MFA Compliance Monitor..." -ForegroundColor Yellow
        
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
        $MailNickname = ($GroupName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($GroupName -replace '[^a-zA-Z0-9]', '').Length))
        
        $Group = New-AzADGroup `
            -DisplayName $GroupName `
            -Description $GroupDescription `
            -MailNickname $MailNickname `
            -SecurityEnabled `
            -MailEnabled:$false
        
        Write-Host "✓ Created Azure AD group: $GroupName" -ForegroundColor Green
        Write-Host "  Group ID: $($Group.Id)" -ForegroundColor Gray
        
        # Wait for Azure AD group to propagate
        Write-Host "  Waiting for group to propagate in Azure AD..." -ForegroundColor Yellow
        $MaxWaitTime = 120
        $WaitInterval = 5
        $ElapsedTime = 0
        
        do {
            Start-Sleep -Seconds $WaitInterval
            $ElapsedTime += $WaitInterval
            
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
        
        $ResourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        
        # Verify resource group exists
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $ResourceGroup) {
            Write-Host "Resource group '$ResourceGroupName' does not exist. Creating it..." -ForegroundColor Yellow
            
            if ($WhatIf) {
                Write-Host "[WHATIF] Would create resource group: $ResourceGroupName" -ForegroundColor Yellow
            } else {
                $Location = "East US 2"
                New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag @{
                    "Purpose" = "MFAComplianceMonitor"
                    "ManagedBy" = "AutomationDeployment"
                    "CreatedDate" = (Get-Date -Format "yyyy-MM-dd")
                    "Environment" = "Production"
                }
                Write-Host "✓ Created resource group: $ResourceGroupName" -ForegroundColor Green
            }
        }
        
        # Assign each required Azure RBAC role
        foreach ($Role in $RequiredAzureRoles) {
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
                # Retry role assignment with exponential backoff
                $MaxRetries = 3
                $RetryCount = 0
                $AssignmentSucceeded = $false
                
                do {
                    try {
                        if ($RetryCount -gt 0) {
                            $WaitTime = [math]::Pow(2, $RetryCount) * 5
                            Write-Host "    Retrying in $WaitTime seconds..." -ForegroundColor Gray
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
                            Write-Warning "  Failed to assign role $($Role.Name): $($_.Exception.Message)"
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

function Show-DeploymentInstructions {
    param($Group)
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " MFA MONITOR GROUP CREATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
        return
    }
    
    Write-Host "`n📋 Group Details:" -ForegroundColor Cyan
    Write-Host "  Name: $($Group.DisplayName)" -ForegroundColor White
    Write-Host "  ID: $($Group.Id)" -ForegroundColor White
    Write-Host "  Type: Security Group" -ForegroundColor White
    
    Write-Host "`n🔐 Permissions Configured:" -ForegroundColor Cyan
    
    Write-Host "`n  Azure RBAC (Resource Group):" -ForegroundColor Yellow
    foreach ($Role in $RequiredAzureRoles) {
        Write-Host "    ✓ $($Role.Name)" -ForegroundColor Green
    }
    
    Write-Host "`n  Microsoft Graph (Required):" -ForegroundColor Yellow
    foreach ($Permission in $RequiredGraphPermissions) {
        Write-Host "    • $($Permission.Name) - $($Permission.Reason)" -ForegroundColor White
    }
    
    Write-Host "`n📊 MFA Monitor Capabilities:" -ForegroundColor Cyan
    Write-Host "  This group enables:" -ForegroundColor White
    Write-Host "  ✓ Track MFA registration compliance" -ForegroundColor Green
    Write-Host "  ✓ Identify users without Microsoft Authenticator" -ForegroundColor Green
    Write-Host "  ✓ Send targeted compliance notifications" -ForegroundColor Green
    Write-Host "  ✓ Generate executive compliance reports" -ForegroundColor Green
    Write-Host "  ✓ Monitor authentication method trends" -ForegroundColor Green
    
    Write-Host "`n👥 Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Add service principals to this group:" -ForegroundColor White
    Write-Host "     Add-AzADGroupMember -TargetGroupId '$($Group.Id)' -MemberObjectId '<ServicePrincipalId>'" -ForegroundColor Gray
    Write-Host "  2. Deploy MFA Compliance Monitor using:" -ForegroundColor White
    Write-Host "     .\Azure-Automation\Deploy-MFAComplianceMonitor.ps1" -ForegroundColor Gray
    Write-Host "  3. Grant Graph permissions using:" -ForegroundColor White
    Write-Host "     .\Grant-MFAMonitorPermissions.ps1 -ManagedIdentityObjectId '<ObjectId>'" -ForegroundColor Gray
    Write-Host "  4. Test with conservative settings first" -ForegroundColor White
    
    Write-Host "`n⚠️ Security Considerations:" -ForegroundColor Yellow
    Write-Host "  - Can read all audit logs (sensitive data)" -ForegroundColor Red
    Write-Host "  - Can access user authentication methods" -ForegroundColor White
    Write-Host "  - Can send emails as the organization" -ForegroundColor White
    Write-Host "  - Regular access reviews recommended" -ForegroundColor White
}

# Main execution
try {
    # Step 1: Connect to Azure
    if (-not (Connect-ToAzure)) {
        throw "Failed to connect to Azure"
    }
    
    # Step 2: Create the deployment group
    $Group = New-MFAMonitorDeploymentGroup
    if (-not $Group) {
        throw "Failed to create deployment group"
    }
    
    # Step 3: Assign Azure RBAC permissions
    $PermissionsSet = Set-ResourceGroupPermissions -Group $Group
    if (-not $PermissionsSet -and -not $WhatIf) {
        Write-Warning "Failed to assign some Azure RBAC permissions. Check troubleshooting section."
    }
    
    # Step 4: Show deployment instructions
    Show-DeploymentInstructions -Group $Group
    
    Write-Host "`n🎉 MFA Compliance Monitor deployment group setup completed!" -ForegroundColor Green
    
} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify you have User Administrator or Global Administrator role" -ForegroundColor Gray
    Write-Host "2. Verify you have Owner or User Access Administrator role" -ForegroundColor Gray
    Write-Host "3. Check if the group name conflicts with existing groups" -ForegroundColor Gray
    Write-Host "4. Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
    exit 1
}