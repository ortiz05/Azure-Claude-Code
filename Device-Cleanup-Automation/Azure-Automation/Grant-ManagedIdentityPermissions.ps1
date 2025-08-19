# Grant-ManagedIdentityPermissions.ps1
# Grants required Microsoft Graph permissions to Azure Automation Managed Identity
#
# This script must be run by a Global Administrator or Privileged Role Administrator

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Object ID of the Managed Identity (from Automation Account → Identity)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ManagedIdentityObjectId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Name of the Managed Identity for display")]
    [string]$ManagedIdentityName = "DeviceCleanupAutomation",
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be granted without making changes")]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host @"
=========================================
Grant Microsoft Graph Permissions
to Azure Automation Managed Identity
=========================================
"@ -ForegroundColor Cyan

Write-Host "Managed Identity Object ID: $ManagedIdentityObjectId" -ForegroundColor Yellow
Write-Host "Display Name: $ManagedIdentityName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Required Microsoft Graph permissions for Device Cleanup
$RequiredPermissions = @(
    @{
        Name = "Device.ReadWrite.All"
        Id = "1138cb37-bd11-4084-a2b7-9f71582aeddb"
        Type = "Application"
        Reason = "Read and delete device objects"
    },
    @{
        Name = "User.Read.All"
        Id = "df021288-bdef-4463-88db-98f22de89214"
        Type = "Application"
        Reason = "Read user information for device ownership"
    },
    @{
        Name = "Directory.ReadWrite.All"
        Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
        Type = "Application"
        Reason = "Modify directory objects"
    },
    @{
        Name = "Mail.Send"
        Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96"
        Type = "Application"
        Reason = "Send email notifications"
    }
)

function Connect-ToMicrosoftGraph {
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Write-Host "You need Global Administrator or Privileged Role Administrator role" -ForegroundColor Yellow
        
        # Connect with required scopes
        Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome
        
        $Context = Get-MgContext
        Write-Host "✓ Connected to tenant: $($Context.TenantId)" -ForegroundColor Green
        Write-Host "  Account: $($Context.Account)" -ForegroundColor Gray
        
        return $true
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        return $false
    }
}

function Get-MicrosoftGraphServicePrincipal {
    try {
        Write-Host "Getting Microsoft Graph service principal..." -ForegroundColor Yellow
        
        # Get the Microsoft Graph service principal (this is what we grant permissions FROM)
        $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id,AppRoles
        
        if (-not $GraphServicePrincipal) {
            throw "Microsoft Graph service principal not found"
        }
        
        Write-Host "✓ Found Microsoft Graph service principal" -ForegroundColor Green
        return $GraphServicePrincipal
        
    } catch {
        Write-Error "Failed to get Microsoft Graph service principal: $($_.Exception.Message)"
        throw
    }
}

function Grant-GraphPermissions {
    param(
        [Parameter(Mandatory = $true)]
        $GraphServicePrincipal,
        
        [Parameter(Mandatory = $true)]
        [string]$ManagedIdentityObjectId
    )
    
    try {
        Write-Host "`nGranting Microsoft Graph permissions..." -ForegroundColor Yellow
        
        # Get the managed identity service principal
        $ManagedIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId -ErrorAction SilentlyContinue
        
        if (-not $ManagedIdentity) {
            throw "Managed Identity not found with Object ID: $ManagedIdentityObjectId"
        }
        
        Write-Host "✓ Found Managed Identity: $($ManagedIdentity.DisplayName)" -ForegroundColor Green
        
        # Get current app role assignments
        $CurrentAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId
        
        foreach ($Permission in $RequiredPermissions) {
            Write-Host "`nProcessing permission: $($Permission.Name)" -ForegroundColor Cyan
            Write-Host "  Purpose: $($Permission.Reason)" -ForegroundColor Gray
            
            # Find the app role in Microsoft Graph
            $AppRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $Permission.Name -and $_.AllowedMemberTypes -contains "Application" }
            
            if (-not $AppRole) {
                Write-Warning "  App role not found: $($Permission.Name)"
                continue
            }
            
            # Check if already assigned
            $ExistingAssignment = $CurrentAssignments | Where-Object { $_.AppRoleId -eq $AppRole.Id }
            
            if ($ExistingAssignment) {
                Write-Host "  ✓ Already granted: $($Permission.Name)" -ForegroundColor Green
            } else {
                if ($WhatIf) {
                    Write-Host "  [WHATIF] Would grant: $($Permission.Name)" -ForegroundColor Yellow
                } else {
                    # Grant the permission
                    $Assignment = @{
                        PrincipalId = $ManagedIdentityObjectId
                        ResourceId = $GraphServicePrincipal.Id
                        AppRoleId = $AppRole.Id
                    }
                    
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -BodyParameter $Assignment | Out-Null
                    Write-Host "  ✓ Granted: $($Permission.Name)" -ForegroundColor Green
                }
            }
        }
        
        Write-Host "`n✓ Permission grant process completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to grant permissions: $($_.Exception.Message)"
        throw
    }
}

function Show-PermissionSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManagedIdentityObjectId
    )
    
    try {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host " PERMISSION SUMMARY" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        if ($WhatIf) {
            Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
            Write-Host "`nPermissions that WOULD be granted:" -ForegroundColor Yellow
        } else {
            Write-Host "`nPermissions granted to Managed Identity:" -ForegroundColor Green
        }
        
        foreach ($Permission in $RequiredPermissions) {
            Write-Host "  • $($Permission.Name)" -ForegroundColor White
            Write-Host "    $($Permission.Reason)" -ForegroundColor Gray
        }
        
        Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Wait 5-10 minutes for permissions to propagate" -ForegroundColor White
        Write-Host "2. Test the runbook in Azure Portal:" -ForegroundColor White
        Write-Host "   - Go to Automation Account → Runbooks" -ForegroundColor Gray
        Write-Host "   - Select 'DeviceCleanupAutomation'" -ForegroundColor Gray
        Write-Host "   - Click 'Test pane' and run with WhatIf=true" -ForegroundColor Gray
        Write-Host "3. Monitor the first scheduled execution" -ForegroundColor White
        Write-Host "4. Review execution logs for any issues" -ForegroundColor White
        
        Write-Host "`n⚠️ Important Notes:" -ForegroundColor Yellow
        Write-Host "• Permissions may take up to 10 minutes to become effective" -ForegroundColor White
        Write-Host "• The managed identity can now:" -ForegroundColor White
        Write-Host "  - Delete devices from Azure AD" -ForegroundColor Red
        Write-Host "  - Read all user information" -ForegroundColor White
        Write-Host "  - Send emails on behalf of the organization" -ForegroundColor White
        Write-Host "• Always test with WhatIf=true first!" -ForegroundColor Yellow
        
    } catch {
        Write-Warning "Could not display summary: $($_.Exception.Message)"
    }
}

# Main execution
try {
    # Step 1: Connect to Microsoft Graph
    if (-not (Connect-ToMicrosoftGraph)) {
        throw "Failed to connect to Microsoft Graph"
    }
    
    # Step 2: Get Microsoft Graph service principal
    $GraphServicePrincipal = Get-MicrosoftGraphServicePrincipal
    
    # Step 3: Grant permissions
    Grant-GraphPermissions -GraphServicePrincipal $GraphServicePrincipal -ManagedIdentityObjectId $ManagedIdentityObjectId
    
    # Step 4: Show summary
    Show-PermissionSummary -ManagedIdentityObjectId $ManagedIdentityObjectId
    
    Write-Host "`n🎉 Permission grant completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Permission grant failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Global Administrator or Privileged Role Administrator role" -ForegroundColor Gray
    Write-Host "2. Verify the Managed Identity Object ID is correct" -ForegroundColor Gray
    Write-Host "3. Check that the Automation Account exists and has a managed identity" -ForegroundColor Gray
    Write-Host "4. Try disconnecting and reconnecting to Microsoft Graph" -ForegroundColor Gray
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}