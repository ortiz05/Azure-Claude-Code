# Grant-MFAMonitorPermissions.ps1
# Grants required Microsoft Graph permissions to MFA Compliance Monitor Managed Identity
#
# Required Permissions:
# - AuditLog.Read.All: Read audit logs for authentication methods
# - User.Read.All: Read user information  
# - Directory.Read.All: Read directory objects
# - Mail.Send: Send compliance notifications

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Object ID of the Managed Identity (from Automation Account → Identity)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ManagedIdentityObjectId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Name of the Managed Identity for display")]
    [string]$ManagedIdentityName = "MFAComplianceMonitor",
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be granted without making changes")]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host @"
=========================================
Grant MFA Compliance Monitor Permissions
Microsoft Graph API Access Configuration
=========================================
"@ -ForegroundColor Cyan

Write-Host "Managed Identity Object ID: $ManagedIdentityObjectId" -ForegroundColor Yellow
Write-Host "Display Name: $ManagedIdentityName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Required Microsoft Graph permissions for MFA Compliance Monitor
$RequiredPermissions = @(
    @{
        Name = "AuditLog.Read.All"
        Id = "b0afded3-3588-46d8-8b3d-9842eff778da"
        Type = "Application"
        Reason = "Read audit logs for authentication method registration and usage"
        Critical = $true
    },
    @{
        Name = "User.Read.All"
        Id = "df021288-bdef-4463-88db-98f22de89214"
        Type = "Application"
        Reason = "Read user profiles and authentication methods"
        Critical = $true
    },
    @{
        Name = "Directory.Read.All"
        Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        Type = "Application"
        Reason = "Read directory objects and group memberships"
        Critical = $true
    },
    @{
        Name = "Mail.Send"
        Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96"
        Type = "Application"
        Reason = "Send compliance notification emails to users and administrators"
        Critical = $true
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
        
        # Get the Microsoft Graph service principal
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

function Grant-MFAMonitorPermissions {
    param(
        [Parameter(Mandatory = $true)]
        $GraphServicePrincipal,
        
        [Parameter(Mandatory = $true)]
        [string]$ManagedIdentityObjectId
    )
    
    try {
        Write-Host "`nGranting MFA Compliance Monitor permissions..." -ForegroundColor Yellow
        
        # Get the managed identity service principal
        $ManagedIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId -ErrorAction SilentlyContinue
        
        if (-not $ManagedIdentity) {
            throw "Managed Identity not found with Object ID: $ManagedIdentityObjectId"
        }
        
        Write-Host "✓ Found Managed Identity: $($ManagedIdentity.DisplayName)" -ForegroundColor Green
        
        # Get current app role assignments
        $CurrentAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId
        
        $GrantedPermissions = @()
        $FailedPermissions = @()
        
        foreach ($Permission in $RequiredPermissions) {
            Write-Host "`nProcessing permission: $($Permission.Name)" -ForegroundColor Cyan
            Write-Host "  Purpose: $($Permission.Reason)" -ForegroundColor Gray
            Write-Host "  Critical: $($Permission.Critical)" -ForegroundColor Gray
            
            # Find the app role in Microsoft Graph
            $AppRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $Permission.Name -and $_.AllowedMemberTypes -contains "Application" }
            
            if (-not $AppRole) {
                Write-Warning "  App role not found: $($Permission.Name)"
                $FailedPermissions += $Permission.Name
                continue
            }
            
            # Check if already assigned
            $ExistingAssignment = $CurrentAssignments | Where-Object { $_.AppRoleId -eq $AppRole.Id }
            
            if ($ExistingAssignment) {
                Write-Host "  ✓ Already granted: $($Permission.Name)" -ForegroundColor Green
                $GrantedPermissions += $Permission.Name
            } else {
                if ($WhatIf) {
                    Write-Host "  [WHATIF] Would grant: $($Permission.Name)" -ForegroundColor Yellow
                    $GrantedPermissions += $Permission.Name
                } else {
                    try {
                        # Grant the permission
                        $Assignment = @{
                            PrincipalId = $ManagedIdentityObjectId
                            ResourceId = $GraphServicePrincipal.Id
                            AppRoleId = $AppRole.Id
                        }
                        
                        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -BodyParameter $Assignment | Out-Null
                        Write-Host "  ✓ Granted: $($Permission.Name)" -ForegroundColor Green
                        $GrantedPermissions += $Permission.Name
                    } catch {
                        Write-Error "  Failed to grant $($Permission.Name): $($_.Exception.Message)"
                        $FailedPermissions += $Permission.Name
                    }
                }
            }
        }
        
        # Summary
        Write-Host "`n=========================================" -ForegroundColor Cyan
        Write-Host " PERMISSION GRANT SUMMARY" -ForegroundColor Cyan
        Write-Host "=========================================" -ForegroundColor Cyan
        
        if ($GrantedPermissions.Count -gt 0) {
            Write-Host "`n✓ Permissions Granted/Verified:" -ForegroundColor Green
            foreach ($perm in $GrantedPermissions) {
                Write-Host "  • $perm" -ForegroundColor White
            }
        }
        
        if ($FailedPermissions.Count -gt 0) {
            Write-Host "`n✗ Failed Permissions:" -ForegroundColor Red
            foreach ($perm in $FailedPermissions) {
                Write-Host "  • $perm" -ForegroundColor Red
            }
            Write-Warning "Some permissions could not be granted. The automation may not function correctly."
        }
        
        return ($FailedPermissions.Count -eq 0)
        
    } catch {
        Write-Error "Failed to grant permissions: $($_.Exception.Message)"
        throw
    }
}

function Show-PostGrantInstructions {
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " POST-GRANT INSTRUCTIONS" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Wait 5-10 minutes for permissions to propagate" -ForegroundColor White
    Write-Host "2. Test the runbook in Azure Portal:" -ForegroundColor White
    Write-Host "   - Go to Automation Account → Runbooks" -ForegroundColor Gray
    Write-Host "   - Select 'MFAComplianceMonitor'" -ForegroundColor Gray
    Write-Host "   - Click 'Test pane'" -ForegroundColor Gray
    Write-Host "   - Set parameters:" -ForegroundColor Gray
    Write-Host "     • WhatIf = true (for safe testing)" -ForegroundColor Gray
    Write-Host "     • DaysToCheck = 7" -ForegroundColor Gray
    Write-Host "   - Click 'Start' and monitor output" -ForegroundColor Gray
    
    Write-Host "`n🔍 MFA Monitor Capabilities:" -ForegroundColor Cyan
    Write-Host "With these permissions, the automation can:" -ForegroundColor White
    Write-Host "  ✓ Read authentication method registrations" -ForegroundColor Green
    Write-Host "  ✓ Analyze MFA compliance across the organization" -ForegroundColor Green
    Write-Host "  ✓ Identify users without Microsoft Authenticator" -ForegroundColor Green
    Write-Host "  ✓ Send targeted compliance notifications" -ForegroundColor Green
    Write-Host "  ✓ Generate compliance reports for management" -ForegroundColor Green
    
    Write-Host "`n⚠️ Security Considerations:" -ForegroundColor Yellow
    Write-Host "• The managed identity can read sensitive audit logs" -ForegroundColor White
    Write-Host "• It can access all user authentication methods" -ForegroundColor White
    Write-Host "• Email notifications will come from the organization" -ForegroundColor White
    Write-Host "• Regular access reviews are recommended" -ForegroundColor White
    
    Write-Host "`n📊 Monitoring:" -ForegroundColor Cyan
    Write-Host "• Check execution history in Automation Account → Jobs" -ForegroundColor White
    Write-Host "• Review email delivery in Exchange Message Trace" -ForegroundColor White
    Write-Host "• Monitor for failed executions and permission errors" -ForegroundColor White
    Write-Host "• Set up alerts for automation failures" -ForegroundColor White
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
    $Success = Grant-MFAMonitorPermissions -GraphServicePrincipal $GraphServicePrincipal -ManagedIdentityObjectId $ManagedIdentityObjectId
    
    if ($Success) {
        # Step 4: Show instructions
        Show-PostGrantInstructions
        
        Write-Host "`n🎉 MFA Compliance Monitor permissions granted successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Permission grant completed with errors. Please review and retry if needed."
    }
    
} catch {
    Write-Error "Permission grant failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Global Administrator or Privileged Role Administrator role" -ForegroundColor Gray
    Write-Host "2. Verify the Managed Identity Object ID is correct" -ForegroundColor Gray
    Write-Host "3. Check that the Automation Account exists and has a managed identity" -ForegroundColor Gray
    Write-Host "4. Ensure Microsoft.Graph modules are installed" -ForegroundColor Gray
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}