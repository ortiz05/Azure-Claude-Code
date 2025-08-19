# Grant-ManagedIdentityPermissions-Enhanced.ps1
# Enhanced version with better account type detection and error handling
# Grants required Microsoft Graph permissions to Azure Automation Managed Identity
#
# This script must be run by a Global Administrator or Privileged Role Administrator
# using an ORGANIZATIONAL account (not personal/MSA account)
#
# Usage Examples:
# Default authentication:
#   .\Grant-ManagedIdentityPermissions-Enhanced.ps1 -ManagedIdentityObjectId "guid"
#
# Specify tenant (required):
#   .\Grant-ManagedIdentityPermissions-Enhanced.ps1 -ManagedIdentityObjectId "guid" -TenantId "tenant-guid"
#
# Custom enterprise app registration:
#   .\Grant-ManagedIdentityPermissions-Enhanced.ps1 -ManagedIdentityObjectId "guid" -ApplicationId "app-guid" -TenantId "tenant-guid"

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Object ID of the Managed Identity (from Automation Account → Identity)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ManagedIdentityObjectId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Name of the Managed Identity for display")]
    [string]$ManagedIdentityName = "DeviceCleanupAutomation",
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD Tenant ID (REQUIRED to avoid authentication issues)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Custom Application ID for Microsoft Graph authentication (if using enterprise app registration)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ApplicationId,
    
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
    
    # Check required Microsoft Graph modules
    $RequiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')
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
Missing required Microsoft Graph PowerShell modules: $($MissingModules -join ', ')
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
Grant Microsoft Graph Permissions
to Azure Automation Managed Identity
=========================================
"@ -ForegroundColor Cyan

Write-Host "Managed Identity Object ID: $ManagedIdentityObjectId" -ForegroundColor Yellow
Write-Host "Display Name: $ManagedIdentityName" -ForegroundColor Yellow
if ($TenantId) {
    Write-Host "Target Tenant ID: $TenantId" -ForegroundColor Yellow
}
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
        Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
        
        # IMPORTANT: Warn about account requirements
        Write-Host @"

⚠️ IMPORTANT: Account Requirements
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
You MUST use an ORGANIZATIONAL account with:
  • Azure AD/Microsoft Entra ID work/school account
  • Global Administrator or Privileged Role Administrator role
  
❌ Personal Microsoft Accounts (MSA) are NOT supported:
  • @outlook.com, @hotmail.com, @live.com accounts will fail
  • Guest accounts may have limited permissions

✅ Valid account examples:
  • admin@yourcompany.onmicrosoft.com
  • globaladmin@yourcompany.com (federated domain)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@ -ForegroundColor Yellow
        
        # Build connection parameters
        $ConnectParams = @{
            Scopes = @("Application.Read.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All")
            NoWelcome = $true
        }
        
        # Add tenant ID if provided (STRONGLY RECOMMENDED)
        if ($TenantId) {
            Write-Host "Connecting to specific tenant: $TenantId" -ForegroundColor Gray
            $ConnectParams['TenantId'] = $TenantId
        } else {
            Write-Warning @"
No TenantId specified. The script will use your default tenant.
If you have access to multiple tenants, specify -TenantId to avoid confusion.
"@
        }
        
        # Add application ID if provided
        if ($ApplicationId) {
            Write-Host "Using custom Application ID: $ApplicationId" -ForegroundColor Gray
            $ConnectParams['ClientId'] = $ApplicationId
        }
        
        # Connect to Microsoft Graph
        Connect-MgGraph @ConnectParams
        
        # Validate connection and account type
        $Context = Get-MgContext
        if (-not $Context) {
            throw "Failed to establish Microsoft Graph context"
        }
        
        Write-Host "✓ Connected successfully" -ForegroundColor Green
        Write-Host "  Tenant: $($Context.TenantId)" -ForegroundColor Gray
        Write-Host "  Account: $($Context.Account)" -ForegroundColor Gray
        Write-Host "  Account Type: $($Context.AccountType)" -ForegroundColor Gray
        
        # Check if this looks like a personal account
        if ($Context.Account -match '@(outlook|hotmail|live|msn)\.(com|net|org)') {
            throw @"
PERSONAL MICROSOFT ACCOUNT DETECTED!

You are signed in with a personal Microsoft account: $($Context.Account)
This script requires an organizational (work/school) account.

Please sign out and sign in with an organizational account that has
Global Administrator or Privileged Role Administrator permissions.
"@
        }
        
        # Additional check for account type
        if ($Context.AccountType -eq 'Consumer' -or $Context.AccountType -eq 'PersonalMicrosoftAccount') {
            throw @"
PERSONAL ACCOUNT TYPE DETECTED!

Account type '$($Context.AccountType)' is not supported.
This script requires an organizational Azure AD account.

Please use an account from your Azure AD tenant.
"@
        }
        
        return $true
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        
        # Provide specific guidance for common errors
        if ($_.Exception.Message -match "AADSTS50020") {
            Write-Host @"

📋 Guest Account Issue Detected
────────────────────────────────────────
The account appears to be a guest in the target tenant.
Guest accounts typically don't have sufficient permissions.

Solution: Use a native account in the target tenant with
Global Administrator or Privileged Role Administrator role.
"@ -ForegroundColor Yellow
        }
        elseif ($_.Exception.Message -match "AADSTS90072") {
            Write-Host @"

📋 Account Domain Issue Detected
────────────────────────────────────────
The account domain is not recognized in this tenant.

Solution: Ensure you're using an account that belongs to
the Azure AD tenant where the Automation Account exists.
"@ -ForegroundColor Yellow
        }
        
        return $false
    }
}

function Test-AccountPermissions {
    try {
        Write-Host "`nValidating account permissions..." -ForegroundColor Yellow
        
        # Try to list service principals as a permission test
        $TestQuery = Get-MgServicePrincipal -Top 1 -ErrorAction Stop
        
        if ($TestQuery) {
            Write-Host "✓ Account has basic directory read permissions" -ForegroundColor Green
            return $true
        }
        
        throw "Unable to verify permissions"
        
    } catch {
        Write-Error @"
Permission validation failed!

This could mean:
1. The account doesn't have sufficient permissions
2. You're using a personal Microsoft account (MSA)
3. Admin consent has not been granted for the required permissions

Error details: $($_.Exception.Message)
"@
        return $false
    }
}

function Get-MicrosoftGraphServicePrincipal {
    try {
        Write-Host "`nGetting Microsoft Graph service principal..." -ForegroundColor Yellow
        
        # This is the step that fails with MSA accounts
        $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id,AppRoles -ErrorAction Stop
        
        if (-not $GraphServicePrincipal) {
            throw "Microsoft Graph service principal not found in tenant"
        }
        
        Write-Host "✓ Found Microsoft Graph service principal" -ForegroundColor Green
        return $GraphServicePrincipal
        
    } catch {
        # Enhanced error handling for MSA account issues
        if ($_.Exception.Message -match "MSA accounts" -or $_.Exception.Message -match "not supported for MSA") {
            Write-Error @"
═══════════════════════════════════════════════════════════════
❌ PERSONAL MICROSOFT ACCOUNT (MSA) DETECTED
═══════════════════════════════════════════════════════════════

The Microsoft Graph API returned an error indicating you're using
a personal Microsoft account (like @outlook.com, @hotmail.com).

This script REQUIRES an organizational Azure AD account.

📋 SOLUTION:
────────────────────────────────────────
1. Sign out of your current session:
   Disconnect-MgGraph

2. Sign in with an organizational account:
   • Must be from your Azure AD tenant
   • Must have Global Administrator role
   • Example: admin@yourcompany.onmicrosoft.com

3. Re-run this script with the -TenantId parameter:
   .\Grant-ManagedIdentityPermissions-Enhanced.ps1 ``
       -ManagedIdentityObjectId "$ManagedIdentityObjectId" ``
       -TenantId "your-tenant-id"

📌 To find your Tenant ID:
   1. Go to portal.azure.com
   2. Navigate to Azure Active Directory
   3. Copy the Tenant ID from the Overview page

═══════════════════════════════════════════════════════════════
"@
        } else {
            Write-Error "Failed to get Microsoft Graph service principal: $($_.Exception.Message)"
        }
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
            throw @"
Managed Identity not found with Object ID: $ManagedIdentityObjectId

Please verify:
1. The Object ID is correct (check Azure Portal → Automation Account → Identity)
2. The Managed Identity exists in this tenant
3. You're connected to the correct tenant
"@
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
    
    # Step 2: Test account permissions
    if (-not (Test-AccountPermissions)) {
        throw "Account permission validation failed"
    }
    
    # Step 3: Get Microsoft Graph service principal
    $GraphServicePrincipal = Get-MicrosoftGraphServicePrincipal
    
    # Step 4: Grant permissions
    Grant-GraphPermissions -GraphServicePrincipal $GraphServicePrincipal -ManagedIdentityObjectId $ManagedIdentityObjectId
    
    # Step 5: Show summary
    Show-PermissionSummary -ManagedIdentityObjectId $ManagedIdentityObjectId
    
    Write-Host "`n🎉 Permission grant completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Permission grant failed: $($_.Exception.Message)"
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
    Write-Host " TROUBLESHOOTING GUIDE" -ForegroundColor Red
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
    
    Write-Host @"

1. ACCOUNT TYPE ISSUES:
   ✓ Use an organizational account (not personal)
   ✓ Account must be from your Azure AD tenant
   ✓ Example: admin@yourcompany.onmicrosoft.com
   
2. PERMISSION ISSUES:
   ✓ Account needs Global Administrator role
   ✓ Or Privileged Role Administrator role
   ✓ Check in Azure Portal → Azure AD → Roles
   
3. TENANT ISSUES:
   ✓ Specify -TenantId parameter explicitly
   ✓ Ensure you're in the correct tenant
   ✓ Find Tenant ID in Azure Portal → Azure AD
   
4. MANAGED IDENTITY ISSUES:
   ✓ Verify the Object ID is correct
   ✓ Check Azure Portal → Automation Account → Identity
   ✓ Ensure managed identity is enabled
   
5. IF STILL FAILING:
   a. Run: Disconnect-MgGraph
   b. Clear browser cache/cookies
   c. Sign in with organizational admin account
   d. Re-run with -TenantId parameter

"@ -ForegroundColor Yellow
    
    exit 1
} finally {
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Gray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}