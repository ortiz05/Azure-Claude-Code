<#
.SYNOPSIS
    Grant Microsoft Graph permissions to Device Cleanup Automation Managed Identity - Fixed for MSA Issues
.DESCRIPTION
    This script grants necessary Graph API permissions to the managed identity with enhanced error handling
    for Microsoft Account (MSA) scenarios and alternative authentication methods.
.PARAMETER AutomationAccountName
    Name of the Azure Automation Account
.PARAMETER ResourceGroupName
    Name of the Resource Group containing the Automation Account
.PARAMETER SubscriptionId
    Azure Subscription ID (optional, will use current context if not provided)
.PARAMETER UseAlternativeAuth
    Use alternative authentication method for MSA accounts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseAlternativeAuth
)

# Enhanced error handling
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Color output functions
function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# Check for required modules
function Test-RequiredModules {
    $requiredModules = @(
        @{Name = 'Az.Accounts'; MinVersion = '2.0.0'},
        @{Name = 'Az.Automation'; MinVersion = '1.0.0'},
        @{Name = 'Microsoft.Graph.Authentication'; MinVersion = '2.0.0'},
        @{Name = 'Microsoft.Graph.Applications'; MinVersion = '2.0.0'}
    )
    
    Write-Info "Checking required PowerShell modules..."
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $module.Name | 
                     Where-Object { $_.Version -ge $module.MinVersion }
        
        if (-not $installed) {
            $missingModules += $module.Name
            Write-Warning "Module $($module.Name) (minimum version $($module.MinVersion)) is not installed"
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Error "Missing required modules. Install them using:"
        $missingModules | ForEach-Object {
            Write-Host "  Install-Module -Name $_ -Scope CurrentUser -Force" -ForegroundColor Yellow
        }
        return $false
    }
    
    Write-Success "All required modules are installed"
    return $true
}

# Test Azure connection with better error handling
function Test-AzureConnection {
    try {
        Write-Info "Testing Azure connection..."
        $context = Get-AzContext
        
        if (-not $context) {
            Write-Warning "Not connected to Azure. Attempting to connect..."
            
            # Try interactive login first
            try {
                Connect-AzAccount -ErrorAction Stop
                $context = Get-AzContext
            }
            catch {
                Write-Error "Failed to connect to Azure: $_"
                Write-Info "Please ensure you're using an organizational account (not personal MSA)"
                return $null
            }
        }
        
        # Check account type
        $accountType = $context.Account.Type
        Write-Info "Connected as: $($context.Account.Id)"
        Write-Info "Account Type: $accountType"
        Write-Info "Tenant: $($context.Tenant.Id)"
        
        if ($context.Account.Id -match '@(outlook|hotmail|live)\.com$') {
            Write-Warning "You appear to be using a personal Microsoft Account (MSA)."
            Write-Warning "This script requires an organizational Azure AD account."
            Write-Info "Please sign in with your work or school account (e.g., admin@company.onmicrosoft.com)"
            
            # Offer to reconnect
            $reconnect = Read-Host "Would you like to sign out and reconnect with a different account? (Y/N)"
            if ($reconnect -eq 'Y') {
                Disconnect-AzAccount
                Connect-AzAccount -TenantId $context.Tenant.Id
                $context = Get-AzContext
            }
        }
        
        return $context
    }
    catch {
        Write-Error "Error checking Azure connection: $_"
        return $null
    }
}

# Alternative method using Azure CLI for MSA scenarios
function Grant-PermissionsViaCLI {
    param(
        [string]$ManagedIdentityId,
        [string]$TenantId
    )
    
    Write-Info "Attempting alternative method using Azure CLI..."
    
    # Check if Azure CLI is installed
    $azCliPath = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCliPath) {
        Write-Error "Azure CLI is not installed. Install from: https://aka.ms/installazurecli"
        return $false
    }
    
    try {
        # Login to Azure CLI
        Write-Info "Logging into Azure CLI..."
        az login --tenant $TenantId
        
        # Get Microsoft Graph service principal
        Write-Info "Getting Microsoft Graph service principal..."
        $graphSpJson = az ad sp list --filter "displayName eq 'Microsoft Graph'" --query "[0]" -o json
        $graphSp = $graphSpJson | ConvertFrom-Json
        
        if (-not $graphSp) {
            Write-Error "Could not find Microsoft Graph service principal"
            return $false
        }
        
        $graphSpId = $graphSp.id
        Write-Success "Found Microsoft Graph service principal: $graphSpId"
        
        # Required permissions
        $permissions = @(
            @{Name = "Device.Read.All"; Type = "Application"},
            @{Name = "Device.ReadWrite.All"; Type = "Application"},
            @{Name = "Directory.Read.All"; Type = "Application"},
            @{Name = "AuditLog.Read.All"; Type = "Application"}
        )
        
        foreach ($permission in $permissions) {
            Write-Info "Granting permission: $($permission.Name)"
            
            # Get permission ID
            $permissionJson = az ad sp show --id $graphSpId --query "appRoles[?value=='$($permission.Name)'].id" -o json
            $permissionId = ($permissionJson | ConvertFrom-Json)[0]
            
            if ($permissionId) {
                # Grant the permission
                az ad app permission add --id $ManagedIdentityId --api $graphSpId --api-permissions "${permissionId}=Role"
                Write-Success "Granted $($permission.Name)"
            }
            else {
                Write-Warning "Could not find permission: $($permission.Name)"
            }
        }
        
        # Grant admin consent
        Write-Info "Granting admin consent..."
        az ad app permission admin-consent --id $ManagedIdentityId
        
        Write-Success "Permissions granted successfully via Azure CLI"
        return $true
    }
    catch {
        Write-Error "Failed to grant permissions via Azure CLI: $_"
        return $false
    }
}

# Main execution
try {
    Write-Info "========================================="
    Write-Info "Device Cleanup Automation Permission Setup"
    Write-Info "========================================="
    
    # Check modules
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not installed"
    }
    
    # Test Azure connection
    $azContext = Test-AzureConnection
    if (-not $azContext) {
        throw "Failed to establish Azure connection"
    }
    
    # Set subscription if provided
    if ($SubscriptionId) {
        Write-Info "Setting subscription to: $SubscriptionId"
        Set-AzContext -SubscriptionId $SubscriptionId
    }
    
    # Get the Automation Account
    Write-Info "Getting Automation Account: $AutomationAccountName"
    $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
    
    if (-not $automationAccount) {
        throw "Automation Account '$AutomationAccountName' not found in Resource Group '$ResourceGroupName'"
    }
    
    Write-Success "Found Automation Account"
    
    # Get the managed identity
    $managedIdentity = $automationAccount.Identity
    if (-not $managedIdentity -or $managedIdentity.Type -ne 'SystemAssigned') {
        throw "System-assigned managed identity is not enabled for this Automation Account"
    }
    
    $principalId = $managedIdentity.PrincipalId
    Write-Success "Found Managed Identity: $principalId"
    
    # Try to connect to Microsoft Graph
    try {
        Write-Info "Connecting to Microsoft Graph..."
        
        # Use device code authentication for better compatibility
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -TenantId $azContext.Tenant.Id -NoWelcome
        
        Write-Success "Connected to Microsoft Graph"
        
        # Get Microsoft Graph service principal
        Write-Info "Getting Microsoft Graph service principal..."
        $graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
        
        if (-not $graphServicePrincipal) {
            throw "Microsoft Graph service principal not found"
        }
        
        Write-Success "Found Microsoft Graph service principal"
        
        # Define required permissions
        $requiredPermissions = @(
            @{Name = "Device.Read.All"; Id = "7438b122-aefc-4978-80ed-43db9fcc7715"},
            @{Name = "Device.ReadWrite.All"; Id = "1138cb37-1270-4bdb-af3d-d647e7c1e0f3"},
            @{Name = "Directory.Read.All"; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"},
            @{Name = "AuditLog.Read.All"; Id = "b0afded3-3588-46d8-8b3d-9842eff778da"}
        )
        
        # Get the managed identity service principal
        Write-Info "Getting managed identity service principal..."
        $managedIdentitySp = Get-MgServicePrincipal -Filter "id eq '$principalId'"
        
        if (-not $managedIdentitySp) {
            throw "Managed identity service principal not found"
        }
        
        # Grant permissions
        foreach ($permission in $requiredPermissions) {
            Write-Info "Granting permission: $($permission.Name)"
            
            $appRole = $graphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $permission.Name }
            
            if ($appRole) {
                $roleAssignment = @{
                    PrincipalId = $principalId
                    ResourceId = $graphServicePrincipal.Id
                    AppRoleId = $appRole.Id
                }
                
                try {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -BodyParameter $roleAssignment -ErrorAction Stop
                    Write-Success "Granted: $($permission.Name)"
                }
                catch {
                    if ($_.Exception.Message -match "Permission being assigned already exists") {
                        Write-Info "Permission already granted: $($permission.Name)"
                    }
                    else {
                        Write-Warning "Failed to grant $($permission.Name): $_"
                    }
                }
            }
            else {
                Write-Warning "Permission not found: $($permission.Name)"
            }
        }
        
        Write-Success "✅ All permissions have been processed successfully!"
        
    }
    catch {
        Write-Error "Failed to use Microsoft Graph: $_"
        
        if ($_.Exception.Message -match "MSA accounts" -or $UseAlternativeAuth) {
            Write-Info "Attempting alternative authentication method..."
            
            # Try Azure CLI method
            $success = Grant-PermissionsViaCLI -ManagedIdentityId $principalId -TenantId $azContext.Tenant.Id
            
            if (-not $success) {
                Write-Error "Alternative method also failed"
                Write-Info ""
                Write-Info "📋 Manual Steps Required:"
                Write-Info "1. Sign in to Azure Portal with an organizational admin account"
                Write-Info "2. Navigate to Azure Active Directory > App registrations"
                Write-Info "3. Search for your managed identity by ID: $principalId"
                Write-Info "4. Go to API permissions"
                Write-Info "5. Add the following Microsoft Graph Application permissions:"
                Write-Info "   - Device.Read.All"
                Write-Info "   - Device.ReadWrite.All"
                Write-Info "   - Directory.Read.All"
                Write-Info "   - AuditLog.Read.All"
                Write-Info "6. Click 'Grant admin consent'"
            }
        }
        else {
            throw
        }
    }
    finally {
        # Disconnect from Microsoft Graph
        if (Get-MgContext) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }
    
    Write-Info ""
    Write-Success "========================================="
    Write-Success "Setup Complete!"
    Write-Success "========================================="
    Write-Info "The managed identity now has the necessary permissions."
    Write-Info "You can now run the Device Cleanup runbooks in your Automation Account."
    
}
catch {
    Write-Error "Script failed: $_"
    Write-Info ""
    Write-Info "Troubleshooting Tips:"
    Write-Info "1. Ensure you're signed in with an organizational account (not personal MSA)"
    Write-Info "2. Verify you have Global Administrator or Privileged Role Administrator role"
    Write-Info "3. Check that the Automation Account has system-assigned managed identity enabled"
    Write-Info "4. Try running with -UseAlternativeAuth switch for Azure CLI method"
    exit 1
}