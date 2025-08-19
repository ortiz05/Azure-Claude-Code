# Get-TenantInfo.ps1
# Helper script to retrieve Azure AD Tenant ID and organization information
# This addresses the Microsoft authentication bug that requires explicit tenant specification
#
# Usage:
#   ./Get-TenantInfo.ps1
#   ./Get-TenantInfo.ps1 -ShowAllTenants

param(
    [Parameter(Mandatory = $false)]
    [switch]$ShowAllTenants
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Azure Tenant Information Retrieval Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if connected to Azure
Write-Host "Checking Azure connection..." -ForegroundColor Yellow
$context = Get-AzContext -ErrorAction SilentlyContinue

if (-not $context) {
    Write-Host "Not connected to Azure. Connecting now..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        Connect-AzAccount -ErrorAction Stop
        $context = Get-AzContext
    }
    catch {
        Write-Host "Failed to connect to Azure: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Alternative method to find your Tenant ID:" -ForegroundColor Yellow
        Write-Host "1. Go to https://portal.azure.com" -ForegroundColor Gray
        Write-Host "2. Navigate to Azure Active Directory" -ForegroundColor Gray
        Write-Host "3. Look for 'Tenant ID' in the Overview page" -ForegroundColor Gray
        Write-Host "4. Copy the GUID value (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)" -ForegroundColor Gray
        exit 1
    }
}

Write-Host "Connected to Azure" -ForegroundColor Green
Write-Host ""

# Display current tenant information
Write-Host "Current Tenant Information:" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Tenant ID:        $($context.Tenant.Id)" -ForegroundColor White
Write-Host "Tenant Name:      $($context.Tenant.Name)" -ForegroundColor White
Write-Host "Account:          $($context.Account.Id)" -ForegroundColor White
Write-Host "Account Type:     $($context.Account.Type)" -ForegroundColor White
Write-Host "Subscription:     $($context.Subscription.Name)" -ForegroundColor White
Write-Host "Subscription ID:  $($context.Subscription.Id)" -ForegroundColor White
Write-Host ""

# Check if it's a Microsoft Account
if ($context.Account.Id -match '@(outlook|hotmail|live|msn)\.com$') {
    Write-Host "WARNING: You appear to be using a personal Microsoft Account (MSA)" -ForegroundColor Red
    Write-Host "  Many Azure automation scripts require an organizational account" -ForegroundColor Yellow
    Write-Host "  Consider using a work or school account instead" -ForegroundColor Yellow
    Write-Host ""
}

# Check for multi-tenant access
if ($ShowAllTenants) {
    Write-Host "Checking for additional tenant access..." -ForegroundColor Yellow
    
    try {
        $tenants = Get-AzTenant
        
        if ($tenants.Count -gt 1) {
            Write-Host ""
            Write-Host "You have access to multiple tenants:" -ForegroundColor Cyan
            Write-Host "==========================================" -ForegroundColor Cyan
            
            foreach ($tenant in $tenants) {
                $isCurrent = $tenant.Id -eq $context.Tenant.Id
                $marker = if ($isCurrent) { "-> " } else { "  " }
                $color = if ($isCurrent) { "Green" } else { "White" }
                
                Write-Host "$marker Tenant: $($tenant.Name)" -ForegroundColor $color
                Write-Host "  ID: $($tenant.Id)" -ForegroundColor Gray
                
                if ($tenant.Domains) {
                    Write-Host "  Primary Domain: $($tenant.Domains[0])" -ForegroundColor Gray
                }
                Write-Host ""
            }
            
            Write-Host "To switch tenants, use:" -ForegroundColor Yellow
            Write-Host "  Set-AzContext -TenantId 'tenant-id-here'" -ForegroundColor Gray
            Write-Host ""
        }
    }
    catch {
        Write-Host "Unable to retrieve tenant list: $_" -ForegroundColor Yellow
    }
}

# Export information for use in scripts
Write-Host "Using Tenant ID in Scripts:" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "PowerShell parameter:" -ForegroundColor Yellow
Write-Host "  -TenantId '$($context.Tenant.Id)'" -ForegroundColor Gray
Write-Host ""
Write-Host "Environment variable (for testing):" -ForegroundColor Yellow
Write-Host "  `$env:AZURE_TENANT_ID = '$($context.Tenant.Id)'" -ForegroundColor Gray
Write-Host ""
Write-Host "Example script usage:" -ForegroundColor Yellow
Write-Host "  .\Grant-ManagedIdentityPermissions-Fixed.ps1 ``" -ForegroundColor Gray
Write-Host "    -AutomationAccountName 'MyAutomation' ``" -ForegroundColor Gray
Write-Host "    -ResourceGroupName 'MyResourceGroup' ``" -ForegroundColor Gray
Write-Host "    -TenantId '$($context.Tenant.Id)'" -ForegroundColor Gray
Write-Host ""

# Save to clipboard if possible
if ($IsWindows) {
    try {
        $context.Tenant.Id | Set-Clipboard
        Write-Host "Tenant ID copied to clipboard!" -ForegroundColor Green
    }
    catch {
        # Clipboard not available
    }
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Save this Tenant ID for future use!" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan