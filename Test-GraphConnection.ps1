<#
.SYNOPSIS
    Test Microsoft Graph connection and account type
.DESCRIPTION
    Quick diagnostic script to identify MSA vs organizational account issues
.PARAMETER TenantId
    Azure AD Tenant ID (optional but recommended to avoid authentication issues)
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Microsoft Graph Connection Diagnostic" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Prompt for Tenant ID if not provided
if (-not $TenantId) {
    Write-Host "⚠ Tenant ID not provided. This may cause authentication issues." -ForegroundColor Yellow
    Write-Host "  To find your Tenant ID:" -ForegroundColor Gray
    Write-Host "  1. Go to Azure Portal > Azure Active Directory" -ForegroundColor Gray
    Write-Host "  2. Look for 'Tenant ID' in the Overview page" -ForegroundColor Gray
    Write-Host ""
    $inputTenantId = Read-Host "Enter your Tenant ID (or press Enter to continue without it)"
    if ($inputTenantId) {
        $TenantId = $inputTenantId
    }
}

if ($TenantId) {
    # Validate Tenant ID format
    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        Write-Host "✗ Invalid Tenant ID format. Expected format: 12345678-1234-1234-1234-123456789012" -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Using Tenant ID: $TenantId" -ForegroundColor Green
    Write-Host ""
}

# Check Azure connection
Write-Host "1. Checking Azure connection..." -ForegroundColor Yellow
try {
    $context = Get-AzContext
    if ($context) {
        Write-Host "✓ Connected to Azure" -ForegroundColor Green
        Write-Host "  Account: $($context.Account.Id)" -ForegroundColor Gray
        Write-Host "  Type: $($context.Account.Type)" -ForegroundColor Gray
        Write-Host "  Tenant: $($context.Tenant.Id)" -ForegroundColor Gray
        
        # Check if it's an MSA
        if ($context.Account.Id -match '@(outlook|hotmail|live|msn)\.com$') {
            Write-Host "⚠ WARNING: This appears to be a personal Microsoft Account (MSA)" -ForegroundColor Red
            Write-Host "  You need an organizational account to grant Graph permissions" -ForegroundColor Yellow
        }
        elseif ($context.Account.Id -match '@.*\.onmicrosoft\.com$') {
            Write-Host "✓ This appears to be an organizational account" -ForegroundColor Green
        }
    }
    else {
        Write-Host "✗ Not connected to Azure" -ForegroundColor Red
        Write-Host "  Run: Connect-AzAccount" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "✗ Error checking Azure connection: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "2. Checking Microsoft Graph modules..." -ForegroundColor Yellow
$graphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications'
)

foreach ($module in $graphModules) {
    $installed = Get-Module -ListAvailable -Name $module
    if ($installed) {
        Write-Host "✓ $module is installed (v$($installed[0].Version))" -ForegroundColor Green
    }
    else {
        Write-Host "✗ $module is NOT installed" -ForegroundColor Red
        Write-Host "  Run: Install-Module -Name $module -Scope CurrentUser" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "3. Testing Microsoft Graph connection..." -ForegroundColor Yellow
try {
    # Try to connect with minimal scope and tenant if provided
    if ($TenantId) {
        Connect-MgGraph -Scopes "User.Read" -TenantId $TenantId -NoWelcome -ErrorAction Stop
    }
    else {
        Connect-MgGraph -Scopes "User.Read" -NoWelcome -ErrorAction Stop
    }
    $mgContext = Get-MgContext
    
    if ($mgContext) {
        Write-Host "✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "  Account: $($mgContext.Account)" -ForegroundColor Gray
        Write-Host "  TenantId: $($mgContext.TenantId)" -ForegroundColor Gray
        Write-Host "  Scopes: $($mgContext.Scopes -join ', ')" -ForegroundColor Gray
        
        # Try to get service principal to test API access
        Write-Host ""
        Write-Host "4. Testing Graph API access..." -ForegroundColor Yellow
        try {
            $testSp = Get-MgServicePrincipal -Top 1 -ErrorAction Stop
            Write-Host "✓ Can access Microsoft Graph API" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -match "MSA accounts") {
                Write-Host "✗ Cannot access Graph API - MSA account detected" -ForegroundColor Red
                Write-Host "  This confirms you're using a personal Microsoft Account" -ForegroundColor Yellow
                Write-Host "  You MUST use an organizational account instead" -ForegroundColor Yellow
            }
            else {
                Write-Host "✗ Cannot access Graph API: $_" -ForegroundColor Red
            }
        }
        
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host "✗ Cannot connect to Microsoft Graph: $_" -ForegroundColor Red
    if ($_.Exception.Message -match "MSA") {
        Write-Host "  This is due to using a personal Microsoft Account" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Recommendations:" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if ($context.Account.Id -match '@(outlook|hotmail|live|msn)\.com$') {
    Write-Host "1. Sign out of your personal account:" -ForegroundColor Yellow
    Write-Host "   Disconnect-AzAccount" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Sign in with your organizational account:" -ForegroundColor Yellow
    Write-Host "   Connect-AzAccount -TenantId 'your-tenant-id'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Use an account like:" -ForegroundColor Yellow
    Write-Host "   admin@yourcompany.onmicrosoft.com" -ForegroundColor Gray
    Write-Host "   user@yourcompany.com (if federated)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. Ensure the account has one of these roles:" -ForegroundColor Yellow
    Write-Host "   - Global Administrator" -ForegroundColor Gray
    Write-Host "   - Privileged Role Administrator" -ForegroundColor Gray
    Write-Host "   - Application Administrator" -ForegroundColor Gray
}
else {
    Write-Host "✓ You appear to be using an organizational account" -ForegroundColor Green
    Write-Host "  If you're still having issues, verify you have admin permissions" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Run the fixed script after switching accounts:" -ForegroundColor Cyan
Write-Host "  .\Grant-ManagedIdentityPermissions-Fixed.ps1 -AutomationAccountName 'YourAccount' -ResourceGroupName 'YourRG'" -ForegroundColor Gray