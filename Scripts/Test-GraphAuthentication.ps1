# Test-GraphAuthentication.ps1
# Reusable authentication script for testing Azure automations with client credentials
# Production scripts should use managed identity - this is for development/testing only

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    
    [Parameter(Mandatory = $false)]
    [string[]]$RequiredScopes = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$TestOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPermissionValidation
)

function Connect-GraphForTesting {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using client credentials for testing purposes
    
    .DESCRIPTION
        This function provides a standard way to authenticate to Microsoft Graph for testing
        Azure automation scripts. It should NOT be used in production - use managed identity instead.
    
    .PARAMETER ClientId
        Application (client) ID from Azure app registration
    
    .PARAMETER TenantId
        Directory (tenant) ID from Azure AD
    
    .PARAMETER ClientSecret
        Client secret from Azure app registration (use secure methods in production)
    
    .PARAMETER RequiredScopes
        Array of required Microsoft Graph scopes to validate
    
    .PARAMETER TestOnly
        Only test connection without validating specific scopes
    
    .PARAMETER SkipPermissionValidation
        Skip permission validation (not recommended)
    
    .EXAMPLE
        Connect-GraphForTesting -RequiredScopes @("Application.Read.All", "Directory.Read.All")
    
    .EXAMPLE
        Connect-GraphForTesting -TestOnly
    #>
    
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Microsoft Graph Test Authentication" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Warning "🔸 This uses client credentials for TESTING only"
    Write-Warning "🔸 Production scripts should use managed identity"
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
    Write-Host "Client ID: $ClientId" -ForegroundColor Yellow
    Write-Host "Required Scopes: $($RequiredScopes -join ', ')" -ForegroundColor Yellow
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        # Import required modules
        Write-Host "`nLoading Microsoft Graph modules..." -ForegroundColor Yellow
        $RequiredModules = @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Applications", 
            "Microsoft.Graph.Reports",
            "Microsoft.Graph.Users"
        )
        
        foreach ($Module in $RequiredModules) {
            if (-not (Get-Module -ListAvailable -Name $Module)) {
                Write-Host "Installing $Module..." -ForegroundColor Yellow
                Install-Module $Module -Scope CurrentUser -Force -AllowClobber
            }
            Import-Module $Module -Force
        }
        Write-Host "✓ Modules loaded successfully" -ForegroundColor Green

        # Connect to Microsoft Graph
        Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
        $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
        
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
        
        $Context = Get-MgContext
        if ($null -eq $Context) {
            throw "Failed to connect to Microsoft Graph"
        }
        
        Write-Host "✓ Successfully connected to Microsoft Graph!" -ForegroundColor Green
        Write-Host "Connected Tenant: $($Context.TenantId)" -ForegroundColor Green
        Write-Host "Authentication Type: $($Context.AuthType)" -ForegroundColor Green
        Write-Host "Available Scopes: $($Context.Scopes -join ', ')" -ForegroundColor Green

        # Validate required permissions
        if (-not $SkipPermissionValidation -and $RequiredScopes.Count -gt 0) {
            Write-Host "`n--- Validating Required Permissions ---" -ForegroundColor Cyan
            
            $CurrentScopes = $Context.Scopes
            $MissingScopes = @()
            $AllPermissionsValid = $true
            
            foreach ($Scope in $RequiredScopes) {
                $HasPermission = $CurrentScopes -contains $Scope
                if ($HasPermission) {
                    Write-Host "  ✓ $Scope - Granted" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ $Scope - Missing" -ForegroundColor Red
                    $MissingScopes += $Scope
                    $AllPermissionsValid = $false
                }
            }
            
            if (-not $AllPermissionsValid) {
                $ErrorMessage = @"
Missing required Microsoft Graph permissions: $($MissingScopes -join ', ')

To fix this:
1. Go to Azure Portal → App Registrations → $ClientId
2. Navigate to API Permissions
3. Add the missing permissions:
$(($MissingScopes | ForEach-Object { "   - Microsoft Graph: $_" }) -join "`n")
4. Click 'Grant admin consent'
5. Re-run this script

Cannot proceed safely without proper permissions.
"@
                throw $ErrorMessage
            }
            
            Write-Host "✓ All required permissions validated" -ForegroundColor Green
        }

        return @{
            Success = $true
            Context = $Context
            TenantId = $Context.TenantId
            Scopes = $Context.Scopes
        }

    } catch {
        Write-Host "`n❌ Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Success = $false
            Error = $_.Exception.Message
            Context = $null
        }
    }
}

function Disconnect-GraphForTesting {
    <#
    .SYNOPSIS
        Safely disconnects from Microsoft Graph
    #>
    
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected safely" -ForegroundColor Green
    }
}

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Tests basic Microsoft Graph connectivity and permissions
    #>
    
    param(
        [string[]]$TestScopes = @("Application.Read.All", "Directory.Read.All", "AuditLog.Read.All", "Mail.Send")
    )
    
    Write-Host "`n--- Testing Graph API Access ---" -ForegroundColor Cyan
    
    try {
        # Test Applications endpoint
        if ($TestScopes -contains "Application.Read.All") {
            Write-Host "Testing Application.Read.All..." -ForegroundColor Yellow
            $TestApps = Get-MgApplication -Top 3 -Property Id,DisplayName -ErrorAction Stop
            Write-Host "  ✓ Retrieved $($TestApps.Count) applications" -ForegroundColor Green
        }
        
        # Test Users endpoint  
        if ($TestScopes -contains "Directory.Read.All") {
            Write-Host "Testing Directory.Read.All..." -ForegroundColor Yellow
            $TestUsers = Get-MgUser -Top 3 -Property Id,DisplayName -ErrorAction Stop
            Write-Host "  ✓ Retrieved $($TestUsers.Count) users" -ForegroundColor Green
        }
        
        # Test Audit Logs
        if ($TestScopes -contains "AuditLog.Read.All") {
            Write-Host "Testing AuditLog.Read.All..." -ForegroundColor Yellow
            $StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
            $TestUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $StartDate&`$top=3"
            $TestResponse = Invoke-MgGraphRequest -Method GET -Uri $TestUri -ErrorAction Stop
            Write-Host "  ✓ Retrieved $($TestResponse.value.Count) sign-in records" -ForegroundColor Green
        }
        
        Write-Host "`n✅ All API tests passed!" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "`n❌ API test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution when script is run directly
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    
    if ($TestOnly) {
        # Simple connection test
        $Result = Connect-GraphForTesting -SkipPermissionValidation
        if ($Result.Success) {
            Test-GraphConnection
        }
        Disconnect-GraphForTesting
    } else {
        # Full authentication with permission validation
        $Result = Connect-GraphForTesting -RequiredScopes $RequiredScopes
        if ($Result.Success) {
            Write-Host "`n🎉 Authentication successful!" -ForegroundColor Green
            Write-Host "You can now use Microsoft Graph cmdlets in your scripts." -ForegroundColor Green
            Write-Host "`nTo disconnect: Disconnect-GraphForTesting" -ForegroundColor Gray
        } else {
            Write-Host "`n💡 To test basic connectivity: .\Test-GraphAuthentication.ps1 -TestOnly" -ForegroundColor Yellow
        }
    }
}

# Export functions for use in other scripts
Export-ModuleMember -Function Connect-GraphForTesting, Disconnect-GraphForTesting, Test-GraphConnection