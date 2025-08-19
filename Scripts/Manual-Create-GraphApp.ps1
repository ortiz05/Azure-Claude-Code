# Create-GraphApp.ps1
# Creates a new Azure AD application with proper Graph permissions for the audit script

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$AppName = "Graph API Audit Tool"
)

try {
    Write-Host "Creating Azure AD application for Graph API auditing..." -ForegroundColor Yellow
    
    # Connect to Microsoft Graph with minimal permissions first
    Connect-MgGraph -TenantId $TenantId -Scopes "Application.ReadWrite.All" -NoWelcome
    
    # Create the application registration
    $AppRegistration = New-MgApplication -DisplayName $AppName -PublicClient @{
        RedirectUris = @("http://localhost")
    }
    
    Write-Host "✓ Created application: $($AppRegistration.DisplayName)" -ForegroundColor Green
    Write-Host "✓ Application ID: $($AppRegistration.AppId)" -ForegroundColor Cyan
    
    # Define required permissions
    $RequiredPermissions = @(
        @{ Permission = "Application.Read.All"; Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" },
        @{ Permission = "Directory.Read.All"; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" },
        @{ Permission = "DelegatedPermissionGrant.Read.All"; Id = "2e770aa0-9f26-4b7b-a9e8-0c01c0b0d431" },
        @{ Permission = "AppRoleAssignment.ReadWrite.All"; Id = "06b708a9-e830-4db3-a914-8e69da51d44f" }
    )
    
    # Microsoft Graph App ID
    $GraphAppId = "00000003-0000-0000-c000-000000000000"
    
    # Build resource access array
    $ResourceAccess = @()
    foreach ($Permission in $RequiredPermissions) {
        $ResourceAccess += @{
            Id = $Permission.Id
            Type = "Role"  # Application permission
        }
    }
    
    # Update application with required permissions
    Update-MgApplication -ApplicationId $AppRegistration.Id -RequiredResourceAccess @{
        ResourceAppId = $GraphAppId
        ResourceAccess = $ResourceAccess
    }
    
    Write-Host "✓ Added required Graph API permissions" -ForegroundColor Green
    
    # Output the details
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Azure AD Application Created Successfully" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Application Name: $($AppRegistration.DisplayName)" -ForegroundColor White
    Write-Host "Application ID: $($AppRegistration.AppId)" -ForegroundColor Yellow
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
    Write-Host "Object ID: $($AppRegistration.Id)" -ForegroundColor Gray
    
    Write-Host "`n⚠️  IMPORTANT NEXT STEPS:" -ForegroundColor Red
    Write-Host "1. Go to Azure Portal → App Registrations → $($AppRegistration.DisplayName)" -ForegroundColor White
    Write-Host "2. Navigate to API Permissions" -ForegroundColor White
    Write-Host "3. Click 'Grant admin consent for [Your Organization]'" -ForegroundColor White
    Write-Host "4. Confirm 'Yes' to grant consent" -ForegroundColor White
    Write-Host "`n5. Then run the audit script with these parameters:" -ForegroundColor Green
    Write-Host "   .\Manual-ApplicationPermissionAudit.ps1 -TenantId '$TenantId' -ClientId '$($AppRegistration.AppId)'" -ForegroundColor Cyan
    
} catch {
    Write-Error "Failed to create application: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}