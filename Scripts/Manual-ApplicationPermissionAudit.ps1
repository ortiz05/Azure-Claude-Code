#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Comprehensive audit of Azure Application Registrations and Enterprise Applications with their API permissions

.DESCRIPTION
    This script performs a detailed security audit of all application registrations and enterprise applications
    in your Azure AD tenant, cataloging both delegated and application permissions for internal security review.
    
    IMPORTANT: This script requires a custom Azure AD application registration with the required permissions
    since the default Microsoft Graph PowerShell application may be disabled in enterprise environments.
    
    The script generates multiple CSV reports to help understand the security posture of applications:
    - Complete application inventory with permission details
    - High-risk permission analysis
    - Application permission summary
    - Detailed permission breakdown by application
    
.PARAMETER TenantId
    Azure AD Tenant ID (required for targeted authentication)

.PARAMETER ClientId
    Application (client) ID of the Azure AD app registration to use for authentication
    Required when the default Microsoft Graph PowerShell app is disabled
    
.PARAMETER ExportPath
    Local directory path for CSV exports (default: C:\Temp\ApplicationAudit)
    
.PARAMETER IncludeBuiltInApps
    Include built-in Microsoft applications in the audit (default: false)
    
.PARAMETER AnalyzeRisks
    Perform risk analysis on permissions (default: true)
    
.PARAMETER Detailed
    Generate detailed reports with extended information (default: true)

.EXAMPLE
    .\Manual-ApplicationPermissionAudit.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321"
    
.EXAMPLE
    .\Manual-ApplicationPermissionAudit.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ExportPath "C:\SecurityAudit" -IncludeBuiltInApps
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Temp\ApplicationAudit",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBuiltInApps = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$AnalyzeRisks = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed = $true
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Application Permission Security Audit" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Client ID: $ClientId" -ForegroundColor Yellow
Write-Host "Export Path: $ExportPath" -ForegroundColor Yellow
Write-Host "Include Built-in Apps: $IncludeBuiltInApps" -ForegroundColor Yellow
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "===========================================" -ForegroundColor Cyan

# Initialize tracking collections
$ApplicationData = [System.Collections.ArrayList]::new()
$PermissionDetails = [System.Collections.ArrayList]::new()
$HighRiskPermissions = [System.Collections.ArrayList]::new()

# Define high-risk permissions for analysis
$HighRiskApplicationPermissions = @(
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All", 
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Policy.ReadWrite.ApplicationConfiguration",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All"
)

$HighRiskDelegatedPermissions = @(
    "Directory.AccessAsUser.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All", 
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All"
)

function Test-RequiredPermissions {
    [CmdletBinding()]
    param()
    
    Write-Host "Validating Microsoft Graph permissions..." -ForegroundColor Yellow
    
    $RequiredPermissions = @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AppRoleAssignment.Read.All"
    )
    
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first."
    }
    
    $MissingPermissions = @()
    foreach ($Permission in $RequiredPermissions) {
        if ($Context.Scopes -notcontains $Permission) {
            $MissingPermissions += $Permission
        }
    }
    
    if ($MissingPermissions.Count -gt 0) {
        $ErrorMessage = @"
CRITICAL ERROR: Missing required Microsoft Graph permissions.

Required permissions:
$(($RequiredPermissions | ForEach-Object { "  - $_" }) -join "`n")

Missing permissions:
$(($MissingPermissions | ForEach-Object { "  - $_" }) -join "`n")

To fix this:
1. Go to Azure Portal → App Registrations → [Your App]
2. Navigate to API Permissions
3. Add the missing Microsoft Graph permissions (Application type)
4. Click 'Grant admin consent'
5. Re-run this script

Cannot proceed safely without proper permissions.
"@
        throw $ErrorMessage
    }
    
    Write-Host "✓ All required permissions validated" -ForegroundColor Green
    return $true
}

function Get-ApplicationPermissionDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Application,
        
        [Parameter(Mandatory = $true)]
        [string]$Type
    )
    
    $PermissionData = @()
    
    # Get application permissions (app roles)
    if ($Application.RequiredResourceAccess) {
        foreach ($ResourceAccess in $Application.RequiredResourceAccess) {
            try {
                # Get the service principal for the resource
                $ServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$($ResourceAccess.ResourceAppId)'" -ErrorAction SilentlyContinue
                $ResourceName = if ($ServicePrincipal) { $ServicePrincipal.DisplayName } else { $ResourceAccess.ResourceAppId }
                
                foreach ($ResourcePermission in $ResourceAccess.ResourceAccess) {
                    $PermissionName = "Unknown"
                    $PermissionType = "Unknown"
                    
                    if ($ServicePrincipal) {
                        if ($ResourcePermission.Type -eq "Role") {
                            # Application permission
                            $AppRole = $ServicePrincipal.AppRoles | Where-Object { $_.Id -eq $ResourcePermission.Id }
                            if ($AppRole) {
                                $PermissionName = $AppRole.Value
                                $PermissionType = "Application"
                            }
                        } elseif ($ResourcePermission.Type -eq "Scope") {
                            # Delegated permission
                            $OAuth2Scope = $ServicePrincipal.OAuth2PermissionScopes | Where-Object { $_.Id -eq $ResourcePermission.Id }
                            if ($OAuth2Scope) {
                                $PermissionName = $OAuth2Scope.Value
                                $PermissionType = "Delegated"
                            }
                        }
                    }
                    
                    # Risk analysis
                    $IsHighRisk = $false
                    if ($PermissionType -eq "Application" -and $HighRiskApplicationPermissions -contains $PermissionName) {
                        $IsHighRisk = $true
                    } elseif ($PermissionType -eq "Delegated" -and $HighRiskDelegatedPermissions -contains $PermissionName) {
                        $IsHighRisk = $true
                    }
                    
                    $PermissionData += [PSCustomObject]@{
                        ApplicationId = $Application.Id
                        ApplicationName = $Application.DisplayName
                        ApplicationType = $Type
                        ResourceId = $ResourceAccess.ResourceAppId
                        ResourceName = $ResourceName
                        PermissionId = $ResourcePermission.Id
                        PermissionName = $PermissionName
                        PermissionType = $PermissionType
                        IsHighRisk = $IsHighRisk
                        AdminConsentRequired = if ($PermissionType -eq "Application") { $true } else { 
                            if ($ServicePrincipal -and $ResourcePermission.Type -eq "Scope") {
                                $OAuth2Scope = $ServicePrincipal.OAuth2PermissionScopes | Where-Object { $_.Id -eq $ResourcePermission.Id }
                                if ($OAuth2Scope) { $OAuth2Scope.AdminConsentRequired } else { $false }
                            } else { $false }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Could not retrieve permission details for resource $($ResourceAccess.ResourceAppId): $_"
            }
        }
    }
    
    return $PermissionData
}

function Connect-ToMicrosoftGraph {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        
        # Check if already connected to the correct tenant and client
        $Context = Get-MgContext
        if ($Context -and $Context.TenantId -eq $TenantId -and $Context.ClientId -eq $ClientId) {
            Write-Host "✓ Already connected to tenant: $($Context.TenantId) with client: $($Context.ClientId)" -ForegroundColor Green
        } else {
            # Connect with specific client ID and tenant-specific authentication
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Scopes "Application.Read.All","Directory.Read.All","DelegatedPermissionGrant.Read.All","AppRoleAssignment.Read.All" -NoWelcome
            
            $Context = Get-MgContext
            Write-Host "✓ Connected to tenant: $($Context.TenantId) with client: $($Context.ClientId)" -ForegroundColor Green
        }
        
        Test-RequiredPermissions
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        throw
    }
}

# Ensure export directory exists
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    Write-Host "Created export directory: $ExportPath" -ForegroundColor Green
}

try {
    # Connect to Microsoft Graph
    Connect-ToMicrosoftGraph
    
    # Get all Application Registrations
    Write-Host "`nScanning Application Registrations..." -ForegroundColor Yellow
    $AppRegistrations = Get-MgApplication -All -Property Id,DisplayName,AppId,CreatedDateTime,PublisherDomain,SignInAudience,RequiredResourceAccess
    
    Write-Host "Found $($AppRegistrations.Count) Application Registrations" -ForegroundColor Green
    
    $ProcessedApps = 0
    foreach ($App in $AppRegistrations) {
        $ProcessedApps++
        
        if ($ProcessedApps % 10 -eq 0) {
            Write-Host "Processed $ProcessedApps/$($AppRegistrations.Count) Application Registrations..." -ForegroundColor Gray
        }
        
        # Skip built-in Microsoft apps unless explicitly requested
        if (-not $IncludeBuiltInApps -and $App.PublisherDomain -like "*.microsoft.com") {
            continue
        }
        
        # Get permission details
        $Permissions = Get-ApplicationPermissionDetails -Application $App -Type "Application Registration"
        
        # Add to permission details collection
        foreach ($Permission in $Permissions) {
            [void]$PermissionDetails.Add($Permission)
            
            if ($Permission.IsHighRisk) {
                [void]$HighRiskPermissions.Add($Permission)
            }
        }
        
        # Create application summary
        $AppSummary = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Type = "Application Registration"
            ApplicationId = $App.Id
            AppId = $App.AppId
            DisplayName = $App.DisplayName
            PublisherDomain = $App.PublisherDomain
            SignInAudience = $App.SignInAudience
            CreatedDateTime = $App.CreatedDateTime
            TotalPermissions = $Permissions.Count
            ApplicationPermissions = ($Permissions | Where-Object { $_.PermissionType -eq "Application" }).Count
            DelegatedPermissions = ($Permissions | Where-Object { $_.PermissionType -eq "Delegated" }).Count
            HighRiskPermissions = ($Permissions | Where-Object { $_.IsHighRisk }).Count
            AdminConsentRequired = ($Permissions | Where-Object { $_.AdminConsentRequired }).Count
            UniqueResources = ($Permissions | Select-Object -ExpandProperty ResourceName -Unique).Count
        }
        
        [void]$ApplicationData.Add($AppSummary)
    }
    
    # Get all Enterprise Applications (Service Principals)
    Write-Host "`nScanning Enterprise Applications..." -ForegroundColor Yellow
    $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,CreatedDateTime,PublisherName,ServicePrincipalType,AppRoles,OAuth2PermissionScopes
    
    # Filter to only user-created applications
    $EnterpriseApps = $ServicePrincipals | Where-Object { 
        $_.ServicePrincipalType -eq "Application" -and 
        (-not $_.PublisherName -or ($IncludeBuiltInApps -or $_.PublisherName -notlike "*Microsoft*"))
    }
    
    Write-Host "Found $($EnterpriseApps.Count) Enterprise Applications" -ForegroundColor Green
    
    $ProcessedEA = 0
    foreach ($EntApp in $EnterpriseApps) {
        $ProcessedEA++
        
        if ($ProcessedEA % 10 -eq 0) {
            Write-Host "Processed $ProcessedEA/$($EnterpriseApps.Count) Enterprise Applications..." -ForegroundColor Gray
        }
        
        # Skip if we already processed this as an App Registration
        if ($ApplicationData | Where-Object { $_.AppId -eq $EntApp.AppId }) {
            continue
        }
        
        # Get granted permissions (app role assignments and OAuth2 grants)
        try {
            $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $EntApp.Id -ErrorAction SilentlyContinue
            $OAuth2Grants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $EntApp.Id -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Could not retrieve granted permissions for $($EntApp.DisplayName): $_"
            $AppRoleAssignments = @()
            $OAuth2Grants = @()
        }
        
        $GrantedPermissions = @()
        
        # Process app role assignments (application permissions)
        foreach ($Assignment in $AppRoleAssignments) {
            try {
                $ResourceSP = Get-MgServicePrincipal -ServicePrincipalId $Assignment.ResourceId -ErrorAction SilentlyContinue
                $AppRole = $ResourceSP.AppRoles | Where-Object { $_.Id -eq $Assignment.AppRoleId }
                
                if ($AppRole) {
                    $IsHighRisk = $HighRiskApplicationPermissions -contains $AppRole.Value
                    
                    $GrantedPermissions += [PSCustomObject]@{
                        ApplicationId = $EntApp.Id
                        ApplicationName = $EntApp.DisplayName
                        ApplicationType = "Enterprise Application"
                        ResourceId = $ResourceSP.AppId
                        ResourceName = $ResourceSP.DisplayName
                        PermissionId = $Assignment.AppRoleId
                        PermissionName = $AppRole.Value
                        PermissionType = "Application"
                        IsHighRisk = $IsHighRisk
                        AdminConsentRequired = $true
                    }
                }
            }
            catch {
                Write-Verbose "Could not process app role assignment for $($EntApp.DisplayName): $_"
            }
        }
        
        # Process OAuth2 grants (delegated permissions)
        foreach ($Grant in $OAuth2Grants) {
            try {
                $ResourceSP = Get-MgServicePrincipal -ServicePrincipalId $Grant.ResourceId -ErrorAction SilentlyContinue
                
                if ($Grant.Scope) {
                    $Scopes = $Grant.Scope -split " "
                    foreach ($Scope in $Scopes) {
                        if ($Scope.Trim()) {
                            $OAuth2Scope = $ResourceSP.OAuth2PermissionScopes | Where-Object { $_.Value -eq $Scope.Trim() }
                            $IsHighRisk = $HighRiskDelegatedPermissions -contains $Scope.Trim()
                            
                            $GrantedPermissions += [PSCustomObject]@{
                                ApplicationId = $EntApp.Id
                                ApplicationName = $EntApp.DisplayName
                                ApplicationType = "Enterprise Application"
                                ResourceId = $ResourceSP.AppId
                                ResourceName = $ResourceSP.DisplayName
                                PermissionId = if ($OAuth2Scope) { $OAuth2Scope.Id } else { "Unknown" }
                                PermissionName = $Scope.Trim()
                                PermissionType = "Delegated"
                                IsHighRisk = $IsHighRisk
                                AdminConsentRequired = if ($OAuth2Scope) { $OAuth2Scope.AdminConsentRequired } else { $false }
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not process OAuth2 grant for $($EntApp.DisplayName): $_"
            }
        }
        
        # Add to permission details collection
        foreach ($Permission in $GrantedPermissions) {
            [void]$PermissionDetails.Add($Permission)
            
            if ($Permission.IsHighRisk) {
                [void]$HighRiskPermissions.Add($Permission)
            }
        }
        
        # Create application summary
        $AppSummary = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Type = "Enterprise Application"
            ApplicationId = $EntApp.Id
            AppId = $EntApp.AppId
            DisplayName = $EntApp.DisplayName
            PublisherDomain = $EntApp.PublisherName
            SignInAudience = "N/A"
            CreatedDateTime = $EntApp.CreatedDateTime
            TotalPermissions = $GrantedPermissions.Count
            ApplicationPermissions = ($GrantedPermissions | Where-Object { $_.PermissionType -eq "Application" }).Count
            DelegatedPermissions = ($GrantedPermissions | Where-Object { $_.PermissionType -eq "Delegated" }).Count
            HighRiskPermissions = ($GrantedPermissions | Where-Object { $_.IsHighRisk }).Count
            AdminConsentRequired = ($GrantedPermissions | Where-Object { $_.AdminConsentRequired }).Count
            UniqueResources = ($GrantedPermissions | Select-Object -ExpandProperty ResourceName -Unique).Count
        }
        
        [void]$ApplicationData.Add($AppSummary)
    }
    
    # Generate Reports
    Write-Host "`n--- Generating Security Audit Reports ---" -ForegroundColor Yellow
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # 1. Complete Application Inventory
    if ($ApplicationData.Count -gt 0) {
        $ApplicationInventoryFile = Join-Path $ExportPath "ApplicationInventory_$Timestamp.csv"
        $ApplicationData | Export-Csv -Path $ApplicationInventoryFile -NoTypeInformation -Encoding UTF8
        Write-Host "Application Inventory: $ApplicationInventoryFile" -ForegroundColor Green
    }
    
    # 2. Detailed Permission Analysis
    if ($PermissionDetails.Count -gt 0) {
        $PermissionDetailsFile = Join-Path $ExportPath "DetailedPermissions_$Timestamp.csv"
        $PermissionDetails | Export-Csv -Path $PermissionDetailsFile -NoTypeInformation -Encoding UTF8
        Write-Host "Detailed Permissions: $PermissionDetailsFile" -ForegroundColor Green
    }
    
    # 3. High-Risk Permissions Report
    if ($HighRiskPermissions.Count -gt 0) {
        $HighRiskFile = Join-Path $ExportPath "HighRiskPermissions_$Timestamp.csv"
        $HighRiskPermissions | Export-Csv -Path $HighRiskFile -NoTypeInformation -Encoding UTF8
        Write-Host "High-Risk Permissions: $HighRiskFile" -ForegroundColor Red
    }
    
    # 4. Permission Summary by Resource
    $ResourceSummary = $PermissionDetails | Group-Object ResourceName | ForEach-Object {
        $Resource = $_.Group
        [PSCustomObject]@{
            ResourceName = $_.Name
            TotalApplicationsWithAccess = ($Resource | Select-Object -ExpandProperty ApplicationName -Unique).Count
            TotalPermissionsGranted = $Resource.Count
            ApplicationPermissions = ($Resource | Where-Object { $_.PermissionType -eq "Application" }).Count
            DelegatedPermissions = ($Resource | Where-Object { $_.PermissionType -eq "Delegated" }).Count
            HighRiskPermissions = ($Resource | Where-Object { $_.IsHighRisk }).Count
            UniquePermissions = ($Resource | Select-Object -ExpandProperty PermissionName -Unique).Count
        }
    }
    
    if ($ResourceSummary.Count -gt 0) {
        $ResourceSummaryFile = Join-Path $ExportPath "ResourcePermissionSummary_$Timestamp.csv"
        $ResourceSummary | Export-Csv -Path $ResourceSummaryFile -NoTypeInformation -Encoding UTF8
        Write-Host "Resource Summary: $ResourceSummaryFile" -ForegroundColor Green
    }
    
    # 5. Executive Summary
    $ExecutiveSummary = [PSCustomObject]@{
        AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TenantId = $TenantId
        ClientId = $ClientId
        TotalApplicationsAudited = $ApplicationData.Count
        ApplicationRegistrations = ($ApplicationData | Where-Object { $_.Type -eq "Application Registration" }).Count
        EnterpriseApplications = ($ApplicationData | Where-Object { $_.Type -eq "Enterprise Application" }).Count
        TotalPermissionsGranted = $PermissionDetails.Count
        ApplicationPermissions = ($PermissionDetails | Where-Object { $_.PermissionType -eq "Application" }).Count
        DelegatedPermissions = ($PermissionDetails | Where-Object { $_.PermissionType -eq "Delegated" }).Count
        HighRiskPermissions = $HighRiskPermissions.Count
        AdminConsentRequiredPermissions = ($PermissionDetails | Where-Object { $_.AdminConsentRequired }).Count
        UniqueResourcesAccessed = ($PermissionDetails | Select-Object -ExpandProperty ResourceName -Unique).Count
        IncludedBuiltInApps = $IncludeBuiltInApps
    }
    
    $ExecutiveSummaryFile = Join-Path $ExportPath "ExecutiveSummary_$Timestamp.csv"
    $ExecutiveSummary | Export-Csv -Path $ExecutiveSummaryFile -NoTypeInformation -Encoding UTF8
    Write-Host "Executive Summary: $ExecutiveSummaryFile" -ForegroundColor Cyan
    
    # Display summary statistics
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Application Permission Audit Complete" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "📊 Audit Summary:" -ForegroundColor Cyan
    Write-Host "  Total Applications: $($ApplicationData.Count)" -ForegroundColor White
    Write-Host "  Total Permissions: $($PermissionDetails.Count)" -ForegroundColor White
    Write-Host "  High-Risk Permissions: $($HighRiskPermissions.Count)" -ForegroundColor Red
    Write-Host "  Application Permissions: $($ExecutiveSummary.ApplicationPermissions)" -ForegroundColor Yellow
    Write-Host "  Delegated Permissions: $($ExecutiveSummary.DelegatedPermissions)" -ForegroundColor Yellow
    Write-Host "  Unique Resources: $($ExecutiveSummary.UniqueResourcesAccessed)" -ForegroundColor White
    Write-Host "`n📁 Reports exported to: $ExportPath" -ForegroundColor Gray
    
    if ($HighRiskPermissions.Count -gt 0) {
        Write-Host "`n🚨 SECURITY ALERT: $($HighRiskPermissions.Count) high-risk permissions detected!" -ForegroundColor Red
        Write-Host "   Review HighRiskPermissions_$Timestamp.csv for details" -ForegroundColor Red
    } else {
        Write-Host "`n✅ No high-risk permissions detected" -ForegroundColor Green
    }
    
    Write-Host "`nEnd Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "==========================================" -ForegroundColor Cyan
    
} catch {
    Write-Error "Application permission audit failed: $($_.Exception.Message)"
    
    # Save error to file
    $ErrorFile = Join-Path $ExportPath "AuditError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $_ | Out-File -FilePath $ErrorFile -Encoding UTF8
    Write-Host "Error details saved to: $ErrorFile" -ForegroundColor Red
    
    exit 1
} finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Gray
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}