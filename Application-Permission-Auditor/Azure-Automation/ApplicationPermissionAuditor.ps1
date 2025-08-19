# ApplicationPermissionAuditor.ps1
# Enterprise Application Permission Audit and Compliance Automation
# Scans and analyzes Microsoft Graph API permissions across all Enterprise Applications
#
# New Feature: Custom Graph Application Support
# Use -GraphClientId parameter to specify a custom Azure AD application for Graph authentication
# when the default Microsoft Graph PowerShell app is disabled in enterprise environments

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    
    [Parameter(Mandatory = $false)]
    [string]$GraphClientId,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeApplications = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Reports",
    
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$StorageContainerName = "permission-audit-reports",
    
    [Parameter(Mandatory = $false)]
    [switch]$UseManagedIdentity = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationEmailFrom = $env:NOTIFICATION_EMAIL_FROM,
    
    [Parameter(Mandatory = $false)]
    [string[]]$SecurityTeamEmails = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendNotifications = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOAuthConsents = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateExecutiveSummary = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$AnalyzePermissionTrends = $true,
    
    [Parameter(Mandatory = $false)]
    [string[]]$HighRiskPermissions = @(
        "Directory.ReadWrite.All",
        "User.ReadWrite.All", 
        "Group.ReadWrite.All",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Device.ReadWrite.All",
        "Policy.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Sites.FullControl.All",
        "Files.ReadWrite.All",
        "Mail.ReadWrite.All",
        "Calendars.ReadWrite.All",
        "Contacts.ReadWrite.All"
    ),
    
    [Parameter(Mandatory = $false)]
    [string[]]$AdminConsentRequiredPermissions = @(
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read.All",
        "User.ReadWrite.All",
        "Group.Read.All", 
        "Group.ReadWrite.All",
        "Application.Read.All",
        "Application.ReadWrite.All",
        "DeviceManagementApps.ReadWrite.All",
        "DeviceManagementConfiguration.ReadWrite.All"
    )
)

$ErrorActionPreference = "Stop"

# Import Azure Storage modules for blob storage functionality
if ($StorageAccountName) {
    Import-Module Az.Storage -ErrorAction Stop
    Import-Module Az.Accounts -ErrorAction Stop
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Application Permission Auditor" -ForegroundColor Cyan
Write-Host "Enterprise Security & Compliance Automation" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Report Path: $ReportPath" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "Include OAuth Consents: $IncludeOAuthConsents" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

function Export-ToBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$BlobName,
        
        [Parameter(Mandatory=$false)]
        [string]$StorageAccount = $StorageAccountName,
        
        [Parameter(Mandatory=$false)]
        [string]$ContainerName = $StorageContainerName
    )
    
    if (-not $StorageAccount) {
        Write-Warning "No storage account specified. Skipping blob upload for $BlobName"
        return $false
    }
    
    try {
        # Create storage context using managed identity
        $Context = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount
        
        # Create folder structure with year/month
        $DatePath = Get-Date -Format "yyyy/MM"
        $BlobPath = "$DatePath/$BlobName"
        
        # Upload file to blob storage
        $BlobResult = Set-AzStorageBlobContent -File $FilePath -Container $ContainerName -Blob $BlobPath -Context $Context -StandardBlobTier Cool -Force
        
        Write-Output "✓ Uploaded to blob storage: $($BlobResult.Name)"
        return $true
    }
    catch {
        Write-Warning "Failed to upload $BlobName to blob storage: $_"
        return $false
    }
}

function Test-RequiredPermissions {
    try {
        Write-Host "Validating Microsoft Graph permissions..." -ForegroundColor Yellow
        
        $RequiredPermissions = @(
            "Application.Read.All",
            "Directory.Read.All",
            "DelegatedPermissionGrant.Read.All",
            "AppRoleAssignment.ReadWrite.All",
            "AuditLog.Read.All",
            "Mail.Send"
        )
        
        $Context = Get-MgContext
        if (-not $Context) {
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first."
        }
        
        $PermissionsValid = $true
        $MissingPermissions = @()
        
        foreach ($Permission in $RequiredPermissions) {
            if ($Context.Scopes -notcontains $Permission) {
                $PermissionsValid = $false
                $MissingPermissions += $Permission
                Write-Host "  ✗ Missing: $Permission" -ForegroundColor Red
            } else {
                Write-Host "  ✓ Granted: $Permission" -ForegroundColor Green
            }
        }
        
        if (-not $PermissionsValid) {
            $ErrorMessage = @"
CRITICAL ERROR: Missing required Microsoft Graph permissions.

Required permissions:
$(($RequiredPermissions | ForEach-Object { "  - $_" }) -join "`n")

Missing permissions:
$(($MissingPermissions | ForEach-Object { "  - $_" }) -join "`n")

To fix this:
1. Go to Azure Portal → App Registrations → $ClientId
2. Navigate to API Permissions
3. Add the missing Microsoft Graph permissions (Application type)
4. Click 'Grant admin consent'
5. Re-run this script

Cannot proceed safely without proper permissions.
"@
            Write-Error $ErrorMessage
            throw "Missing required Microsoft Graph permissions. Cannot continue safely."
        }
        
        Write-Host "✓ All required permissions validated" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Permission validation failed: $($_.Exception.Message)"
        throw
    }
}

function Connect-ToMicrosoftGraph {
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        
        if ($UseManagedIdentity -or $StorageAccountName) {
            # Use Managed Identity for authentication (required for blob storage)
            Write-Host "Connecting with Azure Automation Managed Identity..." -ForegroundColor Yellow
            
            # Use custom Graph application if specified
            if ($GraphClientId) {
                Write-Host "Using custom Graph application: $GraphClientId" -ForegroundColor Yellow
                Connect-MgGraph -Identity -ClientId $GraphClientId -NoWelcome
            } else {
                Connect-MgGraph -Identity -NoWelcome
            }
            
            # Also connect to Azure for storage operations if needed
            if ($StorageAccountName) {
                Write-Host "Connecting to Azure for storage operations..." -ForegroundColor Yellow
                Connect-AzAccount -Identity
            }
        }
        elseif ($ClientId -and $TenantId -and $ClientSecret) {
            # PSScriptAnalyzer: ConvertTo-SecureString with -AsPlainText is required for authentication
            # This is a standard Microsoft Graph authentication pattern
            $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force  # nosemgrep
            $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
            
            # Use custom Graph application if specified, otherwise use the service principal credentials
            if ($GraphClientId) {
                Write-Host "Using custom Graph application: $GraphClientId" -ForegroundColor Yellow
                Connect-MgGraph -ClientId $GraphClientId -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
            } else {
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
            }
        } else {
            # Interactive authentication with custom Graph application if specified
            if ($GraphClientId) {
                Write-Host "Using custom Graph application: $GraphClientId" -ForegroundColor Yellow
                Connect-MgGraph -ClientId $GraphClientId -TenantId $TenantId -NoWelcome
            } else {
                Connect-MgGraph -TenantId $TenantId -NoWelcome
            }
        }
        
        $Context = Get-MgContext
        Write-Host "✓ Connected to tenant: $($Context.TenantId)" -ForegroundColor Green
        
        Test-RequiredPermissions
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        throw
    }
}

function Get-ApplicationPermissionData {
    try {
        Write-Host "Scanning Enterprise Applications and permissions..." -ForegroundColor Yellow
        
        # Get all Enterprise Applications (Service Principals)
        $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,CreatedDateTime,ServicePrincipalType,Homepage,AppRoles,Oauth2PermissionScopes
        
        Write-Host "Found $($ServicePrincipals.Count) Enterprise Applications" -ForegroundColor Green
        
        $PermissionData = @()
        $ProcessedCount = 0
        
        foreach ($SP in $ServicePrincipals) {
            $ProcessedCount++
            
            if ($ProcessedCount % 25 -eq 0) {
                Write-Host "Processed $ProcessedCount/$($ServicePrincipals.Count) applications..." -ForegroundColor Gray
            }
            
            if ($ExcludeApplications -contains $SP.DisplayName -or $ExcludeApplications -contains $SP.AppId) {
                continue
            }
            
            # Get Application Role Assignments (App permissions granted TO this application)
            try {
                $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue
                
                foreach ($Assignment in $AppRoleAssignments) {
                    # Get the resource application details
                    $ResourceApp = Get-MgServicePrincipal -ServicePrincipalId $Assignment.ResourceId -ErrorAction SilentlyContinue
                    
                    if ($ResourceApp) {
                        # Find the specific app role
                        $AppRole = $ResourceApp.AppRoles | Where-Object { $_.Id -eq $Assignment.AppRoleId }
                        
                        $PermissionData += [PSCustomObject]@{
                            ApplicationName = $SP.DisplayName
                            ApplicationId = $SP.AppId
                            ServicePrincipalId = $SP.Id
                            ServicePrincipalType = $SP.ServicePrincipalType
                            CreatedDateTime = $SP.CreatedDateTime
                            PermissionType = "Application"
                            ResourceApplication = $ResourceApp.DisplayName
                            ResourceAppId = $ResourceApp.AppId
                            Permission = if ($AppRole) { $AppRole.Value } else { "Unknown" }
                            PermissionDisplayName = if ($AppRole) { $AppRole.DisplayName } else { "Unknown Role" }
                            PermissionDescription = if ($AppRole) { $AppRole.Description } else { "Role description not available" }
                            ConsentType = "Admin" # App permissions always require admin consent
                            GrantedDateTime = $Assignment.CreatedDateTime
                            RiskLevel = ""
                            IsHighRisk = $false
                            RequiresAdminConsent = $true
                            PrincipalType = "ServicePrincipal"
                            PrincipalId = $SP.Id
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not retrieve app role assignments for $($SP.DisplayName): $($_.Exception.Message)"
            }
            
            # Get OAuth2 Permission Grants (Delegated permissions)
            if ($IncludeOAuthConsents) {
                try {
                    $OAuth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($SP.Id)'" -ErrorAction SilentlyContinue
                    
                    foreach ($Grant in $OAuth2Grants) {
                        # Get the resource application details
                        $ResourceApp = Get-MgServicePrincipal -ServicePrincipalId $Grant.ResourceId -ErrorAction SilentlyContinue
                        
                        if ($ResourceApp -and $Grant.Scope) {
                            $Scopes = $Grant.Scope -split " " | Where-Object { $_ -ne "" }
                            
                            foreach ($Scope in $Scopes) {
                                # Find the OAuth2PermissionScope details
                                $PermissionScope = $ResourceApp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $Scope }
                                
                                $PermissionData += [PSCustomObject]@{
                                    ApplicationName = $SP.DisplayName
                                    ApplicationId = $SP.AppId
                                    ServicePrincipalId = $SP.Id
                                    ServicePrincipalType = $SP.ServicePrincipalType
                                    CreatedDateTime = $SP.CreatedDateTime
                                    PermissionType = "Delegated"
                                    ResourceApplication = $ResourceApp.DisplayName
                                    ResourceAppId = $ResourceApp.AppId
                                    Permission = $Scope
                                    PermissionDisplayName = if ($PermissionScope) { $PermissionScope.AdminConsentDisplayName } else { $Scope }
                                    PermissionDescription = if ($PermissionScope) { $PermissionScope.AdminConsentDescription } else { "Delegated permission" }
                                    ConsentType = $Grant.ConsentType
                                    GrantedDateTime = $Grant.CreatedDateTime
                                    RiskLevel = ""
                                    IsHighRisk = $false
                                    RequiresAdminConsent = if ($PermissionScope) { $PermissionScope.Type -eq "Admin" } else { $false }
                                    PrincipalType = if ($Grant.PrincipalId) { "User" } else { "ServicePrincipal" }
                                    PrincipalId = $Grant.PrincipalId
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Could not retrieve OAuth2 grants for $($SP.DisplayName): $($_.Exception.Message)"
                }
            }
        }
        
        Write-Host "✓ Found $($PermissionData.Count) permissions across $($ServicePrincipals.Count) applications" -ForegroundColor Green
        return $PermissionData
        
    } catch {
        Write-Error "Failed to scan application permissions: $($_.Exception.Message)"
        throw
    }
}

function Set-PermissionRiskLevels {
    param([array]$PermissionData)
    
    try {
        Write-Host "Analyzing permission risk levels..." -ForegroundColor Yellow
        
        $CriticalCount = 0
        $HighCount = 0
        $MediumCount = 0
        $LowCount = 0
        
        foreach ($Permission in $PermissionData) {
            $RiskFactors = @()
            
            # Check if it's a high-risk permission
            if ($HighRiskPermissions -contains $Permission.Permission) {
                $RiskFactors += "High-Risk Permission"
                $Permission.IsHighRisk = $true
            }
            
            # Check if it requires admin consent
            if ($Permission.RequiresAdminConsent) {
                $RiskFactors += "Admin Consent Required"
            }
            
            # Check permission type - Application permissions are generally higher risk
            if ($Permission.PermissionType -eq "Application") {
                $RiskFactors += "Application Permission"
            }
            
            # Check for broad scope permissions
            $BroadScopeKeywords = @("All", "ReadWrite", "FullControl")
            foreach ($Keyword in $BroadScopeKeywords) {
                if ($Permission.Permission -like "*$Keyword*") {
                    $RiskFactors += "Broad Scope"
                    break
                }
            }
            
            # Check for Microsoft Graph permissions (often high privilege)
            if ($Permission.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {
                $RiskFactors += "Microsoft Graph API"
            }
            
            # Check for old applications with powerful permissions
            $ApplicationAge = if ($Permission.CreatedDateTime) {
                [Math]::Round(((Get-Date) - $Permission.CreatedDateTime).TotalDays, 0)
            } else {
                $null
            }
            
            if ($ApplicationAge -and $ApplicationAge -gt 365 -and $Permission.IsHighRisk) {
                $RiskFactors += "Legacy Application"
            }
            
            # Determine overall risk level
            if ($Permission.IsHighRisk -and $Permission.PermissionType -eq "Application") {
                $Permission.RiskLevel = "Critical"
                $CriticalCount++
            } elseif ($Permission.IsHighRisk -or ($RiskFactors.Count -ge 3)) {
                $Permission.RiskLevel = "High"
                $HighCount++
            } elseif ($RiskFactors.Count -ge 2) {
                $Permission.RiskLevel = "Medium"
                $MediumCount++
            } else {
                $Permission.RiskLevel = "Low"
                $LowCount++
            }
            
            $Permission | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue ($RiskFactors -join ", ") -Force
            $Permission | Add-Member -NotePropertyName "ApplicationAge" -NotePropertyValue $ApplicationAge -Force
        }
        
        Write-Host "✓ Risk assessment completed:" -ForegroundColor Green
        Write-Host "  Critical: $CriticalCount" -ForegroundColor Red
        Write-Host "  High: $HighCount" -ForegroundColor Yellow
        Write-Host "  Medium: $MediumCount" -ForegroundColor Yellow
        Write-Host "  Low: $LowCount" -ForegroundColor Green
        
        return $PermissionData
        
    } catch {
        Write-Error "Failed to analyze permission risks: $($_.Exception.Message)"
        throw
    }
}

function Get-PermissionUsagePatterns {
    param([array]$PermissionData)
    
    if (-not $AnalyzePermissionTrends) {
        Write-Host "Skipping permission usage analysis (disabled)" -ForegroundColor Gray
        return $PermissionData
    }
    
    try {
        Write-Host "Analyzing permission usage patterns..." -ForegroundColor Yellow
        
        $StartDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $UniqueAppIds = $PermissionData | Select-Object -ExpandProperty ApplicationId -Unique
        
        $UsageData = @{}
        $ProcessedApps = 0
        
        foreach ($AppId in $UniqueAppIds) {
            $ProcessedApps++
            
            if ($ProcessedApps % 10 -eq 0) {
                Write-Host "Analyzed usage for $ProcessedApps/$($UniqueAppIds.Count) applications..." -ForegroundColor Gray
            }
            
            try {
                # Check for recent sign-ins
                $SignInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=appId eq '$AppId' and createdDateTime ge $StartDate&`$top=1&`$orderby=createdDateTime desc"
                $SignInResponse = Invoke-MgGraphRequest -Method GET -Uri $SignInUri -ErrorAction SilentlyContinue
                
                if ($SignInResponse.value -and $SignInResponse.value.Count -gt 0) {
                    $LastSignIn = [DateTime]::Parse($SignInResponse.value[0].createdDateTime)
                    $UsageData[$AppId] = @{
                        LastUsed = $LastSignIn
                        IsActive = $true
                    }
                } else {
                    $UsageData[$AppId] = @{
                        LastUsed = $null
                        IsActive = $false
                    }
                }
            } catch {
                Write-Verbose "Could not retrieve usage data for AppId: $AppId"
                $UsageData[$AppId] = @{
                    LastUsed = $null
                    IsActive = $false
                }
            }
        }
        
        # Update permission data with usage information
        foreach ($Permission in $PermissionData) {
            if ($UsageData.ContainsKey($Permission.ApplicationId)) {
                $Permission | Add-Member -NotePropertyName "LastUsed" -NotePropertyValue $UsageData[$Permission.ApplicationId].LastUsed -Force
                $Permission | Add-Member -NotePropertyName "IsActiveApplication" -NotePropertyValue $UsageData[$Permission.ApplicationId].IsActive -Force
                
                # Increase risk for unused applications with high-risk permissions
                if (-not $UsageData[$Permission.ApplicationId].IsActive -and $Permission.IsHighRisk) {
                    $CurrentRiskFactors = if ($Permission.RiskFactors) { $Permission.RiskFactors } else { "" }
                    $Permission.RiskFactors = if ($CurrentRiskFactors) { "$CurrentRiskFactors, Unused Application" } else { "Unused Application" }
                    
                    # Upgrade risk level for unused high-risk applications
                    if ($Permission.RiskLevel -eq "High") {
                        $Permission.RiskLevel = "Critical"
                    }
                }
            }
        }
        
        Write-Host "✓ Usage analysis completed for $($UsageData.Keys.Count) applications" -ForegroundColor Green
        return $PermissionData
        
    } catch {
        Write-Warning "Usage analysis failed: $($_.Exception.Message)"
        return $PermissionData
    }
}

function Export-PermissionReports {
    param([array]$PermissionData)
    
    try {
        Write-Host "Generating application permission reports..." -ForegroundColor Yellow
        
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        
        # Detailed Permission Report
        $DetailedReportPath = Join-Path $ReportPath "Application-Permissions-Detailed-$Timestamp.csv"
        $PermissionData | Export-Csv -Path $DetailedReportPath -NoTypeInformation
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $DetailedReportPath -BlobName "Application-Permissions-Detailed-$Timestamp.csv"
        }
        
        # Application Summary Report
        $SummaryData = $PermissionData | Group-Object ApplicationName | ForEach-Object {
            $Permissions = $_.Group
            $CriticalPermissions = @($Permissions | Where-Object { $_.RiskLevel -eq "Critical" })
            $HighRiskPermissions = @($Permissions | Where-Object { $_.RiskLevel -eq "High" })
            $ApplicationPermissions = @($Permissions | Where-Object { $_.PermissionType -eq "Application" })
            $DelegatedPermissions = @($Permissions | Where-Object { $_.PermissionType -eq "Delegated" })
            $AdminConsentRequired = @($Permissions | Where-Object { $_.RequiresAdminConsent })
            
            [PSCustomObject]@{
                ApplicationName = $_.Name
                ApplicationId = $Permissions[0].ApplicationId
                ServicePrincipalType = $Permissions[0].ServicePrincipalType
                CreatedDateTime = $Permissions[0].CreatedDateTime
                TotalPermissions = $Permissions.Count
                ApplicationPermissions = $ApplicationPermissions.Count
                DelegatedPermissions = $DelegatedPermissions.Count
                CriticalRiskPermissions = $CriticalPermissions.Count
                HighRiskPermissions = $HighRiskPermissions.Count
                AdminConsentRequired = $AdminConsentRequired.Count
                IsActiveApplication = if ($Permissions[0].PSObject.Properties.Name -contains 'IsActiveApplication') { $Permissions[0].IsActiveApplication } else { "Not Analyzed" }
                LastUsed = if ($Permissions[0].PSObject.Properties.Name -contains 'LastUsed') { $Permissions[0].LastUsed } else { "Not Analyzed" }
                ApplicationAge = if ($Permissions[0].PSObject.Properties.Name -contains 'ApplicationAge') { $Permissions[0].ApplicationAge } else { $null }
                RecommendedAction = if ($CriticalPermissions.Count -gt 0) { "Immediate Review Required" }
                                  elseif ($HighRiskPermissions.Count -gt 0) { "Security Review Required" }
                                  elseif ($AdminConsentRequired.Count -gt 5) { "Permission Audit Required" }
                                  else { "Monitor" }
                HighRiskPermissionsList = ($Permissions | Where-Object { $_.IsHighRisk } | Select-Object -ExpandProperty Permission | Sort-Object -Unique) -join "; "
            }
        }
        
        $SummaryReportPath = Join-Path $ReportPath "Application-Summary-$Timestamp.csv"
        $SummaryData | Export-Csv -Path $SummaryReportPath -NoTypeInformation
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $SummaryReportPath -BlobName "Application-Summary-$Timestamp.csv"
        }
        
        # High-Risk Permissions Report
        $HighRiskData = $PermissionData | Where-Object { $_.IsHighRisk -or $_.RiskLevel -in @("Critical", "High") } | 
            Sort-Object RiskLevel, ApplicationName
        
        $HighRiskReportPath = Join-Path $ReportPath "High-Risk-Permissions-$Timestamp.csv"
        $HighRiskData | Export-Csv -Path $HighRiskReportPath -NoTypeInformation
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $HighRiskReportPath -BlobName "High-Risk-Permissions-$Timestamp.csv"
        }
        
        # Executive Summary
        $ExecutiveSummaryData = @{
            TotalApplications = ($PermissionData | Select-Object -ExpandProperty ApplicationName -Unique).Count
            TotalPermissions = $PermissionData.Count
            CriticalRiskPermissions = @($PermissionData | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            HighRiskPermissions = @($PermissionData | Where-Object { $_.RiskLevel -eq "High" }).Count
            MediumRiskPermissions = @($PermissionData | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            LowRiskPermissions = @($PermissionData | Where-Object { $_.RiskLevel -eq "Low" }).Count
            ApplicationPermissions = @($PermissionData | Where-Object { $_.PermissionType -eq "Application" }).Count
            DelegatedPermissions = @($PermissionData | Where-Object { $_.PermissionType -eq "Delegated" }).Count
            AdminConsentRequiredPermissions = @($PermissionData | Where-Object { $_.RequiresAdminConsent }).Count
            MicrosoftGraphPermissions = @($PermissionData | Where-Object { $_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000" }).Count
            TopHighRiskPermissions = ($PermissionData | Where-Object { $_.IsHighRisk } | Group-Object Permission | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join "; "
            TopApplicationsByPermissions = ($SummaryData | Sort-Object TotalPermissions -Descending | Select-Object -First 5 | ForEach-Object { "$($_.ApplicationName) ($($_.TotalPermissions))" }) -join "; "
            ReportTimestamp = $Timestamp
        }
        
        $ExecutiveSummaryPath = Join-Path $ReportPath "Permission-Audit-Executive-Summary-$Timestamp.json"
        $ExecutiveSummaryData | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExecutiveSummaryPath
        
        Write-Host "✓ Reports generated successfully:" -ForegroundColor Green
        Write-Host "  Detailed Report: $DetailedReportPath" -ForegroundColor Gray
        Write-Host "  Application Summary: $SummaryReportPath" -ForegroundColor Gray
        Write-Host "  High-Risk Permissions: $HighRiskReportPath" -ForegroundColor Gray
        Write-Host "  Executive Summary: $ExecutiveSummaryPath" -ForegroundColor Gray
        
        return @{
            DetailedReport = $DetailedReportPath
            SummaryReport = $SummaryReportPath
            HighRiskReport = $HighRiskReportPath
            ExecutiveSummary = $ExecutiveSummaryPath
            ExecutiveSummaryData = $ExecutiveSummaryData
        }
        
    } catch {
        Write-Error "Failed to generate reports: $($_.Exception.Message)"
        throw
    }
}

function Send-HighRiskPermissionAlert {
    param(
        [array]$HighRiskApplications,
        [string[]]$SecurityTeamEmails,
        [string[]]$ITAdminEmails
    )
    
    try {
        # Calculate metrics for the email
        $TotalApplications = $HighRiskApplications.Count
        $CriticalPermissions = @($HighRiskApplications | Where-Object { $_.CriticalRiskPermissions -gt 0 })
        $HighRiskPermissions = @($HighRiskApplications | Where-Object { $_.HighRiskPermissions -gt 0 })
        
        $TotalPermissions = ($HighRiskApplications | Measure-Object -Property TotalPermissions -Sum).Sum
        $CriticalRiskCount = ($HighRiskApplications | Measure-Object -Property CriticalRiskPermissions -Sum).Sum
        $HighRiskCount = ($HighRiskApplications | Measure-Object -Property HighRiskPermissions -Sum).Sum
        $ApplicationPermissions = ($HighRiskApplications | Measure-Object -Property ApplicationPermissions -Sum).Sum
        $AdminConsentRequired = ($HighRiskApplications | Measure-Object -Property AdminConsentRequired -Sum).Sum
        
        # Build table rows for critical permissions
        $CriticalRows = ""
        foreach ($App in $CriticalPermissions) {
            $CriticalRows += @"
                <tr>
                    <td class="app-name">$($App.ApplicationName)</td>
                    <td class="permission-name">High-Risk Permissions</td>
                    <td><span class="permission-type-app">Application</span></td>
                    <td><span class="risk-critical">CRITICAL</span></td>
                    <td>Microsoft Graph</td>
                    <td class="risk-factors">$($App.CriticalRiskPermissions) critical permissions</td>
                </tr>
"@
        }
        
        # Build table rows for high risk permissions
        $HighRiskRows = ""
        foreach ($App in $HighRiskPermissions) {
            $HighRiskRows += @"
                <tr>
                    <td class="app-name">$($App.ApplicationName)</td>
                    <td class="permission-name">Elevated Permissions</td>
                    <td><span class="permission-type-app">Application</span></td>
                    <td><span class="risk-high">HIGH</span></td>
                    <td>Microsoft Graph</td>
                    <td class="risk-factors">$($App.HighRiskPermissions) high-risk permissions</td>
                </tr>
"@
        }
        
        # Create the HTML email template (embedded)
        $HtmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>High-Risk Application Permission Alert</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; background-color: #f8f9fa; }
        .container { background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #e91e63 0%, #f44336 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; margin: -40px -40px 40px -40px; text-align: center; }
        .header h1 { margin: 0 0 10px 0; font-size: 28px; font-weight: 600; }
        .alert-icon { font-size: 48px; margin-bottom: 15px; }
        .severity-critical { background-color: #ffebee; border-left: 5px solid #d32f2f; padding: 20px; margin: 25px 0; border-radius: 4px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric-card { background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #dee2e6; }
        .metric-number { font-size: 32px; font-weight: 700; margin-bottom: 8px; }
        .metric-label { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
        .metric-critical { color: #d32f2f; }
        .metric-high { color: #ff9800; }
        .metric-info { color: #1976d2; }
        .permission-table { width: 100%; border-collapse: collapse; margin: 25px 0; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .permission-table th { background: linear-gradient(135deg, #37474f 0%, #455a64 100%); color: white; padding: 15px 12px; text-align: left; font-weight: 600; font-size: 13px; }
        .permission-table td { padding: 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px; }
        .risk-critical { background-color: #ffcdd2; color: #c62828; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
        .risk-high { background-color: #ffe0b2; color: #e65100; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
        .permission-type-app { background-color: #ffebee; color: #d32f2f; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
        .app-name { font-weight: 600; color: #1976d2; }
        .permission-name { font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-size: 11px; }
        .footer { margin-top: 40px; padding-top: 25px; border-top: 2px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="alert-icon">🛡️</div>
            <h1>Application Permission Security Alert</h1>
            <p>High-Risk Permissions Detected - Security Review Required</p>
        </div>

        <div class="severity-critical">
            <h3>🔴 CRITICAL SECURITY FINDINGS</h3>
            <p><strong>$CriticalRiskCount</strong> application permissions require immediate security review.</p>
            <p><strong>Primary Concerns:</strong> Over-privileged applications, unused apps with dangerous permissions, admin consent violations</p>
        </div>

        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-number metric-info">$TotalApplications</div>
                <div class="metric-label">Total Applications</div>
            </div>
            <div class="metric-card">
                <div class="metric-number metric-info">$TotalPermissions</div>
                <div class="metric-label">Total Permissions</div>
            </div>
            <div class="metric-card">
                <div class="metric-number metric-critical">$CriticalRiskCount</div>
                <div class="metric-label">Critical Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-number metric-high">$HighRiskCount</div>
                <div class="metric-label">High Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-number metric-high">$ApplicationPermissions</div>
                <div class="metric-label">App Permissions</div>
            </div>
            <div class="metric-card">
                <div class="metric-number metric-info">$AdminConsentRequired</div>
                <div class="metric-label">Admin Consent Req.</div>
            </div>
        </div>

        <h3>🚨 Critical Risk Permissions</h3>
        <table class="permission-table">
            <thead>
                <tr>
                    <th>Application</th>
                    <th>Permission</th>
                    <th>Type</th>
                    <th>Risk Level</th>
                    <th>Resource API</th>
                    <th>Risk Factors</th>
                </tr>
            </thead>
            <tbody>
                $CriticalRows
            </tbody>
        </table>

        <h3>⚠️ High Risk Permissions</h3>
        <table class="permission-table">
            <thead>
                <tr>
                    <th>Application</th>
                    <th>Permission</th>
                    <th>Type</th>
                    <th>Risk Level</th>
                    <th>Resource API</th>
                    <th>Risk Factors</th>
                </tr>
            </thead>
            <tbody>
                $HighRiskRows
            </tbody>
        </table>

        <div class="footer">
            <p>This alert was generated by the Enterprise Application Permission Auditor</p>
            <p>Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>For questions about this alert, contact the IT Security Team</p>
        </div>
    </div>
</body>
</html>
"@
        
        # Send email to all recipients
        $AllRecipients = @()
        $AllRecipients += $SecurityTeamEmails
        $AllRecipients += $ITAdminEmails
        
        foreach ($RecipientEmail in $AllRecipients) {
            $EmailMessage = @{
                Message = @{
                    Subject = "🚨 SECURITY ALERT: High-Risk Application Permissions Detected"
                    Body = @{
                        ContentType = "HTML"
                        Content = $HtmlTemplate
                    }
                    ToRecipients = @(
                        @{
                            EmailAddress = @{
                                Address = $RecipientEmail
                            }
                        }
                    )
                }
                SaveToSentItems = $true
            }
            
            try {
                $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson
                Write-Host "  ✓ Alert sent to $RecipientEmail" -ForegroundColor Green
            }
            catch {
                Write-Warning "  ⚠ Failed to send alert to $RecipientEmail`: $_"
            }
        }
        
    } catch {
        Write-Warning "Failed to send permission alerts: $_"
    }
}

# Main execution
try {
    Connect-ToMicrosoftGraph
    
    $PermissionData = Get-ApplicationPermissionData
    $PermissionData = Set-PermissionRiskLevels -PermissionData $PermissionData
    $PermissionData = Get-PermissionUsagePatterns -PermissionData $PermissionData
    
    $Reports = Export-PermissionReports -PermissionData $PermissionData
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Application Permission Audit Complete" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $ExecutiveData = $Reports.ExecutiveSummaryData
    Write-Host "📊 Executive Summary:" -ForegroundColor Cyan
    Write-Host "  Total Applications: $($ExecutiveData.TotalApplications)" -ForegroundColor White
    Write-Host "  Total Permissions: $($ExecutiveData.TotalPermissions)" -ForegroundColor White
    Write-Host "  Critical Risk: $($ExecutiveData.CriticalRiskPermissions)" -ForegroundColor Red
    Write-Host "  High Risk: $($ExecutiveData.HighRiskPermissions)" -ForegroundColor Yellow
    Write-Host "  Application Permissions: $($ExecutiveData.ApplicationPermissions)" -ForegroundColor Yellow
    Write-Host "  Admin Consent Required: $($ExecutiveData.AdminConsentRequiredPermissions)" -ForegroundColor Yellow
    Write-Host "  Microsoft Graph Permissions: $($ExecutiveData.MicrosoftGraphPermissions)" -ForegroundColor White
    
    if ($ExecutiveData.CriticalRiskPermissions -gt 0) {
        Write-Host "`n🚨 CRITICAL: Immediate security review required for $($ExecutiveData.CriticalRiskPermissions) permissions!" -ForegroundColor Red
    } elseif ($ExecutiveData.HighRiskPermissions -gt 0) {
        Write-Host "`n⚠️ WARNING: Security review recommended for $($ExecutiveData.HighRiskPermissions) high-risk permissions" -ForegroundColor Yellow
    } else {
        Write-Host "`n✅ No critical security issues found in application permissions" -ForegroundColor Green
    }
    
    Write-Host "`n📁 Reports generated in: $ReportPath" -ForegroundColor Gray
    
    if ($SendNotifications -and ($SecurityTeamEmails.Count -gt 0 -or $ITAdminEmails.Count -gt 0) -and $HighRiskApplications.Count -gt 0) {
        Write-Host "`n📧 Sending high-risk permission alerts..." -ForegroundColor Yellow
        Send-HighRiskPermissionAlert -HighRiskApplications $HighRiskApplications -SecurityTeamEmails $SecurityTeamEmails -ITAdminEmails $ITAdminEmails
    }
    
} catch {
    Write-Error "Application Permission Audit failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}