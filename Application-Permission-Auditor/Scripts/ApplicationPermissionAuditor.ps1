# ApplicationPermissionAuditor.ps1
# Enterprise Application Permission Audit and Compliance Automation
# Scans and analyzes Microsoft Graph API permissions across all Enterprise Applications

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeApplications = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Reports",
    
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

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Application Permission Auditor" -ForegroundColor Cyan
Write-Host "Enterprise Security & Compliance Automation" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Report Path: $ReportPath" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "Include OAuth Consents: $IncludeOAuthConsents" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

function Test-RequiredPermissions {
    try {
        Write-Host "Validating Microsoft Graph permissions..." -ForegroundColor Yellow
        
        $RequiredPermissions = @(
            "Application.Read.All",
            "Directory.Read.All",
            "DelegatedPermissionGrant.Read.All",
            "AppRoleAssignment.Read.All",
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
        
        if ($ClientId -and $TenantId -and $ClientSecret) {
            # PSScriptAnalyzer: ConvertTo-SecureString with -AsPlainText is required for authentication
            # This is a standard Microsoft Graph authentication pattern
            $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force  # nosemgrep
            $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
        } else {
            Connect-MgGraph -TenantId $TenantId -NoWelcome
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
        
        # High-Risk Permissions Report
        $HighRiskData = $PermissionData | Where-Object { $_.IsHighRisk -or $_.RiskLevel -in @("Critical", "High") } | 
            Sort-Object RiskLevel, ApplicationName
        
        $HighRiskReportPath = Join-Path $ReportPath "High-Risk-Permissions-$Timestamp.csv"
        $HighRiskData | Export-Csv -Path $HighRiskReportPath -NoTypeInformation
        
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
    
    if ($SendNotifications -and ($SecurityTeamEmails.Count -gt 0 -or $ITAdminEmails.Count -gt 0)) {
        Write-Host "`n📧 Sending notifications..." -ForegroundColor Yellow
        Write-Host "  (Notification functionality will be implemented in templates)" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Application Permission Audit failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}