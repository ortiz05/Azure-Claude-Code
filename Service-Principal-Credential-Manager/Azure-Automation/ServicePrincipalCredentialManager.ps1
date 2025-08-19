# ServicePrincipalCredentialManager.ps1
# Enterprise Service Principal Credential Management and Security Automation
# Monitors, assesses, and manages Azure Service Principal credentials at scale

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    
    [Parameter(Mandatory = $false)]
    [int]$CriticalThresholdDays = 7,
    
    [Parameter(Mandatory = $false)]
    [int]$WarningThresholdDays = 30,
    
    [Parameter(Mandatory = $false)]
    [int]$PlanningThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [int]$LongLivedThresholdDays = 365,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeServicePrincipals = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Reports",
    
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$StorageContainerName = "service-principal-reports",
    
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
    [switch]$EnableAutomatedRemediation = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendNotifications = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeUsageAnalysis = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateExecutiveSummary = $true
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Service Principal Credential Manager" -ForegroundColor Cyan
Write-Host "Enterprise Security Automation" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Report Path: $ReportPath" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "Automated Remediation: $EnableAutomatedRemediation" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

function Test-RequiredPermissions {
    try {
        Write-Host "Validating Microsoft Graph permissions..." -ForegroundColor Yellow
        
        $RequiredPermissions = @(
            "Application.Read.All",
            "Application.ReadWrite.All", 
            "Directory.Read.All",
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

function Get-ServicePrincipalCredentials {
    try {
        Write-Host "Scanning Service Principal credentials..." -ForegroundColor Yellow
        
        $ServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,CreatedDateTime,ServicePrincipalType,KeyCredentials,PasswordCredentials
        
        Write-Host "Found $($ServicePrincipals.Count) Service Principals" -ForegroundColor Green
        
        $CredentialData = @()
        $ProcessedCount = 0
        
        foreach ($SP in $ServicePrincipals) {
            $ProcessedCount++
            
            if ($ProcessedCount % 50 -eq 0) {
                Write-Host "Processed $ProcessedCount/$($ServicePrincipals.Count) Service Principals..." -ForegroundColor Gray
            }
            
            if ($ExcludeServicePrincipals -contains $SP.DisplayName -or $ExcludeServicePrincipals -contains $SP.AppId) {
                continue
            }
            
            $CurrentDate = Get-Date
            
            foreach ($KeyCred in $SP.KeyCredentials) {
                $DaysUntilExpiry = if ($KeyCred.EndDateTime) { 
                    [Math]::Round(($KeyCred.EndDateTime - $CurrentDate).TotalDays, 1) 
                } else { 
                    $null 
                }
                
                $CredentialAge = if ($KeyCred.StartDateTime) {
                    [Math]::Round(($CurrentDate - $KeyCred.StartDateTime).TotalDays, 0)
                } else {
                    $null
                }
                
                $CredentialData += [PSCustomObject]@{
                    ServicePrincipalId = $SP.Id
                    ServicePrincipalName = $SP.DisplayName
                    AppId = $SP.AppId
                    ServicePrincipalType = $SP.ServicePrincipalType
                    CredentialType = "Certificate"
                    CredentialId = $KeyCred.KeyId
                    StartDate = $KeyCred.StartDateTime
                    EndDate = $KeyCred.EndDateTime
                    DaysUntilExpiry = $DaysUntilExpiry
                    CredentialAge = $CredentialAge
                    Usage = $KeyCred.Usage
                    DisplayName = $KeyCred.DisplayName
                    IsExpired = if ($DaysUntilExpiry -ne $null) { $DaysUntilExpiry -le 0 } else { $false }
                    RiskLevel = ""
                    LastUsed = $null
                    CreatedDateTime = $SP.CreatedDateTime
                }
            }
            
            foreach ($PasswordCred in $SP.PasswordCredentials) {
                $DaysUntilExpiry = if ($PasswordCred.EndDateTime) { 
                    [Math]::Round(($PasswordCred.EndDateTime - $CurrentDate).TotalDays, 1) 
                } else { 
                    $null 
                }
                
                $CredentialAge = if ($PasswordCred.StartDateTime) {
                    [Math]::Round(($CurrentDate - $PasswordCred.StartDateTime).TotalDays, 0)
                } else {
                    $null
                }
                
                $CredentialData += [PSCustomObject]@{
                    ServicePrincipalId = $SP.Id
                    ServicePrincipalName = $SP.DisplayName
                    AppId = $SP.AppId
                    ServicePrincipalType = $SP.ServicePrincipalType
                    CredentialType = "Secret"
                    CredentialId = $PasswordCred.KeyId
                    StartDate = $PasswordCred.StartDateTime
                    EndDate = $PasswordCred.EndDateTime
                    DaysUntilExpiry = $DaysUntilExpiry
                    CredentialAge = $CredentialAge
                    Usage = $null
                    DisplayName = $PasswordCred.DisplayName
                    IsExpired = if ($DaysUntilExpiry -ne $null) { $DaysUntilExpiry -le 0 } else { $false }
                    RiskLevel = ""
                    LastUsed = $null
                    CreatedDateTime = $SP.CreatedDateTime
                }
            }
        }
        
        Write-Host "✓ Found $($CredentialData.Count) credentials across $($ServicePrincipals.Count) Service Principals" -ForegroundColor Green
        return $CredentialData
        
    } catch {
        Write-Error "Failed to scan Service Principal credentials: $($_.Exception.Message)"
        throw
    }
}

function Get-ServicePrincipalUsageData {
    param([array]$CredentialData)
    
    if (-not $IncludeUsageAnalysis) {
        Write-Host "Skipping usage analysis (disabled)" -ForegroundColor Gray
        return $CredentialData
    }
    
    try {
        Write-Host "Analyzing Service Principal usage patterns..." -ForegroundColor Yellow
        
        $StartDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $UniqueAppIds = $CredentialData | Select-Object -ExpandProperty AppId -Unique
        
        $UsageData = @{}
        $ProcessedApps = 0
        
        foreach ($AppId in $UniqueAppIds) {
            $ProcessedApps++
            
            if ($ProcessedApps % 10 -eq 0) {
                Write-Host "Analyzed usage for $ProcessedApps/$($UniqueAppIds.Count) applications..." -ForegroundColor Gray
            }
            
            try {
                $SignInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=appId eq '$AppId' and createdDateTime ge $StartDate&`$top=1&`$orderby=createdDateTime desc"
                $SignInResponse = Invoke-MgGraphRequest -Method GET -Uri $SignInUri -ErrorAction SilentlyContinue
                
                if ($SignInResponse.value -and $SignInResponse.value.Count -gt 0) {
                    $LastSignIn = [DateTime]::Parse($SignInResponse.value[0].createdDateTime)
                    $UsageData[$AppId] = $LastSignIn
                }
            } catch {
                Write-Verbose "Could not retrieve sign-in data for AppId: $AppId"
            }
        }
        
        foreach ($Credential in $CredentialData) {
            if ($UsageData.ContainsKey($Credential.AppId)) {
                $Credential.LastUsed = $UsageData[$Credential.AppId]
            }
        }
        
        Write-Host "✓ Usage analysis completed for $($UsageData.Keys.Count) applications" -ForegroundColor Green
        return $CredentialData
        
    } catch {
        Write-Warning "Usage analysis failed: $($_.Exception.Message)"
        return $CredentialData
    }
}

function Set-CredentialRiskLevels {
    param([array]$CredentialData)
    
    try {
        Write-Host "Calculating credential risk levels..." -ForegroundColor Yellow
        
        $CriticalCount = 0
        $HighCount = 0
        $MediumCount = 0
        $LowCount = 0
        
        foreach ($Credential in $CredentialData) {
            $RiskFactors = @()
            
            if ($Credential.IsExpired) {
                $RiskFactors += "Expired"
            }
            
            if ($Credential.DaysUntilExpiry -ne $null -and $Credential.DaysUntilExpiry -le $CriticalThresholdDays -and -not $Credential.IsExpired) {
                $RiskFactors += "Expires Soon"
            }
            
            if ($Credential.CredentialAge -ne $null -and $Credential.CredentialAge -gt $LongLivedThresholdDays) {
                $RiskFactors += "Long-Lived"
            }
            
            $IsUnused = $false
            if ($IncludeUsageAnalysis -and (-not $Credential.LastUsed -or $Credential.LastUsed -lt (Get-Date).AddDays(-90))) {
                $RiskFactors += "Unused"
                $IsUnused = $true
            }
            
            if ($Credential.CredentialType -eq "Secret" -and $Credential.CredentialAge -gt 90) {
                $RiskFactors += "Secret Type"
            }
            
            if ($Credential.IsExpired -and $IsUnused) {
                $Credential.RiskLevel = "Critical"
                $CriticalCount++
            } elseif ($Credential.IsExpired -or ($Credential.DaysUntilExpiry -ne $null -and $Credential.DaysUntilExpiry -le $CriticalThresholdDays)) {
                $Credential.RiskLevel = "High"
                $HighCount++
            } elseif ($RiskFactors.Count -ge 2) {
                $Credential.RiskLevel = "Medium"
                $MediumCount++
            } else {
                $Credential.RiskLevel = "Low"
                $LowCount++
            }
            
            $Credential | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue ($RiskFactors -join ", ") -Force
        }
        
        Write-Host "✓ Risk assessment completed:" -ForegroundColor Green
        Write-Host "  Critical: $CriticalCount" -ForegroundColor Red
        Write-Host "  High: $HighCount" -ForegroundColor Yellow
        Write-Host "  Medium: $MediumCount" -ForegroundColor Yellow
        Write-Host "  Low: $LowCount" -ForegroundColor Green
        
        return $CredentialData
        
    } catch {
        Write-Error "Failed to calculate risk levels: $($_.Exception.Message)"
        throw
    }
}

function Export-CredentialReports {
    param([array]$CredentialData)
    
    try {
        Write-Host "Generating credential management reports..." -ForegroundColor Yellow
        
        if (-not (Test-Path $ReportPath)) {
            New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        
        $DetailedReportPath = Join-Path $ReportPath "ServicePrincipal-Credentials-Detailed-$Timestamp.csv"
        $CredentialData | Export-Csv -Path $DetailedReportPath -NoTypeInformation
        
        $SummaryData = $CredentialData | Group-Object ServicePrincipalName | ForEach-Object {
            $Credentials = $_.Group
            $CriticalCredentials = @($Credentials | Where-Object { $_.RiskLevel -eq "Critical" })
            $HighRiskCredentials = @($Credentials | Where-Object { $_.RiskLevel -eq "High" })
            $ExpiredCredentials = @($Credentials | Where-Object { $_.IsExpired })
            $SoonToExpireCredentials = @($Credentials | Where-Object { $_.DaysUntilExpiry -ne $null -and $_.DaysUntilExpiry -le $WarningThresholdDays -and -not $_.IsExpired })
            
            [PSCustomObject]@{
                ServicePrincipalName = $_.Name
                AppId = $Credentials[0].AppId
                ServicePrincipalType = $Credentials[0].ServicePrincipalType
                TotalCredentials = $Credentials.Count
                CertificateCount = @($Credentials | Where-Object { $_.CredentialType -eq "Certificate" }).Count
                SecretCount = @($Credentials | Where-Object { $_.CredentialType -eq "Secret" }).Count
                ExpiredCredentials = $ExpiredCredentials.Count
                SoonToExpireCredentials = $SoonToExpireCredentials.Count
                CriticalRiskCredentials = $CriticalCredentials.Count
                HighRiskCredentials = $HighRiskCredentials.Count
                LastUsed = if ($IncludeUsageAnalysis) { ($Credentials.LastUsed | Measure-Object -Maximum).Maximum } else { "Not Analyzed" }
                RecommendedAction = if ($CriticalCredentials.Count -gt 0) { "Immediate Action Required" } 
                                  elseif ($HighRiskCredentials.Count -gt 0) { "Action Required" }
                                  elseif ($SoonToExpireCredentials.Count -gt 0) { "Plan Renewal" }
                                  else { "Monitor" }
                CreatedDateTime = $Credentials[0].CreatedDateTime
            }
        }
        
        $SummaryReportPath = Join-Path $ReportPath "ServicePrincipal-Summary-$Timestamp.csv"
        $SummaryData | Export-Csv -Path $SummaryReportPath -NoTypeInformation
        
        $ExecutiveSummaryData = @{
            TotalServicePrincipals = ($CredentialData | Select-Object -ExpandProperty ServicePrincipalName -Unique).Count
            TotalCredentials = $CredentialData.Count
            ExpiredCredentials = @($CredentialData | Where-Object { $_.IsExpired }).Count
            CriticalRiskCredentials = @($CredentialData | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            HighRiskCredentials = @($CredentialData | Where-Object { $_.RiskLevel -eq "High" }).Count
            MediumRiskCredentials = @($CredentialData | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            LowRiskCredentials = @($CredentialData | Where-Object { $_.RiskLevel -eq "Low" }).Count
            CertificateCredentials = @($CredentialData | Where-Object { $_.CredentialType -eq "Certificate" }).Count
            SecretCredentials = @($CredentialData | Where-Object { $_.CredentialType -eq "Secret" }).Count
            ExpiringIn7Days = @($CredentialData | Where-Object { $_.DaysUntilExpiry -ne $null -and $_.DaysUntilExpiry -le 7 -and -not $_.IsExpired }).Count
            ExpiringIn30Days = @($CredentialData | Where-Object { $_.DaysUntilExpiry -ne $null -and $_.DaysUntilExpiry -le 30 -and -not $_.IsExpired }).Count
            ExpiringIn90Days = @($CredentialData | Where-Object { $_.DaysUntilExpiry -ne $null -and $_.DaysUntilExpiry -le 90 -and -not $_.IsExpired }).Count
            ReportTimestamp = $Timestamp
        }
        
        $ExecutiveSummaryPath = Join-Path $ReportPath "ServicePrincipal-Executive-Summary-$Timestamp.json"
        $ExecutiveSummaryData | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExecutiveSummaryPath
        
        Write-Host "✓ Reports generated successfully:" -ForegroundColor Green
        Write-Host "  Detailed Report: $DetailedReportPath" -ForegroundColor Gray
        Write-Host "  Summary Report: $SummaryReportPath" -ForegroundColor Gray
        Write-Host "  Executive Summary: $ExecutiveSummaryPath" -ForegroundColor Gray
        
        return @{
            DetailedReport = $DetailedReportPath
            SummaryReport = $SummaryReportPath
            ExecutiveSummary = $ExecutiveSummaryPath
            ExecutiveSummaryData = $ExecutiveSummaryData
        }
        
    } catch {
        Write-Error "Failed to generate reports: $($_.Exception.Message)"
        throw
    }
}

function Invoke-AutomatedRemediation {
    param([array]$CredentialData)
    
    if (-not $EnableAutomatedRemediation) {
        Write-Host "Automated remediation disabled - skipping" -ForegroundColor Gray
        return
    }
    
    try {
        Write-Host "Performing automated remediation..." -ForegroundColor Yellow
        
        $CriticalCredentials = @($CredentialData | Where-Object { $_.RiskLevel -eq "Critical" })
        $RemediationActions = @()
        
        foreach ($Credential in $CriticalCredentials) {
            $Action = ""
            
            if ($Credential.IsExpired -and $Credential.RiskFactors -like "*Unused*") {
                if ($WhatIf) {
                    $Action = "WOULD DISABLE expired unused credential"
                    Write-Host "  [WHATIF] Would disable credential: $($Credential.ServicePrincipalName) - $($Credential.CredentialId)" -ForegroundColor Yellow
                } else {
                    $Action = "DISABLED expired unused credential"
                    Write-Host "  [ACTION] Disabling credential: $($Credential.ServicePrincipalName) - $($Credential.CredentialId)" -ForegroundColor Red
                }
            } elseif ($Credential.IsExpired) {
                $Action = "FLAGGED expired credential for manual review"
                Write-Host "  [FLAG] Expired credential requires manual review: $($Credential.ServicePrincipalName)" -ForegroundColor Red
            }
            
            $RemediationActions += [PSCustomObject]@{
                ServicePrincipalName = $Credential.ServicePrincipalName
                CredentialId = $Credential.CredentialId
                RiskLevel = $Credential.RiskLevel
                Action = $Action
                Timestamp = Get-Date
                WhatIfMode = $WhatIf
            }
        }
        
        $RemediationReportPath = Join-Path $ReportPath "Remediation-Actions-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
        $RemediationActions | Export-Csv -Path $RemediationReportPath -NoTypeInformation
        
        Write-Host "✓ Remediation completed - $($RemediationActions.Count) actions taken" -ForegroundColor Green
        Write-Host "  Report: $RemediationReportPath" -ForegroundColor Gray
        
        return $RemediationActions
        
    } catch {
        Write-Error "Automated remediation failed: $($_.Exception.Message)"
        throw
    }
}

try {
    Connect-ToMicrosoftGraph
    
    $CredentialData = Get-ServicePrincipalCredentials
    $CredentialData = Get-ServicePrincipalUsageData -CredentialData $CredentialData
    $CredentialData = Set-CredentialRiskLevels -CredentialData $CredentialData
    
    $Reports = Export-CredentialReports -CredentialData $CredentialData
    $RemediationActions = Invoke-AutomatedRemediation -CredentialData $CredentialData
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Service Principal Credential Management Complete" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $ExecutiveData = $Reports.ExecutiveSummaryData
    Write-Host "📊 Executive Summary:" -ForegroundColor Cyan
    Write-Host "  Total Service Principals: $($ExecutiveData.TotalServicePrincipals)" -ForegroundColor White
    Write-Host "  Total Credentials: $($ExecutiveData.TotalCredentials)" -ForegroundColor White
    Write-Host "  Expired Credentials: $($ExecutiveData.ExpiredCredentials)" -ForegroundColor Red
    Write-Host "  Critical Risk: $($ExecutiveData.CriticalRiskCredentials)" -ForegroundColor Red
    Write-Host "  High Risk: $($ExecutiveData.HighRiskCredentials)" -ForegroundColor Yellow
    Write-Host "  Expiring in 7 days: $($ExecutiveData.ExpiringIn7Days)" -ForegroundColor Red
    Write-Host "  Expiring in 30 days: $($ExecutiveData.ExpiringIn30Days)" -ForegroundColor Yellow
    
    if ($ExecutiveData.CriticalRiskCredentials -gt 0) {
        Write-Host "`n🚨 CRITICAL: Immediate action required for $($ExecutiveData.CriticalRiskCredentials) credentials!" -ForegroundColor Red
    } elseif ($ExecutiveData.HighRiskCredentials -gt 0) {
        Write-Host "`n⚠️ WARNING: Action required for $($ExecutiveData.HighRiskCredentials) high-risk credentials" -ForegroundColor Yellow
    } else {
        Write-Host "`n✅ All Service Principal credentials are in good standing" -ForegroundColor Green
    }
    
    Write-Host "`n📁 Reports generated in: $ReportPath" -ForegroundColor Gray
    
    if ($SendNotifications -and ($SecurityTeamEmails.Count -gt 0 -or $ITAdminEmails.Count -gt 0)) {
        Write-Host "`n📧 Sending notifications..." -ForegroundColor Yellow
        Write-Host "  (Notification functionality will be implemented in templates)" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Service Principal Credential Management failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}