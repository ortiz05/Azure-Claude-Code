<#
.SYNOPSIS
    Azure Automation for monitoring Enterprise Application usage and identifying unused applications
    
.DESCRIPTION
    This script analyzes Azure AD sign-in logs to identify Enterprise Applications that haven't been
    used in the specified number of days (default: 90). It generates comprehensive reports and
    sends email notifications to IT administrators with recommendations for app cleanup.
    
.PARAMETER DaysUnused
    Number of days without usage to consider an app as unused (default: 90)
    
.PARAMETER WhatIf
    Run in simulation mode without sending emails
    
.PARAMETER ITAdminEmails
    Array of IT administrator email addresses for reports
    
.PARAMETER ExcludedApps
    Array of application IDs or display names to exclude from analysis
    
.PARAMETER ExportPath
    Path where CSV reports will be saved (DEPRECATED - use blob storage)
    
.PARAMETER StorageAccountName
    Azure Storage Account name for report storage (required for blob storage)
    
.PARAMETER StorageContainerName
    Azure Storage Container name for reports (default: app-usage-reports)
    
.PARAMETER UseManagedIdentity
    Use Azure Automation managed identity for authentication (recommended)
    
.PARAMETER IncludeActiveApps
    Include actively used applications in reports
    
.PARAMETER SendEmailReport
    Enable/disable email reports to administrators
    
.PARAMETER MinimumRiskThreshold
    Minimum number of unused apps to trigger high-priority alerts (default: 10)
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$DaysUnused = 90,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedApps = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\EnterpriseAppReports",
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageContainerName = "app-usage-reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseManagedIdentity = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeActiveApps = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmailReport = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MinimumRiskThreshold = 10
)

# Import required modules
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Reports -ErrorAction Stop

# Import Azure Storage modules for blob storage functionality
if ($StorageAccountName) {
    Import-Module Az.Storage -ErrorAction Stop
    Import-Module Az.Accounts -ErrorAction Stop
}

# Initialize tracking collections
$Script:UnusedApplications = [System.Collections.ArrayList]::new()
$Script:ActiveApplications = [System.Collections.ArrayList]::new()
$Script:ProcessingErrors = [System.Collections.ArrayList]::new()
$Script:HighRiskApplications = [System.Collections.ArrayList]::new()

#region Helper Functions

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
    [CmdletBinding()]
    param()
    
    Write-Output "Validating Graph API permissions..."
    
    $RequiredPermissions = @{
        "Application.Read.All" = $false
        "AuditLog.Read.All" = $false
        "Directory.Read.All" = $false
        "Mail.Send" = $false
    }
    
    $AllPermissionsValid = $true
    
    try {
        $Context = Get-MgContext
        if ($null -eq $Context) {
            Write-Error "Not connected to Microsoft Graph"
            return $false
        }
        
        $CurrentScopes = $Context.Scopes
        
        foreach ($Permission in $RequiredPermissions.Keys) {
            $HasPermission = $CurrentScopes -contains $Permission
            $RequiredPermissions[$Permission] = $HasPermission
            
            if ($HasPermission) {
                Write-Output "  ✓ $Permission - Granted"
            } else {
                Write-Warning "  ✗ $Permission - Missing or not granted"
                $AllPermissionsValid = $false
            }
        }
        
        return $AllPermissionsValid
    }
    catch {
        Write-Error "Permission validation failed: $_"
        return $false
    }
}

function Test-AppExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Application,
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExclusionList = @()
    )
    
    # Check if app should be excluded
    foreach ($Exclusion in $ExclusionList) {
        # Check by display name (case-insensitive partial match)
        if ($Application.DisplayName -like "*$Exclusion*") {
            return @{
                Excluded = $true
                Reason = "Display name matches exclusion pattern: $Exclusion"
            }
        }
        
        # Check by exact App ID
        if ($Application.AppId -eq $Exclusion) {
            return @{
                Excluded = $true
                Reason = "App ID matches exclusion list: $Exclusion"
            }
        }
        
        # Check by Object ID
        if ($Application.Id -eq $Exclusion) {
            return @{
                Excluded = $true
                Reason = "Object ID matches exclusion list: $Exclusion"
            }
        }
    }
    
    return @{
        Excluded = $false
        Reason = ""
    }
}

function Get-ApplicationRiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Application,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysUnused
    )
    
    $RiskFactors = @()
    $RiskScore = 0
    $RiskLevel = "Low"
    
    # Risk factor: High privilege permissions
    $HighPrivilegePermissions = @(
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "Application.ReadWrite.All",
        "Mail.ReadWrite",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All"
    )
    
    if ($Application.RequiredResourceAccess) {
        foreach ($ResourceAccess in $Application.RequiredResourceAccess) {
            foreach ($Permission in $ResourceAccess.ResourceAccess) {
                if ($Permission.Type -eq "Role") { # Application permissions
                    $RiskScore += 2
                    $RiskFactors += "Has application-level permissions"
                    break
                }
            }
        }
    }
    
    # Risk factor: Long unused period
    if ($DaysUnused -gt 180) {
        $RiskScore += 3
        $RiskFactors += "Unused for over 6 months"
    } elseif ($DaysUnused -gt 90) {
        $RiskScore += 2
        $RiskFactors += "Unused for over 3 months"
    }
    
    # Risk factor: External application
    if ($Application.PublisherDomain -and $Application.PublisherDomain -notlike "*microsoft.com*" -and $Application.PublisherDomain -notlike "*yourdomain.com*") {
        $RiskScore += 1
        $RiskFactors += "Third-party application"
    }
    
    # Risk factor: No recent certification
    if (-not $Application.Certification -or $Application.Certification.CertificationExpirationDateTime -lt (Get-Date).AddMonths(-12)) {
        $RiskScore += 1
        $RiskFactors += "No recent certification"
    }
    
    # Determine risk level
    if ($RiskScore -ge 5) {
        $RiskLevel = "High"
    } elseif ($RiskScore -ge 3) {
        $RiskLevel = "Medium"
    }
    
    return @{
        RiskLevel = $RiskLevel
        RiskScore = $RiskScore
        RiskFactors = $RiskFactors
    }
}

function Send-EnterpriseAppReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$AdminEmails,
        
        [Parameter(Mandatory=$true)]
        [array]$UnusedApps,
        
        [Parameter(Mandatory=$true)]
        [array]$ActiveApps,
        
        [Parameter(Mandatory=$true)]
        [array]$HighRiskApps,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysAnalyzed
    )
    
    $TotalApps = $UnusedApps.Count + $ActiveApps.Count
    $UsageRate = if ($TotalApps -gt 0) { 
        [math]::Round(($ActiveApps.Count / $TotalApps) * 100, 2) 
    } else { 100 }
    
    # Calculate potential cost savings (estimated)
    $EstimatedMonthlySavings = $UnusedApps.Count * 15 # Estimate $15/app/month
    $EstimatedAnnualSavings = $EstimatedMonthlySavings * 12
    
    # Generate top unused apps by risk
    $TopRiskApps = $UnusedApps | Sort-Object { $_.RiskAssessment.RiskScore } -Descending | Select-Object -First 10
    
    # Generate publisher analysis
    $PublisherAnalysis = $UnusedApps | Group-Object PublisherDomain | Sort-Object Count -Descending | Select-Object -First 5
    
    $EmailBody = @"
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #0078d4; }
        .summary-number { font-size: 24px; font-weight: bold; color: #0078d4; }
        .summary-label { color: #666; font-size: 14px; margin-top: 5px; }
        .alert-card { border-left-color: #dc3545; }
        .alert-number { color: #dc3545; }
        .success-card { border-left-color: #28a745; }
        .success-number { color: #28a745; }
        .warning-card { border-left-color: #ffc107; }
        .warning-number { color: #856404; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #f8f9fa; text-align: left; padding: 10px; border: 1px solid #dee2e6; font-weight: bold; }
        td { padding: 8px; border: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .section { margin: 30px 0; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; }
        .alert-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 15px; margin: 20px 0; }
        .recommendation { background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 4px; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 Enterprise Application Usage Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Analysis Period: Applications unused for $DaysAnalyzed+ days</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <div class="summary-number">$TotalApps</div>
            <div class="summary-label">Total Enterprise Apps</div>
        </div>
        <div class="summary-card alert-card">
            <div class="summary-number alert-number">$($UnusedApps.Count)</div>
            <div class="summary-label">Unused Applications</div>
        </div>
        <div class="summary-card success-card">
            <div class="summary-number success-number">$($ActiveApps.Count)</div>
            <div class="summary-label">Active Applications</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$UsageRate%</div>
            <div class="summary-label">Usage Rate</div>
        </div>
        <div class="summary-card warning-card">
            <div class="summary-number warning-number">$($HighRiskApps.Count)</div>
            <div class="summary-label">High Risk Apps</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$EstimatedAnnualSavings</div>
            <div class="summary-label">Est. Annual Savings</div>
        </div>
    </div>
    
    $(if ($UnusedApps.Count -gt $MinimumRiskThreshold) {
        @"
        <div class="alert-box">
            <strong>🚨 High Priority Alert:</strong> $($UnusedApps.Count) unused enterprise applications detected. 
            Immediate review recommended to reduce security exposure and licensing costs.
        </div>
"@
    })
    
    $(if ($TopRiskApps.Count -gt 0) {
        @"
        <div class="section">
            <h2>🎯 Top Priority Unused Applications</h2>
            <table>
                <thead>
                    <tr>
                        <th>Application Name</th>
                        <th>Publisher</th>
                        <th>Last Used</th>
                        <th>Days Unused</th>
                        <th>Risk Level</th>
                        <th>Risk Factors</th>
                    </tr>
                </thead>
                <tbody>
                    $(($TopRiskApps | ForEach-Object {
                        $RiskClass = switch ($_.RiskAssessment.RiskLevel) {
                            "High" { "risk-high" }
                            "Medium" { "risk-medium" }
                            default { "risk-low" }
                        }
                        "<tr>
                            <td><strong>$($_.DisplayName)</strong></td>
                            <td>$($_.PublisherDomain ?? 'Unknown')</td>
                            <td>$($_.LastSignInDate)</td>
                            <td>$($_.DaysUnused)</td>
                            <td class='$RiskClass'>$($_.RiskAssessment.RiskLevel)</td>
                            <td>$($_.RiskAssessment.RiskFactors -join '; ')</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($PublisherAnalysis.Count -gt 0) {
        @"
        <div class="section">
            <h2>📊 Unused Apps by Publisher</h2>
            <table>
                <thead>
                    <tr>
                        <th>Publisher Domain</th>
                        <th>Unused Apps Count</th>
                        <th>Percentage of Total</th>
                    </tr>
                </thead>
                <tbody>
                    $(($PublisherAnalysis | ForEach-Object {
                        $Percentage = [math]::Round(($_.Count / $UnusedApps.Count) * 100, 1)
                        "<tr>
                            <td>$($_.Name ?? 'Unknown')</td>
                            <td>$($_.Count)</td>
                            <td>$Percentage%</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    <div class="recommendation">
        <h2>💡 Recommended Actions</h2>
        <ol>
            $(if ($HighRiskApps.Count -gt 0) {
                "<li><strong>Immediate:</strong> Review and remove $($HighRiskApps.Count) high-risk unused applications</li>"
            })
            $(if ($UnusedApps.Count -gt 5) {
                "<li><strong>Short-term (1-2 weeks):</strong> Audit applications unused for 6+ months</li>"
            })
            <li><strong>Medium-term (1 month):</strong> Implement application lifecycle management policies</li>
            <li><strong>Long-term:</strong> Establish regular quarterly application usage reviews</li>
            $(if ($EstimatedAnnualSavings -gt 1000) {
                "<li><strong>Cost Optimization:</strong> Potential annual savings of $$EstimatedAnnualSavings through app cleanup</li>"
            })
        </ol>
    </div>
    
    <div class="section">
        <h2>🔒 Security Impact Analysis</h2>
        <ul>
            <li><strong>Attack Surface Reduction:</strong> Removing unused apps reduces potential entry points</li>
            <li><strong>Permission Cleanup:</strong> Eliminates unnecessary data access permissions</li>
            <li><strong>Compliance Improvement:</strong> Better alignment with least-privilege principles</li>
            <li><strong>Audit Efficiency:</strong> Simplified security reviews and compliance audits</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📋 Next Steps</h2>
        <ol>
            <li>Review the detailed CSV report for complete application inventory</li>
            <li>Validate applications with business stakeholders before removal</li>
            <li>Document business justification for retained applications</li>
            <li>Schedule regular application usage reviews (quarterly recommended)</li>
            <li>Update application governance policies based on findings</li>
        </ol>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #666;">
        <p><strong>Report Details:</strong></p>
        <ul>
            <li>Analysis covers enterprise applications registered in Azure AD</li>
            <li>Usage data based on sign-in logs from the last $DaysAnalyzed days</li>
            <li>Risk assessment includes permissions, publisher, and usage patterns</li>
            <li>Cost estimates are approximate and may vary based on licensing agreements</li>
        </ul>
        <p>This report was automatically generated by the Enterprise Application Usage Monitor.</p>
        <p>For questions or technical issues, contact the IT Security team.</p>
    </div>
</body>
</html>
"@
    
    foreach ($AdminEmail in $AdminEmails) {
        $Priority = if ($UnusedApps.Count -gt $MinimumRiskThreshold) { "High" } else { "Normal" }
        
        $EmailMessage = @{
            Message = @{
                Subject = "🏢 Enterprise App Usage Report - $($UnusedApps.Count) Unused Apps Found"
                Body = @{
                    ContentType = "HTML"
                    Content = $EmailBody
                }
                ToRecipients = @(
                    @{
                        EmailAddress = @{
                            Address = $AdminEmail
                        }
                    }
                )
                Importance = $Priority
            }
            SaveToSentItems = $true
        }
        
        try {
            if (-not $WhatIf) {
                $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10 -Compress
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson
                Write-Output "Enterprise app report sent to $AdminEmail"
            } else {
                Write-Output "[WhatIf] Would send enterprise app report to $AdminEmail"
            }
        }
        catch {
            Write-Warning "Failed to send report to $AdminEmail`: $_"
        }
    }
}

#endregion

#region Main Processing Functions

function Get-UnusedEnterpriseApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$DaysBack
    )
    
    Write-Output "Analyzing enterprise applications for the last $DaysBack days..."
    
    try {
        # Get all enterprise applications (service principals)
        Write-Output "Retrieving enterprise applications from Azure AD..."
        $AllServicePrincipals = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,CreatedDateTime,ServicePrincipalType,PublisherName,HomePage,ReplyUrls,Tags
        
        # Filter for enterprise applications (exclude Microsoft apps and managed identities)
        $EnterpriseApps = $AllServicePrincipals | Where-Object {
            $_.ServicePrincipalType -eq "Application" -and
            $_.AppId -ne "00000000-0000-0000-0000-000000000000" -and
            $_.PublisherName -ne "Microsoft Corporation"
        }
        
        Write-Output "Found $($EnterpriseApps.Count) enterprise applications to analyze"
        
        # Get sign-in logs for the specified period
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        $Filter = "createdDateTime ge $StartDate and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')"
        
        Write-Output "Retrieving sign-in logs from $StartDate..."
        $SignInLogs = @()
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$select=id,createdDateTime,appId,appDisplayName,userPrincipalName,clientAppUsed,deviceDetail,location&`$top=1000"
        
        do {
            $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri
            $SignInLogs += $Response.value
            $Uri = $Response.'@odata.nextLink'
            
            if ($SignInLogs.Count % 5000 -eq 0) {
                Write-Output "Retrieved $($SignInLogs.Count) sign-in records..."
            }
        } while ($Uri)
        
        Write-Output "Total sign-in records retrieved: $($SignInLogs.Count)"
        
        # Create lookup table for sign-in activity
        $AppUsageMap = @{}
        foreach ($SignIn in $SignInLogs) {
            if ($SignIn.appId -and $SignIn.appId -ne "00000000-0000-0000-0000-000000000000") {
                if (-not $AppUsageMap.ContainsKey($SignIn.appId)) {
                    $AppUsageMap[$SignIn.appId] = @{
                        LastSignIn = $SignIn.createdDateTime
                        TotalSignIns = 1
                        UniqueUsers = @($SignIn.userPrincipalName)
                        ClientApps = @($SignIn.clientAppUsed)
                        Locations = @()
                    }
                } else {
                    $AppUsageMap[$SignIn.appId].TotalSignIns++
                    if ($SignIn.userPrincipalName -notin $AppUsageMap[$SignIn.appId].UniqueUsers) {
                        $AppUsageMap[$SignIn.appId].UniqueUsers += $SignIn.userPrincipalName
                    }
                    if ($SignIn.clientAppUsed -notin $AppUsageMap[$SignIn.appId].ClientApps) {
                        $AppUsageMap[$SignIn.appId].ClientApps += $SignIn.clientAppUsed
                    }
                    
                    # Keep the most recent sign-in
                    if ([DateTime]$SignIn.createdDateTime -gt [DateTime]$AppUsageMap[$SignIn.appId].LastSignIn) {
                        $AppUsageMap[$SignIn.appId].LastSignIn = $SignIn.createdDateTime
                    }
                }
                
                # Add location if available
                if ($SignIn.location -and $SignIn.location.city) {
                    $LocationString = "$($SignIn.location.city), $($SignIn.location.countryOrRegion)"
                    if ($LocationString -notin $AppUsageMap[$SignIn.appId].Locations) {
                        $AppUsageMap[$SignIn.appId].Locations += $LocationString
                    }
                }
            }
        }
        
        # Analyze each enterprise application
        foreach ($App in $EnterpriseApps) {
            try {
                # Check exclusions
                $ExclusionCheck = Test-AppExclusion -Application $App -ExclusionList $ExcludedApps
                
                if ($ExclusionCheck.Excluded) {
                    Write-Verbose "Excluding application: $($App.DisplayName) - Reason: $($ExclusionCheck.Reason)"
                    continue
                }
                
                # Get additional app details
                $ApplicationDetails = $null
                try {
                    $ApplicationDetails = Get-MgApplication -Filter "appId eq '$($App.AppId)'" -Property Id,DisplayName,PublisherDomain,Certification,CreatedDateTime,RequiredResourceAccess -ErrorAction SilentlyContinue
                } catch {
                    Write-Verbose "Could not retrieve application details for $($App.DisplayName)"
                }
                
                $LastSignInDate = "Never"
                $DaysUnused = 999
                $TotalSignIns = 0
                $UniqueUsers = 0
                $ClientApps = @()
                $Locations = @()
                $UsageStatus = "Unused"
                
                if ($AppUsageMap.ContainsKey($App.AppId)) {
                    $UsageData = $AppUsageMap[$App.AppId]
                    $LastSignInDate = ([DateTime]$UsageData.LastSignIn).ToString("yyyy-MM-dd HH:mm:ss")
                    $DaysUnused = (New-TimeSpan -Start ([DateTime]$UsageData.LastSignIn) -End (Get-Date)).Days
                    $TotalSignIns = $UsageData.TotalSignIns
                    $UniqueUsers = $UsageData.UniqueUsers.Count
                    $ClientApps = $UsageData.ClientApps
                    $Locations = $UsageData.Locations
                    $UsageStatus = "Active"
                } else {
                    # Check if app was created within the analysis period
                    $AppAge = (New-TimeSpan -Start $App.CreatedDateTime -End (Get-Date)).Days
                    if ($AppAge -lt $DaysBack) {
                        $DaysUnused = $AppAge
                        $UsageStatus = "New - No Usage"
                    }
                }
                
                # Perform risk assessment
                $RiskAssessment = Get-ApplicationRiskAssessment -Application ($ApplicationDetails ?? $App) -DaysUnused $DaysUnused
                
                # Create application record
                $AppRecord = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    DisplayName = $App.DisplayName
                    AppId = $App.AppId
                    ObjectId = $App.Id
                    PublisherName = $App.PublisherName ?? "Unknown"
                    PublisherDomain = $ApplicationDetails.PublisherDomain ?? "Unknown"
                    CreatedDate = $App.CreatedDateTime.ToString("yyyy-MM-dd")
                    LastSignInDate = $LastSignInDate
                    DaysUnused = $DaysUnused
                    UsageStatus = $UsageStatus
                    TotalSignIns = $TotalSignIns
                    UniqueUsers = $UniqueUsers
                    ClientAppsUsed = ($ClientApps -join "; ")
                    LocationsUsed = ($Locations -join "; ")
                    ServicePrincipalType = $App.ServicePrincipalType
                    HomePage = $App.HomePage ?? ""
                    Tags = ($App.Tags -join "; ")
                    RiskLevel = $RiskAssessment.RiskLevel
                    RiskScore = $RiskAssessment.RiskScore
                    RiskFactors = ($RiskAssessment.RiskFactors -join "; ")
                    HasCertification = ($ApplicationDetails.Certification -ne $null)
                    RequiredPermissions = if ($ApplicationDetails.RequiredResourceAccess) { 
                        ($ApplicationDetails.RequiredResourceAccess | ConvertTo-Json -Compress) 
                    } else { "" }
                }
                
                # Add risk assessment for unused apps analysis
                $AppRecord | Add-Member -NotePropertyName "RiskAssessment" -NotePropertyValue $RiskAssessment
                
                if ($UsageStatus -eq "Active") {
                    [void]$Script:ActiveApplications.Add($AppRecord)
                    Write-Verbose "✓ Active application: $($App.DisplayName) - Last used: $LastSignInDate"
                } else {
                    [void]$Script:UnusedApplications.Add($AppRecord)
                    Write-Output "  ⚠ Unused application: $($App.DisplayName) - Unused for $DaysUnused days - Risk: $($RiskAssessment.RiskLevel)"
                    
                    # Track high-risk applications
                    if ($RiskAssessment.RiskLevel -eq "High") {
                        [void]$Script:HighRiskApplications.Add($AppRecord)
                    }
                }
            }
            catch {
                Write-Warning "Error processing application $($App.DisplayName): $_"
                [void]$Script:ProcessingErrors.Add(@{
                    Application = $App.DisplayName
                    AppId = $App.AppId
                    Error = $_.Exception.Message
                    Timestamp = Get-Date
                })
            }
        }
        
        Write-Output "Analysis complete:"
        Write-Output "  Total enterprise applications: $($EnterpriseApps.Count)"
        Write-Output "  Unused applications: $($Script:UnusedApplications.Count)"
        Write-Output "  Active applications: $($Script:ActiveApplications.Count)"
        Write-Output "  High-risk unused applications: $($Script:HighRiskApplications.Count)"
        Write-Output "  Processing errors: $($Script:ProcessingErrors.Count)"
    }
    catch {
        Write-Error "Failed to analyze enterprise applications: $_"
        throw
    }
}

#endregion

#region Main Execution

Write-Output "========================================="
Write-Output "Enterprise Application Usage Monitor"
Write-Output "========================================="
Write-Output "Analysis Period: Last $DaysUnused days"
Write-Output "WhatIf Mode: $($WhatIf.IsPresent)"
Write-Output "Email Reports: $($SendEmailReport.IsPresent)"
Write-Output "Include Active Apps: $($IncludeActiveApps.IsPresent)"
Write-Output "Export Path: $ExportPath"
if ($StorageAccountName) {
    Write-Output "Blob Storage: $StorageAccountName/$StorageContainerName"
}
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "========================================="

# Ensure export directory exists
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

try {
    # Connect to Microsoft Graph
    Write-Output "`nConnecting to Microsoft Graph..."
    
    $Context = Get-MgContext
    if ($null -eq $Context) {
        if ($UseManagedIdentity -or $StorageAccountName) {
            # Use Managed Identity for authentication (required for blob storage)
            Write-Output "Connecting with Azure Automation Managed Identity..."
            Connect-MgGraph -Identity -NoWelcome
            
            # Also connect to Azure for storage operations if needed
            if ($StorageAccountName) {
                Write-Output "Connecting to Azure for storage operations..."
                Connect-AzAccount -Identity
            }
        }
        else {
            # Fallback authentication (not recommended for production)
            Write-Warning "Using fallback authentication. For production, use managed identity."
            Connect-MgGraph -Scopes "Application.Read.All","AuditLog.Read.All","Directory.Read.All","Mail.Send" -NoWelcome
        }
    }
    
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }
    Write-Output "Successfully connected to tenant: $($Context.TenantId)"
    
    # Validate permissions - FAIL FAST for security
    Write-Output "`n--- Validating Permissions ---"
    $PermissionsValid = Test-RequiredPermissions
    if (-not $PermissionsValid) {
        $RequiredPermissions = @("Application.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Mail.Send")
        $ErrorMessage = @"
CRITICAL ERROR: Missing required Microsoft Graph permissions.

Required permissions:
$(($RequiredPermissions | ForEach-Object { "  - $_" }) -join "`n")

To fix this:
1. Go to Azure Portal → App Registrations → [Your App]
2. Navigate to API Permissions  
3. Add the missing Microsoft Graph permissions (Application type)
4. Click 'Grant admin consent'
5. Re-run this script

Cannot proceed safely without proper permissions.
"@
        Write-Error $ErrorMessage
        throw "Missing required Microsoft Graph permissions. Cannot continue safely."
    }
    
    # Analyze enterprise application usage
    Write-Output "`n--- Analyzing Enterprise Application Usage ---"
    Get-UnusedEnterpriseApplications -DaysBack $DaysUnused
    
    # Generate CSV Reports
    Write-Output "`n--- Generating CSV Reports ---"
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export unused applications
    if ($Script:UnusedApplications.Count -gt 0) {
        $UnusedFile = Join-Path $ExportPath "UnusedEnterpriseApps_$Timestamp.csv"
        $Script:UnusedApplications | Export-Csv -Path $UnusedFile -NoTypeInformation -Encoding UTF8
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $UnusedFile -BlobName "UnusedApplications_$Timestamp.csv"
        }
        Write-Output "Unused applications report: $UnusedFile"
    }
    
    # Export active applications (if requested)
    if ($IncludeActiveApps -and $Script:ActiveApplications.Count -gt 0) {
        $ActiveFile = Join-Path $ExportPath "ActiveEnterpriseApps_$Timestamp.csv"
        $Script:ActiveApplications | Export-Csv -Path $ActiveFile -NoTypeInformation -Encoding UTF8
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $ActiveFile -BlobName "ActiveApplications_$Timestamp.csv"
        }
        Write-Output "Active applications report: $ActiveFile"
    }
    
    # Export high-risk applications
    if ($Script:HighRiskApplications.Count -gt 0) {
        $HighRiskFile = Join-Path $ExportPath "HighRiskUnusedApps_$Timestamp.csv"
        $Script:HighRiskApplications | Export-Csv -Path $HighRiskFile -NoTypeInformation -Encoding UTF8
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $HighRiskFile -BlobName "HighRiskApplications_$Timestamp.csv"
        }
        Write-Output "High-risk applications report: $HighRiskFile"
    }
    
    # Export processing errors
    if ($Script:ProcessingErrors.Count -gt 0) {
        $ErrorFile = Join-Path $ExportPath "ProcessingErrors_$Timestamp.csv"
        $Script:ProcessingErrors | Export-Csv -Path $ErrorFile -NoTypeInformation -Encoding UTF8
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $ErrorFile -BlobName "ProcessingErrors_$Timestamp.csv"
        }
        Write-Output "Processing errors report: $ErrorFile"
    }
    
    # Generate summary CSV
    $SummaryData = @(
        [PSCustomObject]@{
            RunDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Mode = if ($WhatIf) { "Simulation (WhatIf)" } else { "Production" }
            DaysAnalyzed = $DaysUnused
            TotalEnterpriseApps = $Script:UnusedApplications.Count + $Script:ActiveApplications.Count
            UnusedApplications = $Script:UnusedApplications.Count
            ActiveApplications = $Script:ActiveApplications.Count
            HighRiskUnusedApps = $Script:HighRiskApplications.Count
            UsageRate = if (($Script:UnusedApplications.Count + $Script:ActiveApplications.Count) -gt 0) { 
                [math]::Round(($Script:ActiveApplications.Count / ($Script:UnusedApplications.Count + $Script:ActiveApplications.Count)) * 100, 2) 
            } else { 100 }
            ProcessingErrors = $Script:ProcessingErrors.Count
            EmailReportsEnabled = $SendEmailReport
            EstimatedMonthlySavings = $Script:UnusedApplications.Count * 15
            EstimatedAnnualSavings = $Script:UnusedApplications.Count * 15 * 12
        }
    )
    
    $SummaryFile = Join-Path $ExportPath "EnterpriseAppSummary_$Timestamp.csv"
    $SummaryData | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
    
    # Upload summary to blob storage if configured
    if ($StorageAccountName) {
        Export-ToBlob -FilePath $SummaryFile -BlobName "UsageMonitorSummary_$Timestamp.csv"
    }
    Write-Output "Summary report: $SummaryFile"
    
    # Send email report to administrators
    if ($SendEmailReport -and $ITAdminEmails.Count -gt 0) {
        Write-Output "`n--- Sending Email Report ---"
        Send-EnterpriseAppReport `
            -AdminEmails $ITAdminEmails `
            -UnusedApps $Script:UnusedApplications `
            -ActiveApps $Script:ActiveApplications `
            -HighRiskApps $Script:HighRiskApplications `
            -DaysAnalyzed $DaysUnused
    }
    
    # Display final summary
    Write-Output "`n========================================="
    Write-Output "Enterprise Application Analysis Summary"
    Write-Output "========================================="
    Write-Output "Analysis Period: Last $DaysUnused days"
    Write-Output "Total Enterprise Applications: $($Script:UnusedApplications.Count + $Script:ActiveApplications.Count)"
    Write-Output "Unused Applications: $($Script:UnusedApplications.Count)"
    Write-Output "Active Applications: $($Script:ActiveApplications.Count)"
    Write-Output "High-Risk Unused Apps: $($Script:HighRiskApplications.Count)"
    $UsageRate = if (($Script:UnusedApplications.Count + $Script:ActiveApplications.Count) -gt 0) { 
        [math]::Round(($Script:ActiveApplications.Count / ($Script:UnusedApplications.Count + $Script:ActiveApplications.Count)) * 100, 2) 
    } else { 100 }
    Write-Output "Application Usage Rate: $UsageRate%"
    Write-Output "Processing Errors: $($Script:ProcessingErrors.Count)"
    Write-Output "Mode: $(if ($WhatIf) { 'Simulation (WhatIf)' } else { 'Production' })"
    Write-Output "Reports saved to: $ExportPath"
    if ($StorageAccountName) {
        Write-Output "Reports uploaded to blob storage: $StorageAccountName/$StorageContainerName"
    }
    
    # Calculate potential savings
    $EstimatedMonthlySavings = $Script:UnusedApplications.Count * 15
    $EstimatedAnnualSavings = $EstimatedMonthlySavings * 12
    Write-Output "Estimated Monthly Savings: $EstimatedMonthlySavings"
    Write-Output "Estimated Annual Savings: $EstimatedAnnualSavings"
    
    Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "========================================="
    
    if ($Script:UnusedApplications.Count -gt 0) {
        Write-Output "`n⚠️  ATTENTION: $($Script:UnusedApplications.Count) unused enterprise applications found"
        if ($Script:HighRiskApplications.Count -gt 0) {
            Write-Output "🚨 HIGH PRIORITY: $($Script:HighRiskApplications.Count) high-risk applications require immediate review"
        }
        Write-Output "💰 Potential cost savings: $EstimatedAnnualSavings annually"
        Write-Output "📊 Review detailed reports in: $ExportPath"
        
        if ($Script:UnusedApplications.Count -gt $MinimumRiskThreshold) {
            Write-Output "🔔 Alert threshold exceeded - Consider immediate action"
        }
    } else {
        Write-Output "`n✅ Excellent! All enterprise applications are actively used"
    }
}
catch {
    Write-Error "Critical error in enterprise application analysis: $_"
    
    # Save error to file
    $ErrorFile = Join-Path $ExportPath "CriticalError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $ErrorDetails = @"
Enterprise Application Usage Monitor - Critical Error Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Error Details:
$($_.Exception.Message)

Stack Trace:
$($_.Exception.StackTrace)

Script Parameters:
- DaysUnused: $DaysUnused
- WhatIf: $($WhatIf.IsPresent)
- SendEmailReport: $($SendEmailReport.IsPresent)
- IncludeActiveApps: $($IncludeActiveApps.IsPresent)
- ExportPath: $ExportPath
"@
    
    $ErrorDetails | Out-File -FilePath $ErrorFile -Encoding UTF8
    Write-Output "Error details saved to: $ErrorFile"
    
    throw
}
finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Output "`nDisconnecting from Microsoft Graph..."
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}

#endregion