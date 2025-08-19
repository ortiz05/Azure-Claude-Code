<#
.SYNOPSIS
    Azure Automation for identifying unused Enterprise Applications with expired certificates
    
.DESCRIPTION
    This script analyzes Azure AD Enterprise Applications to identify those that:
    1. Haven't been used in the specified number of days (default: 90)
    2. Have expired certificates or secrets
    This combination represents a high security risk and should be prioritized for cleanup.
    
.PARAMETER DaysUnused
    Number of days without usage to consider an app as unused (default: 90)
    
.PARAMETER WhatIf
    Run in simulation mode without sending emails
    
.PARAMETER ITAdminEmails
    Array of IT administrator email addresses for reports
    
.PARAMETER SecurityAdminEmails
    Array of security administrator email addresses for high-priority alerts
    
.PARAMETER ExcludedApps
    Array of application IDs or display names to exclude from analysis
    
.PARAMETER ExportPath
    Path where CSV reports will be saved (DEPRECATED - use blob storage)
    
.PARAMETER StorageAccountName
    Azure Storage Account name for report storage (required for blob storage)
    
.PARAMETER StorageContainerName
    Azure Storage Container name for reports (default: certificate-monitor-reports)
    
.PARAMETER UseManagedIdentity
    Use Azure Automation managed identity for authentication (recommended)
    
.PARAMETER IncludeSoonToExpire
    Include certificates/secrets expiring within specified days (default: 30)
    
.PARAMETER CertificateExpiryWarningDays
    Days before expiration to trigger warnings (default: 30)
    
.PARAMETER SendCriticalAlerts
    Send immediate alerts for high-risk applications
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$DaysUnused = 90,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$SecurityAdminEmails = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedApps = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\EnterpriseAppCertificateReports",
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageContainerName = "certificate-monitor-reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseManagedIdentity = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSoonToExpire = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$CertificateExpiryWarningDays = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendCriticalAlerts = $true
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
$Script:CriticalRiskApplications = [System.Collections.ArrayList]::new()
$Script:HighRiskApplications = [System.Collections.ArrayList]::new()
$Script:MediumRiskApplications = [System.Collections.ArrayList]::new()
$Script:ProcessingErrors = [System.Collections.ArrayList]::new()
$Script:AllAnalyzedApps = [System.Collections.ArrayList]::new()

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

function Get-CertificateExpirationStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Application,
        
        [Parameter(Mandatory=$false)]
        [int]$WarningDays = 30
    )
    
    $ExpirationDetails = @{
        HasExpiredCredentials = $false
        HasExpiringCredentials = $false
        ExpiredCertificates = @()
        ExpiredSecrets = @()
        ExpiringCertificates = @()
        ExpiringSecrets = @()
        TotalCredentials = 0
        WorstExpirationStatus = "Good"
        DaysUntilNextExpiration = 999
    }
    
    $Now = Get-Date
    $WarningDate = $Now.AddDays($WarningDays)
    
    try {
        # Check Key Credentials (Certificates)
        if ($Application.KeyCredentials) {
            foreach ($KeyCred in $Application.KeyCredentials) {
                $ExpirationDetails.TotalCredentials++
                
                if ($KeyCred.EndDateTime -lt $Now) {
                    $ExpirationDetails.HasExpiredCredentials = $true
                    $DaysExpired = (New-TimeSpan -Start $KeyCred.EndDateTime -End $Now).Days
                    $ExpirationDetails.ExpiredCertificates += @{
                        KeyId = $KeyCred.KeyId
                        DisplayName = $KeyCred.DisplayName ?? "Certificate"
                        EndDateTime = $KeyCred.EndDateTime
                        DaysExpired = $DaysExpired
                        Usage = $KeyCred.Usage ?? "Unknown"
                        Type = $KeyCred.Type ?? "AsymmetricX509Cert"
                    }
                    $ExpirationDetails.WorstExpirationStatus = "Expired"
                } elseif ($KeyCred.EndDateTime -lt $WarningDate) {
                    $ExpirationDetails.HasExpiringCredentials = $true
                    $DaysUntilExpiry = (New-TimeSpan -Start $Now -End $KeyCred.EndDateTime).Days
                    $ExpirationDetails.ExpiringCertificates += @{
                        KeyId = $KeyCred.KeyId
                        DisplayName = $KeyCred.DisplayName ?? "Certificate"
                        EndDateTime = $KeyCred.EndDateTime
                        DaysUntilExpiry = $DaysUntilExpiry
                        Usage = $KeyCred.Usage ?? "Unknown"
                        Type = $KeyCred.Type ?? "AsymmetricX509Cert"
                    }
                    
                    if ($ExpirationDetails.WorstExpirationStatus -ne "Expired") {
                        $ExpirationDetails.WorstExpirationStatus = "Expiring"
                    }
                    
                    if ($DaysUntilExpiry -lt $ExpirationDetails.DaysUntilNextExpiration) {
                        $ExpirationDetails.DaysUntilNextExpiration = $DaysUntilExpiry
                    }
                }
            }
        }
        
        # Check Password Credentials (Secrets)
        if ($Application.PasswordCredentials) {
            foreach ($PasswordCred in $Application.PasswordCredentials) {
                $ExpirationDetails.TotalCredentials++
                
                if ($PasswordCred.EndDateTime -lt $Now) {
                    $ExpirationDetails.HasExpiredCredentials = $true
                    $DaysExpired = (New-TimeSpan -Start $PasswordCred.EndDateTime -End $Now).Days
                    $ExpirationDetails.ExpiredSecrets += @{
                        KeyId = $PasswordCred.KeyId
                        DisplayName = $PasswordCred.DisplayName ?? "Client Secret"
                        EndDateTime = $PasswordCred.EndDateTime
                        DaysExpired = $DaysExpired
                        Hint = $PasswordCred.Hint ?? ""
                    }
                    $ExpirationDetails.WorstExpirationStatus = "Expired"
                } elseif ($PasswordCred.EndDateTime -lt $WarningDate) {
                    $ExpirationDetails.HasExpiringCredentials = $true
                    $DaysUntilExpiry = (New-TimeSpan -Start $Now -End $PasswordCred.EndDateTime).Days
                    $ExpirationDetails.ExpiringSecrets += @{
                        KeyId = $PasswordCred.KeyId
                        DisplayName = $PasswordCred.DisplayName ?? "Client Secret"
                        EndDateTime = $PasswordCred.EndDateTime
                        DaysUntilExpiry = $DaysUntilExpiry
                        Hint = $PasswordCred.Hint ?? ""
                    }
                    
                    if ($ExpirationDetails.WorstExpirationStatus -ne "Expired") {
                        $ExpirationDetails.WorstExpirationStatus = "Expiring"
                    }
                    
                    if ($DaysUntilExpiry -lt $ExpirationDetails.DaysUntilNextExpiration) {
                        $ExpirationDetails.DaysUntilNextExpiration = $DaysUntilExpiry
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing credentials for $($Application.DisplayName): $_"
    }
    
    return $ExpirationDetails
}

function Get-ApplicationRiskLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Application,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysUnused,
        
        [Parameter(Mandatory=$true)]
        $ExpirationDetails
    )
    
    $RiskFactors = @()
    $RiskScore = 0
    
    # Critical risk: Expired credentials + unused app
    if ($ExpirationDetails.HasExpiredCredentials -and $DaysUnused -ge 90) {
        $RiskScore += 10
        $RiskFactors += "Expired credentials on unused application"
    }
    
    # High risk: Expired credentials (regardless of usage)
    if ($ExpirationDetails.HasExpiredCredentials) {
        $RiskScore += 7
        $RiskFactors += "Has expired certificates/secrets"
    }
    
    # Medium risk: Expiring credentials + unused
    if ($ExpirationDetails.HasExpiringCredentials -and $DaysUnused -ge 30) {
        $RiskScore += 5
        $RiskFactors += "Credentials expiring soon on unused application"
    }
    
    # Risk factor: Long unused period
    if ($DaysUnused -gt 180) {
        $RiskScore += 3
        $RiskFactors += "Unused for over 6 months"
    } elseif ($DaysUnused -gt 90) {
        $RiskScore += 2
        $RiskFactors += "Unused for over 3 months"
    }
    
    # Risk factor: High privilege permissions
    if ($Application.RequiredResourceAccess) {
        $HasHighPrivileges = $false
        foreach ($ResourceAccess in $Application.RequiredResourceAccess) {
            foreach ($Permission in $ResourceAccess.ResourceAccess) {
                if ($Permission.Type -eq "Role") { # Application permissions
                    $HasHighPrivileges = $true
                    break
                }
            }
            if ($HasHighPrivileges) { break }
        }
        
        if ($HasHighPrivileges) {
            $RiskScore += 3
            $RiskFactors += "Has high-privilege application permissions"
        }
    }
    
    # Risk factor: Multiple expired credentials
    if ($ExpirationDetails.ExpiredCertificates.Count + $ExpirationDetails.ExpiredSecrets.Count -gt 1) {
        $RiskScore += 2
        $RiskFactors += "Multiple expired credentials"
    }
    
    # Risk factor: External application
    if ($Application.PublisherDomain -and $Application.PublisherDomain -notlike "*microsoft.com*" -and $Application.PublisherDomain -notlike "*yourdomain.com*") {
        $RiskScore += 1
        $RiskFactors += "Third-party application"
    }
    
    # Determine risk level
    $RiskLevel = switch ($RiskScore) {
        { $_ -ge 10 } { "Critical" }
        { $_ -ge 7 } { "High" }
        { $_ -ge 4 } { "Medium" }
        default { "Low" }
    }
    
    return @{
        RiskLevel = $RiskLevel
        RiskScore = $RiskScore
        RiskFactors = $RiskFactors
    }
}

function Send-CriticalSecurityAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$SecurityAdminEmails,
        
        [Parameter(Mandatory=$true)]
        [array]$CriticalApps
    )
    
    if ($CriticalApps.Count -eq 0) { return }
    
    $EmailBody = @"
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }
        .critical-header { background: #dc3545; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .alert-box { background: #f8d7da; border: 1px solid #dc3545; border-radius: 4px; padding: 15px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #dc3545; color: white; text-align: left; padding: 10px; border: 1px solid #dee2e6; }
        td { padding: 8px; border: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .expired { color: #dc3545; font-weight: bold; }
        .critical { background-color: #f8d7da; }
    </style>
</head>
<body>
    <div class="critical-header">
        <h1>🚨 CRITICAL SECURITY ALERT</h1>
        <h2>Unused Applications with Expired Certificates/Secrets Detected</h2>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="alert-box">
        <strong>⚠️ IMMEDIATE ACTION REQUIRED:</strong><br>
        $($CriticalApps.Count) enterprise applications have been identified with EXPIRED certificates or secrets 
        AND have not been used for $DaysUnused+ days. This represents a critical security risk.
    </div>
    
    <h2>🎯 Critical Risk Applications</h2>
    <table>
        <thead>
            <tr>
                <th>Application Name</th>
                <th>Publisher</th>
                <th>Days Unused</th>
                <th>Expired Credentials</th>
                <th>Days Expired</th>
                <th>Risk Factors</th>
            </tr>
        </thead>
        <tbody>
            $(($CriticalApps | ForEach-Object {
                $ExpiredItems = @()
                if ($_.ExpiredCertificates.Count -gt 0) {
                    $ExpiredItems += "$($_.ExpiredCertificates.Count) Certificate(s)"
                }
                if ($_.ExpiredSecrets.Count -gt 0) {
                    $ExpiredItems += "$($_.ExpiredSecrets.Count) Secret(s)"
                }
                $ExpiredCredentialsText = $ExpiredItems -join ", "
                
                $MaxDaysExpired = 0
                if ($_.ExpiredCertificates) {
                    $MaxDaysExpired = [math]::Max($MaxDaysExpired, ($_.ExpiredCertificates | Measure-Object DaysExpired -Maximum).Maximum)
                }
                if ($_.ExpiredSecrets) {
                    $MaxDaysExpired = [math]::Max($MaxDaysExpired, ($_.ExpiredSecrets | Measure-Object DaysExpired -Maximum).Maximum)
                }
                
                "<tr class='critical'>
                    <td><strong>$($_.DisplayName)</strong></td>
                    <td>$($_.PublisherDomain ?? 'Unknown')</td>
                    <td>$($_.DaysUnused)</td>
                    <td class='expired'>$ExpiredCredentialsText</td>
                    <td class='expired'>$MaxDaysExpired</td>
                    <td>$($_.RiskFactors -join '; ')</td>
                </tr>"
            }) -join "`n")
        </tbody>
    </table>
    
    <h2>🔧 Immediate Actions Required</h2>
    <ol>
        <li><strong>URGENT (Today):</strong> Review and disable/remove unused applications with expired credentials</li>
        <li><strong>HIGH PRIORITY:</strong> Audit permissions and access granted to these applications</li>
        <li><strong>INVESTIGATE:</strong> Check for any unauthorized access using expired credentials</li>
        <li><strong>DOCUMENT:</strong> Record business justification for any applications that must be retained</li>
        <li><strong>MONITOR:</strong> Set up alerts for future credential expirations</li>
    </ol>
    
    <h2>🛡️ Security Impact</h2>
    <ul>
        <li><strong>Attack Vector:</strong> Expired certificates may indicate compromised or abandoned applications</li>
        <li><strong>Access Risk:</strong> Applications may have retained permissions despite credential expiration</li>
        <li><strong>Compliance Risk:</strong> Unused applications with expired credentials violate security policies</li>
        <li><strong>Audit Exposure:</strong> Security assessments will flag these as critical findings</li>
    </ul>
    
    <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px;">
        <h3>📞 Emergency Contact Information</h3>
        <p><strong>This is a high-priority security alert requiring immediate attention.</strong></p>
        <p>If you need assistance or have questions, contact the Security Operations Center immediately.</p>
        <p><strong>Do not delay action on these findings.</strong></p>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #666;">
        <p>This critical alert was automatically generated by the Enterprise Application Certificate Monitor.</p>
        <p>Report ID: EACM-$(Get-Date -Format 'yyyyMMdd-HHmmss')</p>
    </div>
</body>
</html>
"@
    
    foreach ($AdminEmail in $SecurityAdminEmails) {
        $EmailMessage = @{
            Message = @{
                Subject = "🚨 CRITICAL SECURITY ALERT: $($CriticalApps.Count) Apps with Expired Credentials"
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
                Importance = "High"
            }
            SaveToSentItems = $true
        }
        
        try {
            if (-not $WhatIf) {
                $EmailJson = $EmailMessage | ConvertTo-Json -Depth 10 -Compress
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Body $EmailJson
                Write-Output "🚨 Critical security alert sent to $AdminEmail"
            } else {
                Write-Output "[WhatIf] Would send critical security alert to $AdminEmail"
            }
        }
        catch {
            Write-Error "Failed to send critical alert to $AdminEmail`: $_"
        }
    }
}

function Send-DetailedCertificateReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$AdminEmails,
        
        [Parameter(Mandatory=$true)]
        [array]$CriticalApps,
        
        [Parameter(Mandatory=$true)]
        [array]$HighRiskApps,
        
        [Parameter(Mandatory=$true)]
        [array]$MediumRiskApps,
        
        [Parameter(Mandatory=$true)]
        [array]$AllApps
    )
    
    $TotalApps = $AllApps.Count
    $TotalRiskyApps = $CriticalApps.Count + $HighRiskApps.Count + $MediumRiskApps.Count
    
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
        .critical-card { border-left-color: #dc3545; }
        .critical-number { color: #dc3545; }
        .high-card { border-left-color: #fd7e14; }
        .high-number { color: #fd7e14; }
        .medium-card { border-left-color: #ffc107; }
        .medium-number { color: #856404; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #f8f9fa; text-align: left; padding: 10px; border: 1px solid #dee2e6; font-weight: bold; }
        td { padding: 8px; border: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .section { margin: 30px 0; }
        .expired { color: #dc3545; font-weight: bold; }
        .expiring { color: #ffc107; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Enterprise Application Certificate & Usage Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Focus: Applications unused for $DaysUnused+ days with certificate/secret issues</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <div class="summary-number">$TotalApps</div>
            <div class="summary-label">Total Applications Analyzed</div>
        </div>
        <div class="summary-card critical-card">
            <div class="summary-number critical-number">$($CriticalApps.Count)</div>
            <div class="summary-label">Critical Risk Apps</div>
        </div>
        <div class="summary-card high-card">
            <div class="summary-number high-number">$($HighRiskApps.Count)</div>
            <div class="summary-label">High Risk Apps</div>
        </div>
        <div class="summary-card medium-card">
            <div class="summary-number medium-number">$($MediumRiskApps.Count)</div>
            <div class="summary-label">Medium Risk Apps</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$TotalRiskyApps</div>
            <div class="summary-label">Total At-Risk Apps</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">$(if ($TotalApps -gt 0) { [math]::Round((($TotalApps - $TotalRiskyApps) / $TotalApps) * 100, 1) } else { 100 })%</div>
            <div class="summary-label">Apps in Good Standing</div>
        </div>
    </div>
    
    $(if ($CriticalApps.Count -gt 0) {
        @"
        <div class="section">
            <h2>🚨 Critical Risk Applications (Immediate Action Required)</h2>
            <p><strong>These applications are unused AND have expired certificates/secrets:</strong></p>
            <table>
                <thead>
                    <tr>
                        <th>Application Name</th>
                        <th>Publisher</th>
                        <th>Days Unused</th>
                        <th>Credential Status</th>
                        <th>Expired Details</th>
                        <th>Action Required</th>
                    </tr>
                </thead>
                <tbody>
                    $(($CriticalApps | Select-Object -First 20 | ForEach-Object {
                        $CredentialStatus = @()
                        $ExpiredDetails = @()
                        
                        if ($_.ExpiredCertificates.Count -gt 0) {
                            $CredentialStatus += "$($_.ExpiredCertificates.Count) Expired Cert(s)"
                            $ExpiredDetails += $_.ExpiredCertificates | ForEach-Object { "Cert: $($_.DaysExpired) days" }
                        }
                        if ($_.ExpiredSecrets.Count -gt 0) {
                            $CredentialStatus += "$($_.ExpiredSecrets.Count) Expired Secret(s)"
                            $ExpiredDetails += $_.ExpiredSecrets | ForEach-Object { "Secret: $($_.DaysExpired) days" }
                        }
                        
                        "<tr style='background-color: #f8d7da;'>
                            <td><strong>$($_.DisplayName)</strong></td>
                            <td>$($_.PublisherDomain ?? 'Unknown')</td>
                            <td>$($_.DaysUnused)</td>
                            <td class='expired'>$($CredentialStatus -join ', ')</td>
                            <td class='expired'>$($ExpiredDetails -join ', ')</td>
                            <td><strong>Remove/Disable</strong></td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    $(if ($HighRiskApps.Count -gt 0) {
        @"
        <div class="section">
            <h2>⚠️ High Risk Applications</h2>
            <table>
                <thead>
                    <tr>
                        <th>Application Name</th>
                        <th>Publisher</th>
                        <th>Days Unused</th>
                        <th>Risk Factors</th>
                        <th>Next Expiration</th>
                    </tr>
                </thead>
                <tbody>
                    $(($HighRiskApps | Select-Object -First 15 | ForEach-Object {
                        "<tr>
                            <td><strong>$($_.DisplayName)</strong></td>
                            <td>$($_.PublisherDomain ?? 'Unknown')</td>
                            <td>$($_.DaysUnused)</td>
                            <td>$($_.RiskFactors -join '; ')</td>
                            <td>$(if ($_.DaysUntilNextExpiration -lt 999) { "$($_.DaysUntilNextExpiration) days" } else { "No near expiration" })</td>
                        </tr>"
                    }) -join "`n")
                </tbody>
            </table>
        </div>
"@
    })
    
    <div class="section">
        <h2>📋 Recommended Actions by Priority</h2>
        
        <h3>🚨 Immediate (Today)</h3>
        <ul>
            $(if ($CriticalApps.Count -gt 0) {
                "<li><strong>Remove or disable $($CriticalApps.Count) critical risk applications</strong> - unused apps with expired credentials</li>"
            })
            <li>Review all applications with expired certificates for security breaches</li>
            <li>Audit permissions and access logs for affected applications</li>
        </ul>
        
        <h3>⚠️ High Priority (This Week)</h3>
        <ul>
            $(if ($HighRiskApps.Count -gt 0) {
                "<li>Evaluate $($HighRiskApps.Count) high-risk applications for business necessity</li>"
            })
            <li>Update or remove applications with expiring certificates</li>
            <li>Implement automated certificate expiration monitoring</li>
        </ul>
        
        <h3>📋 Medium Priority (This Month)</h3>
        <ul>
            $(if ($MediumRiskApps.Count -gt 0) {
                "<li>Review $($MediumRiskApps.Count) medium-risk applications</li>"
            })
            <li>Establish application lifecycle management policies</li>
            <li>Set up regular certificate renewal processes</li>
            <li>Document business justification for retained applications</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>🔒 Security Benefits of Cleanup</h2>
        <ul>
            <li><strong>Reduced Attack Surface:</strong> Eliminate unused applications with potential vulnerabilities</li>
            <li><strong>Certificate Hygiene:</strong> Remove expired certificates that may be exploited</li>
            <li><strong>Access Control:</strong> Prevent potential unauthorized access through dormant applications</li>
            <li><strong>Compliance:</strong> Align with security best practices and regulatory requirements</li>
            <li><strong>Operational Efficiency:</strong> Simplify application portfolio management</li>
        </ul>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #666;">
        <p><strong>Analysis Details:</strong></p>
        <ul>
            <li>Certificate expiration analysis based on KeyCredentials and PasswordCredentials</li>
            <li>Usage analysis based on sign-in logs from the last $DaysUnused days</li>
            <li>Risk assessment includes multiple factors: usage, expiration, permissions, and publisher</li>
            <li>Applications with no credentials are excluded from this analysis</li>
        </ul>
        <p>This report was automatically generated by the Enterprise Application Certificate Monitor.</p>
    </div>
</body>
</html>
"@
    
    foreach ($AdminEmail in $AdminEmails) {
        $Priority = if ($CriticalApps.Count -gt 0) { "High" } else { "Normal" }
        
        $EmailMessage = @{
            Message = @{
                Subject = "🔐 Enterprise App Certificate Report - $($CriticalApps.Count) Critical Issues"
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
                Write-Output "Certificate report sent to $AdminEmail"
            } else {
                Write-Output "[WhatIf] Would send certificate report to $AdminEmail"
            }
        }
        catch {
            Write-Warning "Failed to send report to $AdminEmail`: $_"
        }
    }
}

#endregion

#region Main Processing Functions

function Get-UnusedAppsWithExpiredCertificates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$DaysBack
    )
    
    Write-Output "Analyzing enterprise applications for certificate expiration and usage..."
    
    try {
        # Get all applications with detailed credentials
        Write-Output "Retrieving applications with certificate details..."
        $AllApplications = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,PublisherDomain,KeyCredentials,PasswordCredentials,RequiredResourceAccess,Certification
        
        Write-Output "Found $($AllApplications.Count) total applications"
        
        # Filter applications that have credentials (certificates or secrets)
        $AppsWithCredentials = $AllApplications | Where-Object {
            ($_.KeyCredentials -and $_.KeyCredentials.Count -gt 0) -or 
            ($_.PasswordCredentials -and $_.PasswordCredentials.Count -gt 0)
        }
        
        Write-Output "Found $($AppsWithCredentials.Count) applications with certificates/secrets"
        
        # Get sign-in logs for usage analysis
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        $Filter = "createdDateTime ge $StartDate and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')"
        
        Write-Output "Retrieving sign-in logs from $StartDate..."
        $SignInLogs = @()
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$select=id,createdDateTime,appId,appDisplayName,userPrincipalName,clientAppUsed&`$top=1000"
        
        do {
            $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri
            $SignInLogs += $Response.value
            $Uri = $Response.'@odata.nextLink'
            
            if ($SignInLogs.Count % 5000 -eq 0) {
                Write-Output "Retrieved $($SignInLogs.Count) sign-in records..."
            }
        } while ($Uri)
        
        Write-Output "Total sign-in records retrieved: $($SignInLogs.Count)"
        
        # Create usage lookup
        $AppUsageMap = @{}
        foreach ($SignIn in $SignInLogs) {
            if ($SignIn.appId -and $SignIn.appId -ne "00000000-0000-0000-0000-000000000000") {
                if (-not $AppUsageMap.ContainsKey($SignIn.appId)) {
                    $AppUsageMap[$SignIn.appId] = @{
                        LastSignIn = $SignIn.createdDateTime
                        TotalSignIns = 1
                    }
                } else {
                    $AppUsageMap[$SignIn.appId].TotalSignIns++
                    if ([DateTime]$SignIn.createdDateTime -gt [DateTime]$AppUsageMap[$SignIn.appId].LastSignIn) {
                        $AppUsageMap[$SignIn.appId].LastSignIn = $SignIn.createdDateTime
                    }
                }
            }
        }
        
        # Analyze each application
        foreach ($App in $AppsWithCredentials) {
            try {
                # Check exclusions
                $ShouldExclude = $false
                foreach ($Exclusion in $ExcludedApps) {
                    if ($App.DisplayName -like "*$Exclusion*" -or $App.AppId -eq $Exclusion -or $App.Id -eq $Exclusion) {
                        $ShouldExclude = $true
                        break
                    }
                }
                
                if ($ShouldExclude) {
                    Write-Verbose "Excluding application: $($App.DisplayName)"
                    continue
                }
                
                # Analyze certificate/secret expiration
                $ExpirationDetails = Get-CertificateExpirationStatus -Application $App -WarningDays $CertificateExpiryWarningDays
                
                # Determine usage status
                $LastSignInDate = "Never"
                $DaysUnused = 999
                $TotalSignIns = 0
                $UsageStatus = "Unused"
                
                if ($AppUsageMap.ContainsKey($App.AppId)) {
                    $UsageData = $AppUsageMap[$App.AppId]
                    $LastSignInDate = ([DateTime]$UsageData.LastSignIn).ToString("yyyy-MM-dd HH:mm:ss")
                    $DaysUnused = (New-TimeSpan -Start ([DateTime]$UsageData.LastSignIn) -End (Get-Date)).Days
                    $TotalSignIns = $UsageData.TotalSignIns
                    $UsageStatus = if ($DaysUnused -lt $DaysBack) { "Active" } else { "Unused" }
                } else {
                    # Check if app was created within the analysis period
                    $AppAge = (New-TimeSpan -Start $App.CreatedDateTime -End (Get-Date)).Days
                    if ($AppAge -lt $DaysBack) {
                        $DaysUnused = $AppAge
                        $UsageStatus = "New - No Usage"
                    }
                }
                
                # Calculate risk assessment
                $RiskAssessment = Get-ApplicationRiskLevel -Application $App -DaysUnused $DaysUnused -ExpirationDetails $ExpirationDetails
                
                # Create comprehensive application record
                $AppRecord = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    DisplayName = $App.DisplayName
                    AppId = $App.AppId
                    ObjectId = $App.Id
                    PublisherDomain = $App.PublisherDomain ?? "Unknown"
                    CreatedDate = $App.CreatedDateTime.ToString("yyyy-MM-dd")
                    LastSignInDate = $LastSignInDate
                    DaysUnused = $DaysUnused
                    UsageStatus = $UsageStatus
                    TotalSignIns = $TotalSignIns
                    
                    # Certificate/Secret Details
                    TotalCredentials = $ExpirationDetails.TotalCredentials
                    HasExpiredCredentials = $ExpirationDetails.HasExpiredCredentials
                    HasExpiringCredentials = $ExpirationDetails.HasExpiringCredentials
                    ExpiredCertificatesCount = $ExpirationDetails.ExpiredCertificates.Count
                    ExpiredSecretsCount = $ExpirationDetails.ExpiredSecrets.Count
                    ExpiringCertificatesCount = $ExpirationDetails.ExpiringCertificates.Count
                    ExpiringSecretsCount = $ExpirationDetails.ExpiringSecrets.Count
                    WorstExpirationStatus = $ExpirationDetails.WorstExpirationStatus
                    DaysUntilNextExpiration = $ExpirationDetails.DaysUntilNextExpiration
                    
                    # Risk Assessment
                    RiskLevel = $RiskAssessment.RiskLevel
                    RiskScore = $RiskAssessment.RiskScore
                    RiskFactors = ($RiskAssessment.RiskFactors -join "; ")
                    
                    # Detailed Credential Information
                    ExpiredCertificateDetails = ($ExpirationDetails.ExpiredCertificates | ForEach-Object { "$($_.DisplayName): $($_.DaysExpired) days expired" }) -join "; "
                    ExpiredSecretDetails = ($ExpirationDetails.ExpiredSecrets | ForEach-Object { "$($_.DisplayName): $($_.DaysExpired) days expired" }) -join "; "
                    ExpiringCertificateDetails = ($ExpirationDetails.ExpiringCertificates | ForEach-Object { "$($_.DisplayName): $($_.DaysUntilExpiry) days until expiry" }) -join "; "
                    ExpiringSecretDetails = ($ExpirationDetails.ExpiringSecrets | ForEach-Object { "$($_.DisplayName): $($_.DaysUntilExpiry) days until expiry" }) -join "; "
                    
                    # Additional metadata
                    HasCertification = ($App.Certification -ne $null)
                    RequiredPermissions = if ($App.RequiredResourceAccess) { 
                        ($App.RequiredResourceAccess | ConvertTo-Json -Compress) 
                    } else { "" }
                }
                
                # Add detailed objects for email reporting
                $AppRecord | Add-Member -NotePropertyName "ExpiredCertificates" -NotePropertyValue $ExpirationDetails.ExpiredCertificates
                $AppRecord | Add-Member -NotePropertyName "ExpiredSecrets" -NotePropertyValue $ExpirationDetails.ExpiredSecrets
                $AppRecord | Add-Member -NotePropertyName "ExpiringCertificates" -NotePropertyValue $ExpirationDetails.ExpiringCertificates
                $AppRecord | Add-Member -NotePropertyName "ExpiringSecrets" -NotePropertyValue $ExpirationDetails.ExpiringSecrets
                
                # Add to all analyzed apps
                [void]$Script:AllAnalyzedApps.Add($AppRecord)
                
                # Categorize by risk level
                switch ($RiskAssessment.RiskLevel) {
                    "Critical" {
                        [void]$Script:CriticalRiskApplications.Add($AppRecord)
                        Write-Output "  🚨 CRITICAL: $($App.DisplayName) - Unused for $DaysUnused days with expired credentials"
                    }
                    "High" {
                        [void]$Script:HighRiskApplications.Add($AppRecord)
                        Write-Output "  ⚠ HIGH RISK: $($App.DisplayName) - $($RiskAssessment.RiskFactors -join ', ')"
                    }
                    "Medium" {
                        [void]$Script:MediumRiskApplications.Add($AppRecord)
                        Write-Verbose "Medium risk: $($App.DisplayName)"
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
        Write-Output "  Applications with credentials: $($AppsWithCredentials.Count)"
        Write-Output "  Critical risk applications: $($Script:CriticalRiskApplications.Count)"
        Write-Output "  High risk applications: $($Script:HighRiskApplications.Count)"
        Write-Output "  Medium risk applications: $($Script:MediumRiskApplications.Count)"
        Write-Output "  Processing errors: $($Script:ProcessingErrors.Count)"
    }
    catch {
        Write-Error "Failed to analyze applications: $_"
        throw
    }
}

#endregion

#region Main Execution

Write-Output "========================================="
Write-Output "Enterprise Application Certificate Monitor"
Write-Output "========================================="
Write-Output "Focus: Applications unused for $DaysUnused+ days with certificate issues"
Write-Output "Certificate Warning Period: $CertificateExpiryWarningDays days"
Write-Output "WhatIf Mode: $($WhatIf.IsPresent)"
Write-Output "Include Soon-to-Expire: $($IncludeSoonToExpire.IsPresent)"
Write-Output "Critical Alerts: $($SendCriticalAlerts.IsPresent)"
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
    
    # Analyze applications for certificate issues and usage
    Write-Output "`n--- Analyzing Applications ---"
    Get-UnusedAppsWithExpiredCertificates -DaysBack $DaysUnused
    
    # Send critical alerts if enabled and critical apps found
    if ($SendCriticalAlerts -and $Script:CriticalRiskApplications.Count -gt 0 -and $SecurityAdminEmails.Count -gt 0) {
        Write-Output "`n--- Sending Critical Security Alerts ---"
        Send-CriticalSecurityAlert -SecurityAdminEmails $SecurityAdminEmails -CriticalApps $Script:CriticalRiskApplications
    }
    
    # Generate CSV Reports
    Write-Output "`n--- Generating CSV Reports ---"
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export critical risk applications
    if ($Script:CriticalRiskApplications.Count -gt 0) {
        $CriticalFile = Join-Path $ExportPath "CriticalRiskApps_$Timestamp.csv"
        $Script:CriticalRiskApplications | Export-Csv -Path $CriticalFile -NoTypeInformation -Encoding UTF8
        Write-Output "Critical risk applications report: $CriticalFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $CriticalFile -BlobName "CriticalRiskApps_$Timestamp.csv"
        }
    }
    
    # Export high risk applications
    if ($Script:HighRiskApplications.Count -gt 0) {
        $HighRiskFile = Join-Path $ExportPath "HighRiskApps_$Timestamp.csv"
        $Script:HighRiskApplications | Export-Csv -Path $HighRiskFile -NoTypeInformation -Encoding UTF8
        Write-Output "High risk applications report: $HighRiskFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $HighRiskFile -BlobName "HighRiskApps_$Timestamp.csv"
        }
    }
    
    # Export medium risk applications
    if ($Script:MediumRiskApplications.Count -gt 0) {
        $MediumRiskFile = Join-Path $ExportPath "MediumRiskApps_$Timestamp.csv"
        $Script:MediumRiskApplications | Export-Csv -Path $MediumRiskFile -NoTypeInformation -Encoding UTF8
        Write-Output "Medium risk applications report: $MediumRiskFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $MediumRiskFile -BlobName "MediumRiskApps_$Timestamp.csv"
        }
    }
    
    # Export all analyzed applications
    if ($Script:AllAnalyzedApps.Count -gt 0) {
        $AllAppsFile = Join-Path $ExportPath "AllAnalyzedApps_$Timestamp.csv"
        $Script:AllAnalyzedApps | Export-Csv -Path $AllAppsFile -NoTypeInformation -Encoding UTF8
        Write-Output "Complete application analysis report: $AllAppsFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $AllAppsFile -BlobName "AllAnalyzedApps_$Timestamp.csv"
        }
    }
    
    # Export processing errors
    if ($Script:ProcessingErrors.Count -gt 0) {
        $ErrorFile = Join-Path $ExportPath "ProcessingErrors_$Timestamp.csv"
        $Script:ProcessingErrors | Export-Csv -Path $ErrorFile -NoTypeInformation -Encoding UTF8
        Write-Output "Processing errors report: $ErrorFile"
        
        # Upload to blob storage if configured
        if ($StorageAccountName) {
            Export-ToBlob -FilePath $ErrorFile -BlobName "ProcessingErrors_$Timestamp.csv"
        }
    }
    
    # Generate summary CSV
    $SummaryData = @(
        [PSCustomObject]@{
            RunDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Mode = if ($WhatIf) { "Simulation (WhatIf)" } else { "Production" }
            DaysAnalyzed = $DaysUnused
            CertificateWarningDays = $CertificateExpiryWarningDays
            TotalApplicationsAnalyzed = $Script:AllAnalyzedApps.Count
            CriticalRiskApplications = $Script:CriticalRiskApplications.Count
            HighRiskApplications = $Script:HighRiskApplications.Count
            MediumRiskApplications = $Script:MediumRiskApplications.Count
            TotalRiskyApplications = $Script:CriticalRiskApplications.Count + $Script:HighRiskApplications.Count + $Script:MediumRiskApplications.Count
            ProcessingErrors = $Script:ProcessingErrors.Count
            CriticalAlertsEnabled = $SendCriticalAlerts
            SecurityAlertsConfigured = $SecurityAdminEmails.Count -gt 0
        }
    )
    
    $SummaryFile = Join-Path $ExportPath "CertificateMonitorSummary_$Timestamp.csv"
    $SummaryData | Export-Csv -Path $SummaryFile -NoTypeInformation -Encoding UTF8
    Write-Output "Summary report: $SummaryFile"
    
    # Upload summary to blob storage if configured
    if ($StorageAccountName) {
        Export-ToBlob -FilePath $SummaryFile -BlobName "CertificateMonitorSummary_$Timestamp.csv"
    }
    
    # Send detailed email report to IT administrators
    if ($ITAdminEmails.Count -gt 0) {
        Write-Output "`n--- Sending Detailed Email Report ---"
        Send-DetailedCertificateReport `
            -AdminEmails $ITAdminEmails `
            -CriticalApps $Script:CriticalRiskApplications `
            -HighRiskApps $Script:HighRiskApplications `
            -MediumRiskApps $Script:MediumRiskApplications `
            -AllApps $Script:AllAnalyzedApps
    }
    
    # Display final summary
    Write-Output "`n========================================="
    Write-Output "Certificate Monitor Analysis Summary"
    Write-Output "========================================="
    Write-Output "Analysis Period: Last $DaysUnused days (unused threshold)"
    Write-Output "Certificate Warning Period: $CertificateExpiryWarningDays days"
    Write-Output "Total Applications Analyzed: $($Script:AllAnalyzedApps.Count)"
    Write-Output "Critical Risk Applications: $($Script:CriticalRiskApplications.Count)"
    Write-Output "High Risk Applications: $($Script:HighRiskApplications.Count)"
    Write-Output "Medium Risk Applications: $($Script:MediumRiskApplications.Count)"
    Write-Output "Processing Errors: $($Script:ProcessingErrors.Count)"
    Write-Output "Mode: $(if ($WhatIf) { 'Simulation (WhatIf)' } else { 'Production' })"
    Write-Output "Reports saved to: $ExportPath"
    if ($StorageAccountName) {
        Write-Output "Reports uploaded to blob storage: $StorageAccountName/$StorageContainerName"
    }
    Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "========================================="
    
    if ($Script:CriticalRiskApplications.Count -gt 0) {
        Write-Output "`n🚨 CRITICAL ALERT: $($Script:CriticalRiskApplications.Count) applications with expired credentials and no recent usage!"
        Write-Output "📧 Security alerts sent: $(if ($SendCriticalAlerts -and $SecurityAdminEmails.Count -gt 0) { 'Yes' } else { 'No' })"
        Write-Output "⚡ IMMEDIATE ACTION REQUIRED - Review and remove these applications"
    }
    
    if ($Script:HighRiskApplications.Count -gt 0) {
        Write-Output "`n⚠️ HIGH PRIORITY: $($Script:HighRiskApplications.Count) high-risk applications require review"
    }
    
    if ($Script:CriticalRiskApplications.Count -eq 0 -and $Script:HighRiskApplications.Count -eq 0) {
        Write-Output "`n✅ Good news! No critical certificate/usage issues found"
    }
    
    Write-Output "`n📊 Review detailed reports in: $ExportPath"
}
catch {
    Write-Error "Critical error in certificate monitoring: $_"
    
    # Save error to file
    $ErrorFile = Join-Path $ExportPath "CriticalError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $ErrorDetails = @"
Enterprise Application Certificate Monitor - Critical Error Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Error Details:
$($_.Exception.Message)

Stack Trace:
$($_.Exception.StackTrace)

Script Parameters:
- DaysUnused: $DaysUnused
- CertificateExpiryWarningDays: $CertificateExpiryWarningDays
- WhatIf: $($WhatIf.IsPresent)
- SendCriticalAlerts: $($SendCriticalAlerts.IsPresent)
- ExportPath: $ExportPath
"@
    
    $ErrorDetails | Out-File -FilePath $ErrorFile -Encoding UTF8
    Write-Output "Error details saved to: $ErrorFile"
    
    # Upload error to blob storage if configured
    if ($StorageAccountName) {
        Export-ToBlob -FilePath $ErrorFile -BlobName "CriticalError_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    }
    
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