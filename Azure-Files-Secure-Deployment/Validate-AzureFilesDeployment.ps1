# Validate-AzureFilesDeployment.ps1
# Validation script for secure Azure Files deployment

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$FileShareName = "secure-fileshare"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Azure Files Security Validation" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Connect to Azure
try {
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    $Context = Get-AzContext
    if (-not $Context -or $Context.Subscription.Id -ne $SubscriptionId) {
        Connect-AzAccount -SubscriptionId $SubscriptionId
    }
    Write-Host "✓ Connected to Azure subscription: $SubscriptionId" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    exit 1
}

# Validation results
$ValidationResults = @{
    SecurityControls = @()
    NetworkSecurity = @()
    DataProtection = @()
    AccessControls = @()
    Monitoring = @()
    Issues = @()
    Recommendations = @()
}

function Test-StorageAccountSecurity {
    try {
        Write-Host "Validating storage account security..." -ForegroundColor Yellow
        
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
        if (-not $StorageAccount) {
            $ValidationResults.Issues += "Storage account '$StorageAccountName' not found"
            return
        }
        
        # Check HTTPS-only traffic
        if ($StorageAccount.EnableHttpsTrafficOnly) {
            $ValidationResults.SecurityControls += "✓ HTTPS-only traffic: Enabled"
        } else {
            $ValidationResults.Issues += "✗ HTTPS-only traffic: Disabled"
            $ValidationResults.Recommendations += "Enable HTTPS-only traffic for security"
        }
        
        # Check minimum TLS version
        if ($StorageAccount.MinimumTlsVersion -eq "TLS1_2") {
            $ValidationResults.SecurityControls += "✓ Minimum TLS version: 1.2"
        } else {
            $ValidationResults.Issues += "✗ Minimum TLS version: $($StorageAccount.MinimumTlsVersion)"
            $ValidationResults.Recommendations += "Set minimum TLS version to 1.2"
        }
        
        # Check shared key access
        if ($StorageAccount.AllowSharedKeyAccess -eq $false) {
            $ValidationResults.SecurityControls += "✓ Shared key access: Disabled"
        } else {
            $ValidationResults.Issues += "✗ Shared key access: Enabled"
            $ValidationResults.Recommendations += "Disable shared key access to enforce Azure AD authentication"
        }
        
        # Check blob public access
        if ($StorageAccount.AllowBlobPublicAccess -eq $false) {
            $ValidationResults.SecurityControls += "✓ Public blob access: Disabled"
        } else {
            $ValidationResults.Issues += "✗ Public blob access: Enabled"
            $ValidationResults.Recommendations += "Disable public blob access to prevent data exposure"
        }
        
        # Check cross-tenant replication
        if ($StorageAccount.AllowCrossTenantReplication -eq $false) {
            $ValidationResults.SecurityControls += "✓ Cross-tenant replication: Disabled"
        } else {
            $ValidationResults.Issues += "✗ Cross-tenant replication: Enabled"
            $ValidationResults.Recommendations += "Disable cross-tenant replication to prevent data leakage"
        }
        
        Write-Host "✓ Storage account security validation completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to validate storage account security: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to validate storage account security"
    }
}

function Test-NetworkSecurity {
    try {
        Write-Host "Validating network security..." -ForegroundColor Yellow
        
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        
        # Check public network access
        if ($StorageAccount.PublicNetworkAccess -eq "Disabled") {
            $ValidationResults.NetworkSecurity += "✓ Public network access: Disabled (most secure)"
        } elseif ($StorageAccount.PublicNetworkAccess -eq "Enabled") {
            # Check if network rules are configured
            $NetworkRules = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
            
            if ($NetworkRules.VirtualNetworkRules.Count -gt 0 -or $NetworkRules.IpRules.Count -gt 0) {
                $ValidationResults.NetworkSecurity += "✓ Public access: Restricted with network rules"
                $ValidationResults.NetworkSecurity += "  - VNet rules: $($NetworkRules.VirtualNetworkRules.Count)"
                $ValidationResults.NetworkSecurity += "  - IP rules: $($NetworkRules.IpRules.Count)"
            } else {
                $ValidationResults.Issues += "✗ Public access: Enabled without restrictions"
                $ValidationResults.Recommendations += "Configure VNet integration or IP restrictions"
            }
        }
        
        # Check default action
        $NetworkRules = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        if ($NetworkRules.DefaultAction -eq "Deny") {
            $ValidationResults.NetworkSecurity += "✓ Default network action: Deny"
        } else {
            $ValidationResults.Issues += "✗ Default network action: Allow"
            $ValidationResults.Recommendations += "Set default network action to Deny"
        }
        
        Write-Host "✓ Network security validation completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to validate network security: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to validate network security"
    }
}

function Test-DataProtection {
    try {
        Write-Host "Validating data protection..." -ForegroundColor Yellow
        
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        $Context = $StorageAccount.Context
        
        # Check soft delete for blobs
        try {
            $BlobServiceProperties = Get-AzStorageBlobServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
            if ($BlobServiceProperties.DeleteRetentionPolicy.Enabled) {
                $ValidationResults.DataProtection += "✓ Blob soft delete: Enabled ($($BlobServiceProperties.DeleteRetentionPolicy.Days) days)"
            } else {
                $ValidationResults.Issues += "✗ Blob soft delete: Disabled"
                $ValidationResults.Recommendations += "Enable blob soft delete with appropriate retention period"
            }
        } catch {
            $ValidationResults.DataProtection += "ℹ️ Blob soft delete: Unable to verify"
        }
        
        # Check soft delete for file shares
        try {
            $FileServiceProperties = Get-AzStorageServiceProperty -ServiceType File -Context $Context
            if ($FileServiceProperties.DeleteRetentionPolicy.Enabled) {
                $ValidationResults.DataProtection += "✓ File share soft delete: Enabled ($($FileServiceProperties.DeleteRetentionPolicy.Days) days)"
            } else {
                $ValidationResults.Issues += "✗ File share soft delete: Disabled"
                $ValidationResults.Recommendations += "Enable file share soft delete with appropriate retention period"
            }
        } catch {
            $ValidationResults.DataProtection += "ℹ️ File share soft delete: Unable to verify"
        }
        
        # Check versioning
        try {
            if ($BlobServiceProperties.IsVersioningEnabled) {
                $ValidationResults.DataProtection += "✓ Blob versioning: Enabled"
            } else {
                $ValidationResults.Recommendations += "Consider enabling blob versioning for audit trail"
            }
        } catch {
            $ValidationResults.DataProtection += "ℹ️ Blob versioning: Unable to verify"
        }
        
        # Check encryption
        if ($StorageAccount.Encryption.Services.File.Enabled) {
            $ValidationResults.DataProtection += "✓ File encryption: Enabled"
        } else {
            $ValidationResults.Issues += "✗ File encryption: Disabled"
        }
        
        if ($StorageAccount.Encryption.KeySource -eq "Microsoft.Keyvault") {
            $ValidationResults.DataProtection += "✓ Customer-managed encryption: Enabled"
        } else {
            $ValidationResults.DataProtection += "ℹ️ Using Microsoft-managed encryption keys"
            $ValidationResults.Recommendations += "Consider customer-managed encryption for sensitive data"
        }
        
        Write-Host "✓ Data protection validation completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to validate data protection: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to validate data protection"
    }
}

function Test-FileShareConfiguration {
    try {
        Write-Host "Validating file share configuration..." -ForegroundColor Yellow
        
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        $Context = $StorageAccount.Context
        
        # Check if file share exists
        $FileShare = Get-AzStorageShare -Name $FileShareName -Context $Context -ErrorAction SilentlyContinue
        if ($FileShare) {
            $ValidationResults.AccessControls += "✓ File share exists: $FileShareName"
            $ValidationResults.AccessControls += "  - Quota: $($FileShare.QuotaGiB) GB"
            $ValidationResults.AccessControls += "  - Last modified: $($FileShare.LastModified)"
        } else {
            $ValidationResults.Issues += "✗ File share not found: $FileShareName"
            return
        }
        
        # Check Azure AD authentication (if supported)
        try {
            if ($StorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceType -eq "AADDS") {
                $ValidationResults.AccessControls += "✓ Azure AD authentication: Enabled (AADDS)"
            } elseif ($StorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceType -eq "AD") {
                $ValidationResults.AccessControls += "✓ Azure AD authentication: Enabled (AD DS)"
            } else {
                $ValidationResults.AccessControls += "ℹ️ Azure AD authentication: Not configured"
                $ValidationResults.Recommendations += "Configure Azure AD authentication for identity-based access"
            }
        } catch {
            $ValidationResults.AccessControls += "ℹ️ Azure AD authentication: Unable to verify"
        }
        
        Write-Host "✓ File share configuration validation completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to validate file share configuration: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to validate file share configuration"
    }
}

function Test-MonitoringConfiguration {
    try {
        Write-Host "Validating monitoring configuration..." -ForegroundColor Yellow
        
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        
        # Check diagnostic settings
        $DiagnosticSettings = Get-AzDiagnosticSetting -ResourceId $StorageAccount.Id -ErrorAction SilentlyContinue
        if ($DiagnosticSettings) {
            $ValidationResults.Monitoring += "✓ Diagnostic settings: Configured"
            foreach ($Setting in $DiagnosticSettings) {
                if ($Setting.WorkspaceId) {
                    $ValidationResults.Monitoring += "  - Log Analytics: Enabled"
                }
                if ($Setting.StorageAccountId) {
                    $ValidationResults.Monitoring += "  - Storage logging: Enabled"
                }
            }
        } else {
            $ValidationResults.Recommendations += "Configure diagnostic settings for monitoring and compliance"
        }
        
        # Check storage analytics
        $Context = $StorageAccount.Context
        try {
            $FileServiceProperties = Get-AzStorageServiceProperty -ServiceType File -Context $Context
            if ($FileServiceProperties.Logging.LoggingOperations -ne "None") {
                $ValidationResults.Monitoring += "✓ File service logging: Enabled"
                $ValidationResults.Monitoring += "  - Operations: $($FileServiceProperties.Logging.LoggingOperations)"
                $ValidationResults.Monitoring += "  - Retention: $($FileServiceProperties.Logging.RetentionDays) days"
            } else {
                $ValidationResults.Recommendations += "Enable file service logging for audit trail"
            }
            
            if ($FileServiceProperties.Metrics.MetricsLevel -ne "None") {
                $ValidationResults.Monitoring += "✓ File service metrics: Enabled"
                $ValidationResults.Monitoring += "  - Level: $($FileServiceProperties.Metrics.MetricsLevel)"
            } else {
                $ValidationResults.Recommendations += "Enable file service metrics for monitoring"
            }
        } catch {
            $ValidationResults.Monitoring += "ℹ️ Storage analytics: Unable to verify"
        }
        
        Write-Host "✓ Monitoring configuration validation completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to validate monitoring configuration: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to validate monitoring configuration"
    }
}

function Test-ConnectivityAndPermissions {
    try {
        Write-Host "Testing connectivity and permissions..." -ForegroundColor Yellow
        
        # Test SMB connectivity (port 445)
        $SMBConnectivity = Test-NetConnection -ComputerName "$StorageAccountName.file.core.windows.net" -Port 445 -WarningAction SilentlyContinue
        if ($SMBConnectivity.TcpTestSucceeded) {
            $ValidationResults.AccessControls += "✓ SMB connectivity: Accessible (port 445)"
        } else {
            $ValidationResults.Issues += "✗ SMB connectivity: Failed (port 445 blocked)"
            $ValidationResults.Recommendations += "Ensure port 445 is open for SMB access"
        }
        
        # Test HTTPS connectivity (port 443)
        $HTTPSConnectivity = Test-NetConnection -ComputerName "$StorageAccountName.file.core.windows.net" -Port 443 -WarningAction SilentlyContinue
        if ($HTTPSConnectivity.TcpTestSucceeded) {
            $ValidationResults.AccessControls += "✓ HTTPS connectivity: Accessible (port 443)"
        } else {
            $ValidationResults.Issues += "✗ HTTPS connectivity: Failed (port 443 blocked)"
        }
        
        Write-Host "✓ Connectivity testing completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to test connectivity: $($_.Exception.Message)"
        $ValidationResults.Issues += "Failed to test connectivity"
    }
}

function Show-ValidationReport {
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Azure Files Security Validation Report" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    Write-Host "Storage Account: $StorageAccountName" -ForegroundColor Yellow
    Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
    Write-Host "Validation Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    
    if ($ValidationResults.SecurityControls.Count -gt 0) {
        Write-Host "`n🔐 Security Controls:" -ForegroundColor Cyan
        foreach ($Control in $ValidationResults.SecurityControls) {
            Write-Host "  $Control" -ForegroundColor White
        }
    }
    
    if ($ValidationResults.NetworkSecurity.Count -gt 0) {
        Write-Host "`n🌐 Network Security:" -ForegroundColor Cyan
        foreach ($Network in $ValidationResults.NetworkSecurity) {
            Write-Host "  $Network" -ForegroundColor White
        }
    }
    
    if ($ValidationResults.DataProtection.Count -gt 0) {
        Write-Host "`n🛡️ Data Protection:" -ForegroundColor Cyan
        foreach ($Protection in $ValidationResults.DataProtection) {
            Write-Host "  $Protection" -ForegroundColor White
        }
    }
    
    if ($ValidationResults.AccessControls.Count -gt 0) {
        Write-Host "`n🔑 Access Controls:" -ForegroundColor Cyan
        foreach ($Access in $ValidationResults.AccessControls) {
            Write-Host "  $Access" -ForegroundColor White
        }
    }
    
    if ($ValidationResults.Monitoring.Count -gt 0) {
        Write-Host "`n📊 Monitoring:" -ForegroundColor Cyan
        foreach ($Monitor in $ValidationResults.Monitoring) {
            Write-Host "  $Monitor" -ForegroundColor White
        }
    }
    
    if ($ValidationResults.Issues.Count -gt 0) {
        Write-Host "`n⚠️ Security Issues Found:" -ForegroundColor Red
        foreach ($Issue in $ValidationResults.Issues) {
            Write-Host "  $Issue" -ForegroundColor Yellow
        }
    }
    
    if ($ValidationResults.Recommendations.Count -gt 0) {
        Write-Host "`n💡 Recommendations:" -ForegroundColor Blue
        foreach ($Recommendation in $ValidationResults.Recommendations) {
            Write-Host "  • $Recommendation" -ForegroundColor Gray
        }
    }
    
    # Overall security score
    $TotalChecks = $ValidationResults.SecurityControls.Count + $ValidationResults.NetworkSecurity.Count + $ValidationResults.DataProtection.Count + $ValidationResults.AccessControls.Count
    $IssueCount = $ValidationResults.Issues.Count
    $SecurityScore = if ($TotalChecks -gt 0) { [math]::Round((($TotalChecks - $IssueCount) / $TotalChecks) * 100, 2) } else { 0 }
    
    Write-Host "`n📈 Security Score: $SecurityScore%" -ForegroundColor $(if ($SecurityScore -ge 90) { "Green" } elseif ($SecurityScore -ge 70) { "Yellow" } else { "Red" })
    
    if ($IssueCount -eq 0) {
        Write-Host "`n✅ All security validations passed!" -ForegroundColor Green
    } else {
        Write-Host "`n⚠️ $IssueCount security issue(s) found. Please review and remediate." -ForegroundColor Yellow
    }
}

# Main execution
try {
    Test-StorageAccountSecurity
    Test-NetworkSecurity
    Test-DataProtection
    Test-FileShareConfiguration
    Test-MonitoringConfiguration
    Test-ConnectivityAndPermissions
    
    Show-ValidationReport
    
    if ($ValidationResults.Issues.Count -gt 0) {
        exit 1
    }
    
} catch {
    Write-Error "Validation failed: $($_.Exception.Message)"
    exit 1
}