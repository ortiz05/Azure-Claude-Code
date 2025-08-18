# Test-PermissionAuditorConnection.ps1
# Testing script for Application Permission Auditor connectivity and permissions

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPermissionValidation
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Application Permission Auditor" -ForegroundColor Cyan
Write-Host "Connection & Permission Testing" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Import shared test functions
if (Test-Path "$PSScriptRoot\..\..\Scripts\Test-GraphAuthentication.ps1") {
    . "$PSScriptRoot\..\..\Scripts\Test-GraphAuthentication.ps1"
} else {
    Write-Error "Shared test script not found. Please ensure Test-GraphAuthentication.ps1 exists in Scripts directory."
    exit 1
}

function Test-ApplicationPermissionAccess {
    try {
        Write-Host "`n--- Testing Application Permission API Access ---" -ForegroundColor Cyan
        
        Write-Host "Testing Service Principal read access..." -ForegroundColor Yellow
        $TestSPs = Get-MgServicePrincipal -Top 3 -Property Id,DisplayName,AppId,ServicePrincipalType -ErrorAction Stop
        Write-Host "  ✓ Retrieved $($TestSPs.Count) Service Principals" -ForegroundColor Green
        
        if ($TestSPs.Count -gt 0) {
            $TestSP = $TestSPs[0]
            Write-Host "Testing app role assignments for: $($TestSP.DisplayName)" -ForegroundColor Yellow
            
            try {
                $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TestSP.Id -Top 5 -ErrorAction Stop
                Write-Host "  ✓ Retrieved $($AppRoleAssignments.Count) app role assignments" -ForegroundColor Green
            } catch {
                Write-Host "  ⚠️ App role assignment access may be limited: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            Write-Host "Testing OAuth2 permission grants..." -ForegroundColor Yellow
            try {
                $OAuth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($TestSP.Id)'" -Top 5 -ErrorAction Stop
                Write-Host "  ✓ Retrieved $($OAuth2Grants.Count) OAuth2 permission grants" -ForegroundColor Green
            } catch {
                Write-Host "  ⚠️ OAuth2 permission grant access may be limited: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Testing Application read access..." -ForegroundColor Yellow
        $TestApps = Get-MgApplication -Top 3 -Property Id,DisplayName,AppId -ErrorAction Stop
        Write-Host "  ✓ Retrieved $($TestApps.Count) Applications" -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host "  ❌ Application permission API test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-DelegatedPermissionGrantAccess {
    try {
        Write-Host "`nTesting Delegated Permission Grant access..." -ForegroundColor Yellow
        
        # Test reading delegated permission grants directly
        $DelegatedGrantsUri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=5"
        $GrantResponse = Invoke-MgGraphRequest -Method GET -Uri $DelegatedGrantsUri -ErrorAction Stop
        
        Write-Host "  ✓ Retrieved $($GrantResponse.value.Count) delegated permission grants" -ForegroundColor Green
        
        if ($GrantResponse.value.Count -gt 0) {
            $SampleGrant = $GrantResponse.value[0]
            Write-Host "  ✓ Sample grant - Client: $($SampleGrant.clientId), Resource: $($SampleGrant.resourceId)" -ForegroundColor Green
        }
        
        return $true
        
    } catch {
        Write-Host "  ❌ Delegated permission grant access test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-AppRoleAssignmentAccess {
    try {
        Write-Host "`nTesting App Role Assignment access..." -ForegroundColor Yellow
        
        # Test reading app role assignments directly  
        $AppRoleAssignmentsUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName&`$expand=appRoleAssignments(`$top=2)&`$top=3"
        $AssignmentResponse = Invoke-MgGraphRequest -Method GET -Uri $AppRoleAssignmentsUri -ErrorAction Stop
        
        $TotalAssignments = 0
        foreach ($SP in $AssignmentResponse.value) {
            if ($SP.appRoleAssignments) {
                $TotalAssignments += $SP.appRoleAssignments.Count
            }
        }
        
        Write-Host "  ✓ Retrieved app role assignments from $($AssignmentResponse.value.Count) service principals" -ForegroundColor Green
        Write-Host "  ✓ Total assignments found: $TotalAssignments" -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host "  ❌ App role assignment access test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-AuditLogAccess {
    try {
        Write-Host "`nTesting Audit Log access..." -ForegroundColor Yellow
        
        $StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $AuditUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $StartDate&`$top=5"
        $AuditResponse = Invoke-MgGraphRequest -Method GET -Uri $AuditUri -ErrorAction Stop
        
        Write-Host "  ✓ Retrieved $($AuditResponse.value.Count) audit log entries" -ForegroundColor Green
        
        if ($AuditResponse.value.Count -gt 0) {
            $AppSignIns = @($AuditResponse.value | Where-Object { $_.appId -ne $null })
            Write-Host "  ✓ Found $($AppSignIns.Count) application sign-ins for usage analysis" -ForegroundColor Green
        }
        
        return $true
        
    } catch {
        Write-Host "  ❌ Audit log access test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-MailSendPermission {
    try {
        Write-Host "`nTesting Mail.Send permission..." -ForegroundColor Yellow
        
        # Test by checking if we can access the me/sendMail endpoint (this will fail with permission error if not granted)
        $MailTestUri = "https://graph.microsoft.com/v1.0/me"
        $UserResponse = Invoke-MgGraphRequest -Method GET -Uri $MailTestUri -ErrorAction Stop
        
        Write-Host "  ✓ Mail API access available" -ForegroundColor Green
        return $true
        
    } catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Insufficient privileges*") {
            Write-Host "  ⚠️ Mail.Send permission may not be granted" -ForegroundColor Yellow
            return $false
        } else {
            Write-Host "  ✓ Mail API access appears functional" -ForegroundColor Green
            return $true
        }
    }
}

function Test-SpecificPermissions {
    try {
        Write-Host "`n--- Testing Required Permissions ---" -ForegroundColor Cyan
        
        $PermissionTests = @{
            "Application.Read.All" = { Test-ApplicationPermissionAccess }
            "DelegatedPermissionGrant.Read.All" = { Test-DelegatedPermissionGrantAccess }
            "AppRoleAssignment.Read.All" = { Test-AppRoleAssignmentAccess }
            "AuditLog.Read.All" = { Test-AuditLogAccess }
            "Mail.Send" = { Test-MailSendPermission }
        }
        
        $PassedTests = 0
        $TotalTests = $PermissionTests.Count
        
        foreach ($Permission in $PermissionTests.Keys) {
            Write-Host "`nTesting $Permission..." -ForegroundColor Yellow
            
            try {
                $TestResult = & $PermissionTests[$Permission]
                if ($TestResult) {
                    Write-Host "  ✓ $Permission - Functional" -ForegroundColor Green
                    $PassedTests++
                } else {
                    Write-Host "  ⚠️ $Permission - May have issues" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  ❌ $Permission - Failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        Write-Host "`n--- Permission Test Summary ---" -ForegroundColor Cyan
        Write-Host "Passed: $PassedTests/$TotalTests permissions" -ForegroundColor $(if ($PassedTests -eq $TotalTests) { "Green" } else { "Yellow" })
        
        return $PassedTests -eq $TotalTests
        
    } catch {
        Write-Error "Permission testing failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-SamplePermissionAnalysis {
    try {
        Write-Host "`n--- Sample Permission Analysis ---" -ForegroundColor Cyan
        
        Write-Host "Running sample permission risk analysis..." -ForegroundColor Yellow
        
        # Get a few service principals for analysis
        $SampleSPs = Get-MgServicePrincipal -Top 5 -Property Id,DisplayName,AppId,ServicePrincipalType -ErrorAction Stop
        
        $HighRiskPermissions = @(
            "Directory.ReadWrite.All",
            "User.ReadWrite.All", 
            "Application.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory"
        )
        
        $AnalysisResults = @()
        
        foreach ($SP in $SampleSPs) {
            try {
                # Get app role assignments
                $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue
                
                foreach ($Role in $AppRoles) {
                    # Get resource details
                    $Resource = Get-MgServicePrincipal -ServicePrincipalId $Role.ResourceId -ErrorAction SilentlyContinue
                    
                    if ($Resource) {
                        $AppRole = $Resource.AppRoles | Where-Object { $_.Id -eq $Role.AppRoleId }
                        if ($AppRole) {
                            $IsHighRisk = $HighRiskPermissions -contains $AppRole.Value
                            
                            $AnalysisResults += [PSCustomObject]@{
                                Application = $SP.DisplayName
                                Permission = $AppRole.Value
                                Resource = $Resource.DisplayName
                                IsHighRisk = $IsHighRisk
                                Type = "Application"
                            }
                        }
                    }
                }
                
                # Get OAuth2 grants  
                $OAuth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($SP.Id)'" -ErrorAction SilentlyContinue
                
                foreach ($Grant in $OAuth2Grants) {
                    if ($Grant.Scope) {
                        $Scopes = $Grant.Scope -split " " | Where-Object { $_ -ne "" }
                        foreach ($Scope in $Scopes) {
                            $IsHighRisk = $HighRiskPermissions -contains $Scope
                            
                            $AnalysisResults += [PSCustomObject]@{
                                Application = $SP.DisplayName
                                Permission = $Scope
                                Resource = "Microsoft Graph"
                                IsHighRisk = $IsHighRisk
                                Type = "Delegated"
                            }
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not analyze permissions for $($SP.DisplayName): $($_.Exception.Message)"
            }
        }
        
        $TotalPermissions = $AnalysisResults.Count
        $HighRiskCount = @($AnalysisResults | Where-Object { $_.IsHighRisk }).Count
        $ApplicationPermissions = @($AnalysisResults | Where-Object { $_.Type -eq "Application" }).Count
        $DelegatedPermissions = @($AnalysisResults | Where-Object { $_.Type -eq "Delegated" }).Count
        
        Write-Host "✓ Sample analysis completed:" -ForegroundColor Green
        Write-Host "  Total permissions analyzed: $TotalPermissions" -ForegroundColor White
        Write-Host "  High-risk permissions: $HighRiskCount" -ForegroundColor $(if ($HighRiskCount -gt 0) { "Red" } else { "Green" })
        Write-Host "  Application permissions: $ApplicationPermissions" -ForegroundColor White
        Write-Host "  Delegated permissions: $DelegatedPermissions" -ForegroundColor White
        
        if ($HighRiskCount -gt 0) {
            Write-Host "`nHigh-risk permissions found:" -ForegroundColor Yellow
            $AnalysisResults | Where-Object { $_.IsHighRisk } | ForEach-Object {
                Write-Host "  • $($_.Application): $($_.Permission) ($($_.Type))" -ForegroundColor Red
            }
        }
        
        return $true
        
    } catch {
        Write-Host "❌ Sample permission analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
try {
    $RequiredScopes = @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AppRoleAssignment.Read.All",
        "AuditLog.Read.All",
        "Mail.Send"
    )
    
    if ($TestOnly) {
        Write-Host "Running basic connectivity test..." -ForegroundColor Yellow
        $Result = Connect-GraphForTesting -SkipPermissionValidation
    } else {
        Write-Host "Running full authentication with permission validation..." -ForegroundColor Yellow
        $Result = Connect-GraphForTesting -RequiredScopes $RequiredScopes
    }
    
    if ($Result.Success) {
        Write-Host "`n✅ Microsoft Graph connection successful!" -ForegroundColor Green
        
        # Run specific permission tests
        $PermissionTestsPassed = Test-SpecificPermissions
        
        # Run sample permission analysis
        $AnalysisTestPassed = Test-SamplePermissionAnalysis
        
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Application Permission Auditor" -ForegroundColor Cyan
        Write-Host "Test Results Summary" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        if ($PermissionTestsPassed -and $AnalysisTestPassed) {
            Write-Host "✅ All tests passed - Ready for application permission auditing!" -ForegroundColor Green
            Write-Host "`nYou can now run the main script:" -ForegroundColor Green
            Write-Host "  .\ApplicationPermissionAuditor.ps1" -ForegroundColor Gray
            Write-Host "`nRecommended first run:" -ForegroundColor Yellow
            Write-Host "  .\ApplicationPermissionAuditor.ps1 -WhatIf -IncludeOAuthConsents" -ForegroundColor Gray
        } else {
            Write-Host "⚠️ Some tests failed - Review permissions and configuration" -ForegroundColor Yellow
            Write-Host "`nCommon issues:" -ForegroundColor Yellow
            Write-Host "  - Missing Microsoft Graph API permissions" -ForegroundColor Gray
            Write-Host "  - Admin consent not granted" -ForegroundColor Gray
            Write-Host "  - Service Principal not configured correctly" -ForegroundColor Gray
            Write-Host "  - DelegatedPermissionGrant.Read.All permission missing" -ForegroundColor Gray
            Write-Host "  - AppRoleAssignment.Read.All permission missing" -ForegroundColor Gray
        }
        
    } else {
        Write-Host "`n❌ Connection test failed: $($Result.Error)" -ForegroundColor Red
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Verify tenant ID, client ID, and client secret" -ForegroundColor Gray
        Write-Host "  2. Check Azure app registration configuration" -ForegroundColor Gray
        Write-Host "  3. Ensure required permissions are granted with admin consent" -ForegroundColor Gray
        Write-Host "  4. Verify DelegatedPermissionGrant.Read.All and AppRoleAssignment.Read.All permissions" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Test execution failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-GraphForTesting
    }
}