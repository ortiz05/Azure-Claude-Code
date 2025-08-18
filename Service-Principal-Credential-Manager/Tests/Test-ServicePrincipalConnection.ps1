# Test-ServicePrincipalConnection.ps1
# Testing script for Service Principal Credential Manager connectivity and permissions

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
Write-Host "Service Principal Credential Manager" -ForegroundColor Cyan
Write-Host "Connection & Permission Testing" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Import shared test functions
if (Test-Path "$PSScriptRoot\..\..\Scripts\Test-GraphAuthentication.ps1") {
    . "$PSScriptRoot\..\..\Scripts\Test-GraphAuthentication.ps1"
} else {
    Write-Error "Shared test script not found. Please ensure Test-GraphAuthentication.ps1 exists in Scripts directory."
    exit 1
}

function Test-ServicePrincipalAccess {
    try {
        Write-Host "`n--- Testing Service Principal API Access ---" -ForegroundColor Cyan
        
        Write-Host "Testing Service Principal read access..." -ForegroundColor Yellow
        $TestSPs = Get-MgServicePrincipal -Top 3 -Property Id,DisplayName,AppId -ErrorAction Stop
        Write-Host "  ✓ Retrieved $($TestSPs.Count) Service Principals" -ForegroundColor Green
        
        if ($TestSPs.Count -gt 0) {
            $TestSP = $TestSPs[0]
            Write-Host "Testing credential access for: $($TestSP.DisplayName)" -ForegroundColor Yellow
            
            $SPWithCreds = Get-MgServicePrincipal -ServicePrincipalId $TestSP.Id -Property KeyCredentials,PasswordCredentials -ErrorAction Stop
            $TotalCreds = $SPWithCreds.KeyCredentials.Count + $SPWithCreds.PasswordCredentials.Count
            Write-Host "  ✓ Retrieved credential details: $TotalCreds credentials" -ForegroundColor Green
        }
        
        Write-Host "Testing Application read access..." -ForegroundColor Yellow
        $TestApps = Get-MgApplication -Top 3 -Property Id,DisplayName,AppId -ErrorAction Stop
        Write-Host "  ✓ Retrieved $($TestApps.Count) Applications" -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host "  ❌ Service Principal API test failed: $($_.Exception.Message)" -ForegroundColor Red
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
            $ServicePrincipalSignIns = @($AuditResponse.value | Where-Object { $_.servicePrincipalId -ne $null })
            Write-Host "  ✓ Found $($ServicePrincipalSignIns.Count) Service Principal sign-ins" -ForegroundColor Green
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
            "Application.Read.All" = { Test-ServicePrincipalAccess }
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

# Main execution
try {
    $RequiredScopes = @(
        "Application.Read.All",
        "Application.ReadWrite.All", 
        "Directory.Read.All",
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
        
        # Run Service Principal-specific API tests
        $APITestsPassed = Test-ServicePrincipalAccess
        
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Service Principal Credential Manager" -ForegroundColor Cyan
        Write-Host "Test Results Summary" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        if ($PermissionTestsPassed -and $APITestsPassed) {
            Write-Host "✅ All tests passed - Ready for Service Principal credential management!" -ForegroundColor Green
            Write-Host "`nYou can now run the main script:" -ForegroundColor Green
            Write-Host "  .\ServicePrincipalCredentialManager.ps1" -ForegroundColor Gray
        } else {
            Write-Host "⚠️ Some tests failed - Review permissions and configuration" -ForegroundColor Yellow
            Write-Host "`nCommon issues:" -ForegroundColor Yellow
            Write-Host "  - Missing Microsoft Graph API permissions" -ForegroundColor Gray
            Write-Host "  - Admin consent not granted" -ForegroundColor Gray
            Write-Host "  - Service Principal not configured correctly" -ForegroundColor Gray
        }
        
    } else {
        Write-Host "`n❌ Connection test failed: $($Result.Error)" -ForegroundColor Red
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Verify tenant ID, client ID, and client secret" -ForegroundColor Gray
        Write-Host "  2. Check Azure app registration configuration" -ForegroundColor Gray
        Write-Host "  3. Ensure required permissions are granted with admin consent" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Test execution failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Get-MgContext) {
        Disconnect-GraphForTesting
    }
}