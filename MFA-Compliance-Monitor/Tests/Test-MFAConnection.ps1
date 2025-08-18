# Test-MFAConnection.ps1
# Script to test Microsoft Graph API connection and permissions for MFA compliance monitoring

# Application credentials - Replace with your values or use secure methods
$ClientId = "YOUR_CLIENT_ID_HERE"
$TenantId = "YOUR_TENANT_ID_HERE"
$ClientSecret = "YOUR_CLIENT_SECRET_HERE"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "MFA Compliance Monitor - Connection Test" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow
Write-Host "Client ID: $ClientId" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

try {
    # Install required module if not present
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Host "Installing Microsoft Graph PowerShell module..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }

    # Import modules
    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Reports
    Import-Module Microsoft.Graph.Users

    # Connect to Microsoft Graph
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
    
    if ($ClientId -ne "YOUR_CLIENT_ID_HERE" -and $TenantId -ne "YOUR_TENANT_ID_HERE" -and $ClientSecret -ne "YOUR_CLIENT_SECRET_HERE") {
        # Use provided credentials
        $SecureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureClientSecret)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
    } else {
        # Use interactive authentication with required scopes
        Connect-MgGraph -Scopes "AuditLog.Read.All","User.Read.All","Mail.Send","Directory.Read.All" -NoWelcome
    }

    # Verify connection
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }

    Write-Host "`n✓ Successfully connected to Microsoft Graph!" -ForegroundColor Green
    Write-Host "Connected Tenant: $($Context.TenantId)" -ForegroundColor Green
    Write-Host "Authentication Type: $($Context.AuthType)" -ForegroundColor Green
    Write-Host "Scopes: $($Context.Scopes -join ', ')" -ForegroundColor Green

    # Test required permissions
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Required Permissions" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    $RequiredPermissions = @{
        "AuditLog.Read.All" = $false
        "User.Read.All" = $false
        "Mail.Send" = $false
        "Directory.Read.All" = $false
    }

    $CurrentScopes = $Context.Scopes
    $AllPermissionsValid = $true

    foreach ($Permission in $RequiredPermissions.Keys) {
        $HasPermission = $CurrentScopes -contains $Permission
        $RequiredPermissions[$Permission] = $HasPermission
        
        if ($HasPermission) {
            Write-Host "  ✓ $Permission - Granted" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $Permission - Missing or not granted" -ForegroundColor Red
            $AllPermissionsValid = $false
        }
    }

    # Test sign-in logs access
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Sign-In Logs Access" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        $StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
        $Filter = "createdDateTime ge $StartDate and signInEventTypes/any(t: t eq 'interactiveUser')"
        
        Write-Host "Testing sign-in log query (last 7 days)..." -ForegroundColor Yellow
        $TestUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$top=5"
        $TestResponse = Invoke-MgGraphRequest -Method GET -Uri $TestUri
        
        Write-Host "✓ Successfully retrieved sign-in logs" -ForegroundColor Green
        Write-Host "Sample records found: $($TestResponse.value.Count)" -ForegroundColor Yellow
        
        if ($TestResponse.value.Count -gt 0) {
            Write-Host "`nSample sign-in record details:" -ForegroundColor Cyan
            $SampleRecord = $TestResponse.value[0]
            Write-Host "  User: $($SampleRecord.userDisplayName)" -ForegroundColor Gray
            Write-Host "  Date: $($SampleRecord.createdDateTime)" -ForegroundColor Gray
            Write-Host "  Auth Requirement: $($SampleRecord.authenticationRequirement)" -ForegroundColor Gray
            
            if ($SampleRecord.authenticationMethodsUsed) {
                Write-Host "  MFA Methods: $($SampleRecord.authenticationMethodsUsed -join ', ')" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ Failed to retrieve sign-in logs: $_" -ForegroundColor Red
        Write-Host "Please ensure the app has 'AuditLog.Read.All' permission" -ForegroundColor Yellow
        $AllPermissionsValid = $false
    }

    # Test user information access
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing User Information Access" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        $TestUsers = Get-MgUser -Top 3 -Property DisplayName,UserPrincipalName,Mail -ErrorAction Stop
        Write-Host "✓ Successfully retrieved user information" -ForegroundColor Green
        Write-Host "Sample users found: $($TestUsers.Count)" -ForegroundColor Yellow
        
        if ($TestUsers.Count -gt 0) {
            Write-Host "`nSample users:" -ForegroundColor Cyan
            $TestUsers | ForEach-Object {
                Write-Host "  - $($_.DisplayName) ($($_.UserPrincipalName))" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ Failed to retrieve user information: $_" -ForegroundColor Red
        Write-Host "Please ensure the app has 'User.Read.All' permission" -ForegroundColor Yellow
        $AllPermissionsValid = $false
    }

    # Test MFA method analysis
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing MFA Method Analysis" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        # Get recent MFA sign-ins
        $StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
        $MFAFilter = "createdDateTime ge $StartDate and authenticationRequirement eq 'multiFactorAuthentication'"
        $MFAUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$MFAFilter&`$top=10"
        
        Write-Host "Analyzing MFA methods used in last 7 days..." -ForegroundColor Yellow
        $MFAResponse = Invoke-MgGraphRequest -Method GET -Uri $MFAUri
        
        Write-Host "✓ Successfully analyzed MFA sign-ins" -ForegroundColor Green
        Write-Host "MFA sign-ins found: $($MFAResponse.value.Count)" -ForegroundColor Yellow
        
        if ($MFAResponse.value.Count -gt 0) {
            # Analyze methods used
            $MethodCounts = @{}
            $MFAResponse.value | ForEach-Object {
                if ($_.authenticationMethodsUsed) {
                    $_.authenticationMethodsUsed | ForEach-Object {
                        if ($MethodCounts.ContainsKey($_)) {
                            $MethodCounts[$_]++
                        } else {
                            $MethodCounts[$_] = 1
                        }
                    }
                }
            }
            
            Write-Host "`nMFA methods detected:" -ForegroundColor Cyan
            $MethodCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                $IsCompliant = $_.Key -in @("microsoftAuthenticatorPush", "microsoftAuthenticatorOTP")
                $Status = if ($IsCompliant) { "✓ Compliant" } else { "⚠ Non-Compliant" }
                $Color = if ($IsCompliant) { "Green" } else { "Yellow" }
                Write-Host "  $($_.Key): $($_.Value) uses - $Status" -ForegroundColor $Color
            }
            
            # Calculate compliance rate
            $CompliantMethods = @("microsoftAuthenticatorPush", "microsoftAuthenticatorOTP")
            $CompliantUses = ($MethodCounts.GetEnumerator() | Where-Object { $_.Key -in $CompliantMethods } | Measure-Object Value -Sum).Sum
            $TotalUses = ($MethodCounts.Values | Measure-Object -Sum).Sum
            $ComplianceRate = if ($TotalUses -gt 0) { [math]::Round(($CompliantUses / $TotalUses) * 100, 2) } else { 0 }
            
            Write-Host "`nCurrent MFA compliance rate: $ComplianceRate%" -ForegroundColor $(if ($ComplianceRate -ge 90) { "Green" } elseif ($ComplianceRate -ge 70) { "Yellow" } else { "Red" })
        } else {
            Write-Host "No MFA sign-ins found in the last 7 days" -ForegroundColor Yellow
            Write-Host "This might be normal for smaller organizations or test environments" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "✗ Failed to analyze MFA methods: $_" -ForegroundColor Red
        Write-Host "This may indicate permission issues or no MFA sign-ins available" -ForegroundColor Yellow
    }

    # Test email sending capability (simulation)
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Email Capability" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    if ($CurrentScopes -contains "Mail.Send") {
        Write-Host "✓ Mail.Send permission is available" -ForegroundColor Green
        Write-Host "Email notifications can be sent to users and administrators" -ForegroundColor Gray
        Write-Host "Note: Actual email sending is not tested to avoid spam" -ForegroundColor Yellow
    } else {
        Write-Host "✗ Mail.Send permission is missing" -ForegroundColor Red
        Write-Host "Email notifications will not work without this permission" -ForegroundColor Yellow
    }

    # Summary and recommendations
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Connection Test Summary" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    if ($AllPermissionsValid) {
        Write-Host "✅ All tests passed! MFA Compliance Monitor is ready to use." -ForegroundColor Green
        Write-Host "`nRecommended next steps:" -ForegroundColor Cyan
        Write-Host "1. Run the MFA Compliance Monitor in WhatIf mode" -ForegroundColor White
        Write-Host "2. Review the generated reports" -ForegroundColor White
        Write-Host "3. Configure exclusion lists if needed" -ForegroundColor White
        Write-Host "4. Set up regular scheduled execution" -ForegroundColor White
    } else {
        Write-Host "⚠️ Some tests failed. Please address the permission issues above." -ForegroundColor Yellow
        Write-Host "`nRequired actions:" -ForegroundColor Cyan
        Write-Host "1. Grant missing Graph API permissions" -ForegroundColor White
        Write-Host "2. Ensure admin consent is provided" -ForegroundColor White
        Write-Host "3. Re-run this test after fixing permissions" -ForegroundColor White
    }

    Write-Host "`nFor production deployment:" -ForegroundColor Cyan
    Write-Host "- Use managed identity instead of client credentials" -ForegroundColor White
    Write-Host "- Configure regular automated execution" -ForegroundColor White
    Write-Host "- Set up monitoring and alerting" -ForegroundColor White
    Write-Host "- Review and customize email templates" -ForegroundColor White

}
catch {
    Write-Host "`n✗ Connection test failed: $_" -ForegroundColor Red
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Verify the Client ID and Tenant ID are correct" -ForegroundColor Yellow
    Write-Host "2. Ensure the client secret hasn't expired" -ForegroundColor Yellow
    Write-Host "3. Confirm the app registration has the required API permissions:" -ForegroundColor Yellow
    Write-Host "   - AuditLog.Read.All (Application)" -ForegroundColor Yellow
    Write-Host "   - User.Read.All (Application)" -ForegroundColor Yellow
    Write-Host "   - Mail.Send (Application)" -ForegroundColor Yellow
    Write-Host "   - Directory.Read.All (Application)" -ForegroundColor Yellow
    Write-Host "4. Make sure admin consent has been granted for the permissions" -ForegroundColor Yellow
    Write-Host "5. Check if your account has sufficient privileges to read audit logs" -ForegroundColor Yellow
}
finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected" -ForegroundColor Green
    }
}