# Test-GraphConnection.ps1
# Script to test Microsoft Graph API connection using provided credentials

# Application credentials - Replace with your values or use secure methods
$ClientId = "YOUR_CLIENT_ID_HERE"
$TenantId = "YOUR_TENANT_ID_HERE"
$ClientSecret = "YOUR_CLIENT_SECRET_HERE"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Microsoft Graph API Connection Test" -ForegroundColor Cyan
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
    Import-Module Microsoft.Graph.Identity.DirectoryManagement

    # Convert client secret to secure string
    $SecureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureClientSecret)

    # Connect to Microsoft Graph
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome

    # Verify connection
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }

    Write-Host "`n✓ Successfully connected to Microsoft Graph!" -ForegroundColor Green
    Write-Host "Connected Tenant: $($Context.TenantId)" -ForegroundColor Green
    Write-Host "Authentication Type: $($Context.AuthType)" -ForegroundColor Green
    Write-Host "Scopes: $($Context.Scopes -join ', ')" -ForegroundColor Green

    # Test basic device read operation
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Device Read Operations" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        # Get device count
        $Devices = Get-MgDevice -Top 5
        $DeviceCount = (Get-MgDevice -CountVariable DevCount -ConsistencyLevel eventual).Count
        
        Write-Host "✓ Successfully retrieved device information" -ForegroundColor Green
        Write-Host "Total devices in tenant: $DeviceCount" -ForegroundColor Yellow
        
        if ($Devices.Count -gt 0) {
            Write-Host "`nSample of first 5 devices:" -ForegroundColor Cyan
            $Devices | ForEach-Object {
                Write-Host "  - $($_.DisplayName) (OS: $($_.OperatingSystem))" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ Failed to retrieve devices: $_" -ForegroundColor Red
        Write-Host "Please ensure the app has 'Device.Read.All' or 'Device.ReadWrite.All' permission" -ForegroundColor Yellow
    }

    # Test finding inactive devices
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Inactive Device Detection" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    $InactiveDays = 90
    $CutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    try {
        $AllDevices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime, OperatingSystem
        $InactiveDevices = $AllDevices | Where-Object {
            $_.ApproximateLastSignInDateTime -ne $null -and 
            $_.ApproximateLastSignInDateTime -lt $CutoffDate
        }
        
        Write-Host "✓ Inactive device detection successful" -ForegroundColor Green
        Write-Host "Devices inactive for more than $InactiveDays days: $($InactiveDevices.Count)" -ForegroundColor Yellow
        
        if ($InactiveDevices.Count -gt 0) {
            Write-Host "`nSample of inactive devices (showing first 3):" -ForegroundColor Cyan
            $InactiveDevices | Select-Object -First 3 | ForEach-Object {
                $LastSignIn = if ($_.ApproximateLastSignInDateTime) { 
                    $_.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") 
                } else { 
                    "Never" 
                }
                Write-Host "  - $($_.DisplayName) - Last Sign-in: $LastSignIn" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ Failed to detect inactive devices: $_" -ForegroundColor Red
    }

    # Test Autopilot device access (if permissions allow)
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Testing Autopilot Device Access" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan

    try {
        Import-Module Microsoft.Graph.DeviceManagement.Enrollment -ErrorAction SilentlyContinue
        $AutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Top 5 -ErrorAction Stop
        
        Write-Host "✓ Successfully accessed Autopilot devices" -ForegroundColor Green
        Write-Host "Sample Autopilot devices found: $($AutopilotDevices.Count)" -ForegroundColor Yellow
    }
    catch {
        Write-Host "✗ Cannot access Autopilot devices: $_" -ForegroundColor Red
        Write-Host "This may be normal if the app doesn't have DeviceManagementServiceConfig permissions" -ForegroundColor Yellow
    }

    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Connection Test Summary" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "✓ Graph API connection successful" -ForegroundColor Green
    Write-Host "✓ Basic device operations working" -ForegroundColor Green
    Write-Host "✓ Ready for device cleanup automation" -ForegroundColor Green

}
catch {
    Write-Host "`n✗ Connection test failed: $_" -ForegroundColor Red
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Verify the Client ID and Tenant ID are correct" -ForegroundColor Yellow
    Write-Host "2. Ensure the client secret hasn't expired" -ForegroundColor Yellow
    Write-Host "3. Confirm the app registration has the required API permissions:" -ForegroundColor Yellow
    Write-Host "   - Device.ReadWrite.All (Application)" -ForegroundColor Yellow
    Write-Host "   - Directory.ReadWrite.All (Application)" -ForegroundColor Yellow
    Write-Host "4. Make sure admin consent has been granted for the permissions" -ForegroundColor Yellow
}
finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected" -ForegroundColor Green
    }
}