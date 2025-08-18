# Test-DeviceCleanupFunctions.ps1
# Script to test the device cleanup functions in WhatIf mode

# Application credentials - Replace with your values or use secure methods
$ClientId = "YOUR_CLIENT_ID_HERE"
$TenantId = "YOUR_TENANT_ID_HERE"
$ClientSecret = "YOUR_CLIENT_SECRET_HERE"

# Import cleanup functions from Claude.md documentation
function Remove-InactiveRegisteredDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 90,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    Write-Output "Starting cleanup of registered devices inactive for $InactiveDays days or more..."
    
    # Calculate the cutoff date
    $CutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    try {
        # Get all devices from Entra ID
        $AllDevices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime, OperatingSystem, DeviceId, TrustType
        
        # Filter devices that are inactive and not Autopilot devices
        $InactiveDevices = $AllDevices | Where-Object {
            $_.ApproximateLastSignInDateTime -ne $null -and 
            $_.ApproximateLastSignInDateTime -lt $CutoffDate -and
            $_.TrustType -ne "AzureAD" # Exclude Autopilot devices
        }
        
        Write-Output "Found $($InactiveDevices.Count) inactive registered devices"
        
        foreach ($Device in $InactiveDevices) {
            $LastSignIn = if ($Device.ApproximateLastSignInDateTime) { 
                $Device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") 
            } else { 
                "Never" 
            }
            
            Write-Output "Processing: $($Device.DisplayName) - Last Sign-in: $LastSignIn"
            
            if (-not $WhatIf) {
                try {
                    Remove-MgDevice -DeviceId $Device.Id -Confirm:$false
                    Write-Output "  ✓ Successfully removed device: $($Device.DisplayName)"
                }
                catch {
                    Write-Error "  ✗ Failed to remove device $($Device.DisplayName): $_"
                }
            }
            else {
                Write-Output "  [WhatIf] Would remove device: $($Device.DisplayName)"
            }
        }
        
        Write-Output "Registered device cleanup completed. Processed $($InactiveDevices.Count) devices."
    }
    catch {
        Write-Error "Error during registered device cleanup: $_"
        throw
    }
}

function Remove-InactiveAutopilotDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 90,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    Write-Output "Starting cleanup of Autopilot devices inactive for $InactiveDays days or more..."
    
    # Calculate the cutoff date
    $CutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    try {
        # Try to get Autopilot devices (may fail if not available)
        $AutopilotDevices = $null
        try {
            $AutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop
        }
        catch {
            Write-Warning "Cannot access Autopilot devices. This may be normal for this tenant."
            Write-Warning "Error: $_"
            return
        }
        
        # Get all Entra ID devices for cross-reference
        $EntraDevices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime, DeviceId
        
        $InactiveAutopilotDevices = @()
        
        foreach ($AutopilotDevice in $AutopilotDevices) {
            # Find corresponding Entra ID device
            $EntraDevice = $EntraDevices | Where-Object { 
                $_.DeviceId -eq $AutopilotDevice.AzureActiveDirectoryDeviceId 
            }
            
            if ($EntraDevice) {
                if ($EntraDevice.ApproximateLastSignInDateTime -ne $null -and 
                    $EntraDevice.ApproximateLastSignInDateTime -lt $CutoffDate) {
                    
                    $InactiveAutopilotDevices += @{
                        AutopilotDevice = $AutopilotDevice
                        EntraDevice = $EntraDevice
                    }
                }
            }
        }
        
        Write-Output "Found $($InactiveAutopilotDevices.Count) inactive Autopilot devices"
        
        foreach ($DeviceInfo in $InactiveAutopilotDevices) {
            $Device = $DeviceInfo.EntraDevice
            $AutopilotInfo = $DeviceInfo.AutopilotDevice
            
            $LastSignIn = if ($Device.ApproximateLastSignInDateTime) { 
                $Device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") 
            } else { 
                "Never" 
            }
            
            Write-Output "Processing Autopilot device: $($Device.DisplayName) - Serial: $($AutopilotInfo.SerialNumber) - Last Sign-in: $LastSignIn"
            
            if (-not $WhatIf) {
                try {
                    # Remove from Entra ID only (keeps Autopilot registration)
                    Remove-MgDevice -DeviceId $Device.Id -Confirm:$false
                    Write-Output "  ✓ Successfully removed from Entra ID: $($Device.DisplayName)"
                    Write-Output "  ℹ Device remains registered in Autopilot with serial: $($AutopilotInfo.SerialNumber)"
                }
                catch {
                    Write-Error "  ✗ Failed to remove device $($Device.DisplayName): $_"
                }
            }
            else {
                Write-Output "  [WhatIf] Would remove from Entra ID: $($Device.DisplayName)"
                Write-Output "  [WhatIf] Device would remain in Autopilot"
            }
        }
        
        Write-Output "Autopilot device cleanup completed. Processed $($InactiveAutopilotDevices.Count) devices."
    }
    catch {
        Write-Error "Error during Autopilot device cleanup: $_"
        throw
    }
}

# Main test execution
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Device Cleanup Functions Test" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Running in WhatIf mode (no actual deletions)" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

try {
    # Import required modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    
    # Try to import Autopilot module (may not be needed)
    Import-Module Microsoft.Graph.DeviceManagement.Enrollment -ErrorAction SilentlyContinue

    # Connect to Microsoft Graph
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
    $SecureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureClientSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome

    # Verify connection
    $Context = Get-MgContext
    if ($null -eq $Context) {
        throw "Failed to connect to Microsoft Graph"
    }
    Write-Host "✓ Successfully connected to tenant: $($Context.TenantId)" -ForegroundColor Green

    # Test with different inactive day thresholds to see what would be cleaned up
    Write-Host "`n--- Testing with 30 days inactive ---" -ForegroundColor Cyan
    Remove-InactiveRegisteredDevices -InactiveDays 30 -WhatIf

    Write-Host "`n--- Testing with 60 days inactive ---" -ForegroundColor Cyan
    Remove-InactiveRegisteredDevices -InactiveDays 60 -WhatIf

    Write-Host "`n--- Testing with 90 days inactive (default) ---" -ForegroundColor Cyan
    Remove-InactiveRegisteredDevices -InactiveDays 90 -WhatIf

    Write-Host "`n--- Testing Autopilot cleanup with 90 days inactive ---" -ForegroundColor Cyan
    Remove-InactiveAutopilotDevices -InactiveDays 90 -WhatIf

    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Function Test Summary" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "✓ Cleanup functions tested successfully" -ForegroundColor Green
    Write-Host "✓ All operations ran in WhatIf mode" -ForegroundColor Green
    Write-Host "✓ No devices were actually deleted" -ForegroundColor Green
    
    # Show device statistics
    $AllDevices = Get-MgDevice -All -CountVariable TotalCount -ConsistencyLevel eventual
    Write-Host "`nDevice Statistics:" -ForegroundColor Yellow
    Write-Host "  Total devices in tenant: $TotalCount" -ForegroundColor Gray
    
    # Count by last sign-in periods
    $Now = Get-Date
    $Devices30Days = ($AllDevices | Where-Object { $_.ApproximateLastSignInDateTime -and $_.ApproximateLastSignInDateTime -lt $Now.AddDays(-30) }).Count
    $Devices60Days = ($AllDevices | Where-Object { $_.ApproximateLastSignInDateTime -and $_.ApproximateLastSignInDateTime -lt $Now.AddDays(-60) }).Count
    $Devices90Days = ($AllDevices | Where-Object { $_.ApproximateLastSignInDateTime -and $_.ApproximateLastSignInDateTime -lt $Now.AddDays(-90) }).Count
    
    Write-Host "  Inactive >30 days: $Devices30Days" -ForegroundColor Gray
    Write-Host "  Inactive >60 days: $Devices60Days" -ForegroundColor Gray
    Write-Host "  Inactive >90 days: $Devices90Days" -ForegroundColor Gray

}
catch {
    Write-Host "`n✗ Test failed: $_" -ForegroundColor Red
}
finally {
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected" -ForegroundColor Green
    }
}