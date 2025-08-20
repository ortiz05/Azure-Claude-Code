# Deploy-ApplicationPermissionAuditor.ps1
# Azure Automation deployment script for Application Permission Auditor

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Automation

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$RunbookName = "ApplicationPermissionAuditor",
    
    [Parameter(Mandatory = $false)]
    [string]$ScheduleName = "ApplicationPermissionAuditor-Weekly",
    
    [Parameter(Mandatory = $false)]
    [string]$StartTime = "06:00:00",
    
    [Parameter(Mandatory = $false)]
    [string]$TimeZone = "UTC",
    
    [Parameter(Mandatory = $false)]
    [string[]]$SecurityTeamEmails = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationEmailFrom = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableSchedule = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# PowerShell and module compatibility validation
function Test-PowerShellCompatibility {
    Write-Host "Validating PowerShell compatibility..." -ForegroundColor Yellow
    
    # Check PowerShell version
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -lt 7) {
        Write-Error @"
PowerShell 7.0 or later is required for this script.
Current version: $($PSVersion.ToString())
Please install PowerShell 7 from: https://github.com/PowerShell/PowerShell/releases
"@
        return $false
    }
    Write-Host "✓ PowerShell version: $($PSVersion.ToString())" -ForegroundColor Green
    
    # Check required Azure modules
    $RequiredModules = @('Az.Accounts', 'Az.Automation')
    $MissingModules = @()
    
    foreach ($Module in $RequiredModules) {
        $ModuleInfo = Get-Module -Name $Module -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($ModuleInfo) {
            Write-Host "✓ $Module version: $($ModuleInfo.Version)" -ForegroundColor Green
        } else {
            $MissingModules += $Module
            Write-Warning "✗ Missing module: $Module"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Error @"
Missing required Azure PowerShell modules: $($MissingModules -join ', ')
Install missing modules with:
Install-Module -Name $($MissingModules -join ', ') -Scope CurrentUser -Force
"@
        return $false
    }
    
    # Check if running in Windows PowerShell (not supported)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Write-Error @"
Windows PowerShell (Desktop edition) is not supported.
Please use PowerShell 7+ (Core edition).
Download from: https://github.com/PowerShell/PowerShell/releases
"@
        return $false
    }
    
    Write-Host "✓ PowerShell compatibility validation passed" -ForegroundColor Green
    return $true
}

# Validate compatibility before proceeding
if (-not (Test-PowerShellCompatibility)) {
    exit 1
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Application Permission Auditor Deployment" -ForegroundColor Cyan
Write-Host "Azure Automation Configuration" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Yellow
Write-Host "Runbook Name: $RunbookName" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Required PowerShell modules for the runbook
$RequiredModules = @(
    @{Name = "Microsoft.Graph.Authentication"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Applications"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Identity.SignIns"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Reports"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Mail"; Version = "2.15.0"}
)

# Required Microsoft Graph permissions
$RequiredPermissions = @(
    "Application.Read.All",
    "Directory.Read.All", 
    "DelegatedPermissionGrant.Read.All",
    "AppRoleAssignment.ReadWrite.All",
    "AuditLog.Read.All",
    "Mail.Send"
)

function Connect-ToAzure {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        
        # Connect to Azure
        $Context = Get-AzContext
        if (-not $Context -or $Context.Subscription.Id -ne $SubscriptionId) {
            Connect-AzAccount -SubscriptionId $SubscriptionId
        }
        
        Write-Host "✓ Connected to Azure subscription: $SubscriptionId" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        throw
    }
}

function Test-AutomationAccount {
    try {
        Write-Host "Validating Azure Automation Account..." -ForegroundColor Yellow
        
        $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        
        if (-not $AutomationAccount) {
            throw "Automation Account '$AutomationAccountName' not found in resource group '$ResourceGroupName'"
        }
        
        Write-Host "✓ Automation Account validated: $($AutomationAccount.AutomationAccountName)" -ForegroundColor Green
        Write-Host "  Location: $($AutomationAccount.Location)" -ForegroundColor Gray
        Write-Host "  Resource Group: $($AutomationAccount.ResourceGroupName)" -ForegroundColor Gray
        
        return $AutomationAccount
        
    } catch {
        Write-Error "Automation Account validation failed: $($_.Exception.Message)"
        throw
    }
}

function Install-RequiredModules {
    try {
        Write-Host "Installing required PowerShell modules..." -ForegroundColor Yellow
        
        foreach ($Module in $RequiredModules) {
            Write-Host "Installing module: $($Module.Name) (v$($Module.Version))..." -ForegroundColor Gray
            
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would install module: $($Module.Name)" -ForegroundColor Yellow
            } else {
                $ImportJob = Import-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $Module.Name `
                    -ModuleVersion $Module.Version
                
                Write-Host "  ✓ Import job started for $($Module.Name)" -ForegroundColor Green
            }
        }
        
        if (-not $WhatIf) {
            Write-Host "⚠️ Module installation started - this may take 15-30 minutes" -ForegroundColor Yellow
            Write-Host "   Monitor progress in Azure Portal: Automation Account → Modules" -ForegroundColor Gray
        }
        
    } catch {
        Write-Error "Failed to install required modules: $($_.Exception.Message)"
        throw
    }
}

function Create-RunbookContent {
    # Read the full Application Permission Auditor script content
    $MainScriptPath = "$PSScriptRoot\ApplicationPermissionAuditor.ps1"
    if (-not (Test-Path $MainScriptPath)) {
        throw "Main Application Permission Auditor script not found at: $MainScriptPath"
    }
    
    # Get the main script content and remove the param block since we'll handle parameters differently
    $MainScriptContent = Get-Content $MainScriptPath -Raw
    
    # Remove the original param block and CmdletBinding from the main script
    $MainScriptContent = $MainScriptContent -replace '(?s)^[^#]*\[CmdletBinding\(\)\].*?^\)', ''
    $MainScriptContent = $MainScriptContent -replace '(?s)^param\(.*?^\)', ''
    
    # Create the runbook content with embedded main script
    $RunbookContent = @"
#Requires -Version 7.4

# Application Permission Auditor - Azure Automation Runbook
# This runbook performs enterprise-wide application permission auditing
# PowerShell 7+ Compatible with Microsoft Graph modules

param(
    [string]`$SecurityTeamEmails = "$($SecurityTeamEmails -join ',')",
    [string]`$ITAdminEmails = "$($ITAdminEmails -join ',')",
    [string]`$NotificationEmailFrom = "$NotificationEmailFrom",
    [bool]`$WhatIf = `$true,
    [bool]`$SendNotifications = `$true,
    [bool]`$IncludeOAuthConsents = `$true,
    [bool]`$GenerateExecutiveSummary = `$true,
    [bool]`$AnalyzePermissionTrends = `$true
)

`$ErrorActionPreference = "Stop"

Write-Output "========================================="
Write-Output "Application Permission Auditor - Azure Automation"
Write-Output "PowerShell Version: `$(`$PSVersionTable.PSVersion)"
Write-Output "Started at: `$(Get-Date)"
Write-Output "========================================="

try {
    # Import required modules for PowerShell 7 compatibility
    Write-Output "Importing Microsoft Graph modules..."
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Applications -Force
    Import-Module Microsoft.Graph.Identity.SignIns -Force
    Import-Module Microsoft.Graph.Reports -Force
    Import-Module Microsoft.Graph.Mail -Force
    Write-Output "✓ Modules imported successfully"
    
    # Convert email parameters back to arrays for main script
    `$SecurityTeamEmailArray = if (`$SecurityTeamEmails) { `$SecurityTeamEmails -split ',' -ne '' } else { @() }
    `$ITAdminEmailArray = if (`$ITAdminEmails) { `$ITAdminEmails -split ',' -ne '' } else { @() }
    
    Write-Output "Executing Application Permission Auditor with managed identity..."
    Write-Output "Security Team Emails: `$(`$SecurityTeamEmailArray.Count) addresses"
    Write-Output "IT Admin Emails: `$(`$ITAdminEmailArray.Count) addresses"
    Write-Output "WhatIf Mode: `$WhatIf"
    
    # Set variables that the main script expects
    `$TenantId = `$env:AZURE_TENANT_ID
    `$ClientId = `$env:AZURE_CLIENT_ID
    `$ClientSecret = `$env:AZURE_CLIENT_SECRET
    `$ExcludeApplications = @()
    `$ReportPath = "C:\temp\Reports"
    `$StorageAccountName = `$null
    `$StorageContainerName = "permission-audit-reports"
    `$UseManagedIdentity = `$true
    `$HighRiskPermissions = @(
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
    )
    `$AdminConsentRequiredPermissions = @(
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
    
    # Create reports directory
    if (-not (Test-Path `$ReportPath)) {
        New-Item -Path `$ReportPath -ItemType Directory -Force | Out-Null
    }
    
    #############################################################################
    # EMBEDDED APPLICATION PERMISSION AUDITOR SCRIPT
    #############################################################################
    
$MainScriptContent
    
    #############################################################################
    # END EMBEDDED SCRIPT
    #############################################################################
    
    Write-Output "✓ Application Permission Auditor completed successfully"
    
} catch {
    Write-Error "Application Permission Auditor failed: `$(`$_.Exception.Message)"
    Write-Output "Stack Trace: `$(`$_.ScriptStackTrace)"
    throw
} finally {
    if (Get-MgContext) {
        Write-Output "Disconnecting from Microsoft Graph..."
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}

Write-Output "========================================="
Write-Output "Application Permission Auditor completed at: `$(Get-Date)"
Write-Output "========================================="
"@

    return $RunbookContent
}

function Deploy-Runbook {
    try {
        Write-Host "Creating/updating runbook with PowerShell 7.4 runtime..." -ForegroundColor Yellow
        
        $RunbookContent = Create-RunbookContent
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create/update runbook: $RunbookName" -ForegroundColor Yellow
            Write-Host "[WHATIF] Runbook content length: $($RunbookContent.Length) characters" -ForegroundColor Yellow
            Write-Host "[WHATIF] Runtime Environment: PowerShell 7.4" -ForegroundColor Yellow
        } else {
            Write-Host "Note: PowerShell 7.4 runtime should be configured in Azure Portal" -ForegroundColor Yellow
            Write-Host "Go to: Automation Account > Runtime Environments > Create > PowerShell 7.4" -ForegroundColor Gray
            
            # Create temporary file for runbook content
            $TempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
            $RunbookContent | Out-File -FilePath $TempFile -Encoding UTF8
            
            try {
                # Check if runbook exists
                $ExistingRunbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName -ErrorAction SilentlyContinue
                
                if ($ExistingRunbook) {
                    Write-Host "Removing existing runbook to recreate with PowerShell 7.4..." -ForegroundColor Gray
                    Remove-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                        -AutomationAccountName $AutomationAccountName `
                        -Name $RunbookName -Force
                }
                
                Write-Host "Creating new runbook..." -ForegroundColor Gray
                
                # Import runbook (Runtime environment needs to be set manually in Azure Portal)
                Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName `
                    -Type PowerShell `
                    -Path $TempFile
                
                # Publish the runbook
                Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName
                
                Write-Host "✓ Runbook '$RunbookName' deployed and published with PowerShell 7.4 support" -ForegroundColor Green
            }
            finally {
                # Clean up temporary file
                if (Test-Path $TempFile) {
                    Remove-Item $TempFile -Force
                }
            }
        }
        
    } catch {
        Write-Error "Failed to deploy runbook: $($_.Exception.Message)"
        throw
    }
}

function Create-Schedule {
    if (-not $EnableSchedule) {
        Write-Host "Schedule creation disabled - skipping" -ForegroundColor Gray
        return
    }
    
    try {
        Write-Host "Creating execution schedule..." -ForegroundColor Yellow
        
        $ScheduleStart = (Get-Date).Date.AddDays(1).Add([TimeSpan]::Parse($StartTime))
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create schedule: $ScheduleName" -ForegroundColor Yellow
            Write-Host "[WHATIF] Start time: $ScheduleStart" -ForegroundColor Yellow
            Write-Host "[WHATIF] Frequency: Weekly" -ForegroundColor Yellow
        } else {
            # Check if schedule exists
            $ExistingSchedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Name $ScheduleName -ErrorAction SilentlyContinue
            
            if ($ExistingSchedule) {
                Write-Host "Schedule already exists - updating..." -ForegroundColor Gray
                Set-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $ScheduleName `
                    -StartTime $ScheduleStart `
                    -WeekInterval 1
            } else {
                Write-Host "Creating new schedule..." -ForegroundColor Gray
                New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $ScheduleName `
                    -StartTime $ScheduleStart `
                    -WeekInterval 1 `
                    -TimeZone $TimeZone
            }
            
            # Link schedule to runbook
            Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -RunbookName $RunbookName `
                -ScheduleName $ScheduleName
            
            Write-Host "✓ Schedule '$ScheduleName' created and linked to runbook" -ForegroundColor Green
            Write-Host "  Next execution: $ScheduleStart" -ForegroundColor Gray
        }
        
    } catch {
        Write-Error "Failed to create schedule: $($_.Exception.Message)"
        throw
    }
}

function Show-PostDeploymentInstructions {
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Deployment Summary" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
        Write-Host "  Run without -WhatIf to execute deployment" -ForegroundColor Gray
    } else {
        Write-Host "✓ Application Permission Auditor deployed successfully!" -ForegroundColor Green
    }
    
    Write-Host "`n📋 Required Manual Steps:" -ForegroundColor Cyan
    Write-Host "1. Configure Managed Identity Permissions:" -ForegroundColor White
    foreach ($Permission in $RequiredPermissions) {
        Write-Host "   - $Permission" -ForegroundColor Gray
    }
    
    Write-Host "`n2. Grant Admin Consent for Microsoft Graph API:" -ForegroundColor White
    Write-Host "   - Go to Azure Portal → Automation Account → Identity" -ForegroundColor Gray
    Write-Host "   - Copy the Object ID of the system-assigned managed identity" -ForegroundColor Gray
    Write-Host "   - Use Azure CLI or PowerShell to grant permissions" -ForegroundColor Gray
    
    Write-Host "`n3. Test the Deployment:" -ForegroundColor White
    Write-Host "   - Go to Azure Portal → Automation Account → Runbooks" -ForegroundColor Gray
    Write-Host "   - Select '$RunbookName' and click 'Test pane'" -ForegroundColor Gray
    Write-Host "   - Run with WhatIf=true for initial testing" -ForegroundColor Gray
    
    Write-Host "`n4. Monitor Module Installation:" -ForegroundColor White
    Write-Host "   - Go to Azure Portal → Automation Account → Modules" -ForegroundColor Gray
    Write-Host "   - Wait for all modules to show 'Available' status (15-30 minutes)" -ForegroundColor Gray
    
    if ($EnableSchedule -and -not $WhatIf) {
        Write-Host "`n⏰ Schedule Configuration:" -ForegroundColor Cyan
        Write-Host "  Schedule Name: $ScheduleName" -ForegroundColor White
        Write-Host "  Frequency: Weekly" -ForegroundColor White
        Write-Host "  Next Run: $((Get-Date).Date.AddDays(1).Add([TimeSpan]::Parse($StartTime)))" -ForegroundColor White
    }
    
    Write-Host "`n🔗 Useful Resources:" -ForegroundColor Cyan
    Write-Host "  Documentation: ./README.md" -ForegroundColor Gray
    Write-Host "  Testing Guide: ./Tests/Test-PermissionAuditorConnection.ps1" -ForegroundColor Gray
    Write-Host "  Azure Portal: https://portal.azure.com" -ForegroundColor Gray
}

# Main execution
try {
    Connect-ToAzure
    Test-AutomationAccount
    Install-RequiredModules
    Deploy-Runbook
    Create-Schedule
    Show-PostDeploymentInstructions
    
    Write-Host "`n🎉 Deployment completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
}