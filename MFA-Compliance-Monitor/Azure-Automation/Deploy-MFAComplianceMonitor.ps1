# Deploy-MFAComplianceMonitor.ps1
# Enhanced Azure Automation deployment script for MFA Compliance Monitor
# Auto-creates infrastructure and embeds full script content

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Automation, Az.Resources

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD tenant ID")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false, HelpMessage = "Custom Application ID for Azure authentication (if using enterprise app registration)")]
    [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ApplicationId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
    [ValidateLength(1, 90)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Automation account name")]
    [ValidateLength(6, 50)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Azure region")]
    [string]$Location = "East US 2",
    
    [Parameter(Mandatory = $false)]
    [string]$RunbookName = "MFAComplianceMonitor",
    
    [Parameter(Mandatory = $false)]
    [string]$ScheduleName = "MFAComplianceMonitor-Daily",
    
    [Parameter(Mandatory = $false)]
    [string]$StartTime = "07:00:00",
    
    [Parameter(Mandatory = $false)]
    [string]$TimeZone = "UTC",
    
    [Parameter(Mandatory = $false)]
    [int]$DaysToAnalyze = 30,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ITAdminEmails = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeUsers = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableSchedule = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# PowerShell and module compatibility validation
function Test-PowerShellCompatibility {
    Write-Host "Validating PowerShell compatibility..." -ForegroundColor Yellow
    
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7.0 or later is required. Current version: $($PSVersion.ToString())"
        return $false
    }
    Write-Host "✓ PowerShell version: $($PSVersion.ToString())" -ForegroundColor Green
    
    $RequiredModules = @('Az.Accounts', 'Az.Automation', 'Az.Resources')
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
        Write-Error "Missing required Azure PowerShell modules: $($MissingModules -join ', ')"
        return $false
    }
    
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Write-Error "Windows PowerShell (Desktop edition) is not supported. Please use PowerShell 7+ (Core edition)."
        return $false
    }
    
    Write-Host "✓ PowerShell compatibility validation passed" -ForegroundColor Green
    return $true
}

# Validate compatibility before proceeding
if (-not (Test-PowerShellCompatibility)) {
    exit 1
}

Write-Host @"
=========================================
 MFA COMPLIANCE MONITOR DEPLOYMENT
 Enhanced Azure Automation Configuration
=========================================
"@ -ForegroundColor Cyan

Write-Host "Subscription: $SubscriptionId" -ForegroundColor Yellow
Write-Host "Tenant: $TenantId" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow
Write-Host "Runbook Name: $RunbookName" -ForegroundColor Yellow
Write-Host "Analysis Period: $DaysToAnalyze days" -ForegroundColor Yellow
Write-Host "WhatIf Mode: $WhatIf" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Required PowerShell modules for the runbook
$RequiredModules = @(
    @{Name = "Microsoft.Graph.Authentication"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Identity.SignIns"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Users"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Mail"; Version = "2.15.0"},
    @{Name = "Microsoft.Graph.Reports"; Version = "2.15.0"}
)

# Required Microsoft Graph permissions
$RequiredPermissions = @(
    "AuditLog.Read.All",
    "User.Read.All",
    "Mail.Send",
    "Directory.Read.All"
)

function Connect-ToAzure {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        
        $Context = Get-AzContext
        $NeedsConnection = $false
        
        if (-not $Context) {
            $NeedsConnection = $true
        } elseif ($Context.Subscription.Id -ne $SubscriptionId) {
            $NeedsConnection = $true
        } elseif ($Context.Tenant.Id -ne $TenantId) {
            $NeedsConnection = $true
        }
        
        if ($NeedsConnection) {
            if ($ApplicationId) {
                Write-Host "Using custom Application ID: $ApplicationId" -ForegroundColor Gray
                Connect-AzAccount -ApplicationId $ApplicationId -SubscriptionId $SubscriptionId -TenantId $TenantId
            } else {
                Write-Host "Using default interactive authentication" -ForegroundColor Gray
                Connect-AzAccount -SubscriptionId $SubscriptionId -TenantId $TenantId
            }
        }
        
        $Context = Get-AzContext
        Write-Host "✓ Connected to Azure subscription: $SubscriptionId" -ForegroundColor Green
        Write-Host "  Tenant: $($Context.Tenant.Id)" -ForegroundColor Gray
        
    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        throw
    }
}

function Ensure-ResourceGroup {
    try {
        Write-Host "Checking resource group: $ResourceGroupName" -ForegroundColor Yellow
        
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $ResourceGroup) {
            if ($WhatIf) {
                Write-Host "[WHATIF] Would create resource group: $ResourceGroupName" -ForegroundColor Yellow
                return
            }
            
            Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
            $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag @{
                "Purpose" = "MFAComplianceMonitor"
                "ManagedBy" = "AutomationDeployment"
                "CreatedDate" = (Get-Date -Format "yyyy-MM-dd")
                "Environment" = "Production"
            }
            Write-Host "✓ Created resource group: $ResourceGroupName" -ForegroundColor Green
        } else {
            Write-Host "✓ Resource group exists: $ResourceGroupName" -ForegroundColor Green
        }
        
        return $ResourceGroup
    }
    catch {
        Write-Error "Failed to create resource group: $($_.Exception.Message)"
        throw
    }
}

function Ensure-AutomationAccount {
    try {
        Write-Host "Checking automation account: $AutomationAccountName" -ForegroundColor Yellow
        
        $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        if (-not $AutomationAccount) {
            if ($WhatIf) {
                Write-Host "[WHATIF] Would create automation account: $AutomationAccountName" -ForegroundColor Yellow
                return
            }
            
            Write-Host "Creating automation account: $AutomationAccountName" -ForegroundColor Yellow
            $AutomationAccount = New-AzAutomationAccount `
                -ResourceGroupName $ResourceGroupName `
                -Name $AutomationAccountName `
                -Location $Location `
                -AssignSystemIdentity `
                -Tag @{
                    "Purpose" = "MFAComplianceMonitor"
                    "ManagedBy" = "AutomationDeployment"
                    "CreatedDate" = (Get-Date -Format "yyyy-MM-dd")
                    "Environment" = "Production"
                }
            
            Write-Host "✓ Created automation account: $AutomationAccountName" -ForegroundColor Green
            Write-Host "  System-assigned managed identity enabled" -ForegroundColor Gray
            
            # Wait for managed identity to be ready
            Write-Host "  Waiting for managed identity propagation..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
        } else {
            Write-Host "✓ Automation account exists: $AutomationAccountName" -ForegroundColor Green
            
            # Ensure system identity is enabled
            if (-not $AutomationAccount.Identity) {
                Write-Host "Enabling system-assigned managed identity..." -ForegroundColor Yellow
                if (-not $WhatIf) {
                    Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -AssignSystemIdentity
                    Write-Host "✓ System-assigned managed identity enabled" -ForegroundColor Green
                }
            }
        }
        
        return $AutomationAccount
    }
    catch {
        Write-Error "Failed to create automation account: $($_.Exception.Message)"
        throw
    }
}

function Install-RequiredModules {
    try {
        Write-Host "Installing required PowerShell modules..." -ForegroundColor Yellow
        
        foreach ($Module in $RequiredModules) {
            Write-Host "  Installing module: $($Module.Name) v$($Module.Version)" -ForegroundColor Gray
            
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would install: $($Module.Name)" -ForegroundColor Yellow
                continue
            }
            
            # Check if module already exists
            $ExistingModule = Get-AzAutomationModule `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Name $Module.Name `
                -ErrorAction SilentlyContinue
            
            if ($ExistingModule -and $ExistingModule.Version -eq $Module.Version) {
                Write-Host "  ✓ Module already installed: $($Module.Name) v$($Module.Version)" -ForegroundColor Green
                continue
            }
            
            # Import module from PowerShell Gallery
            $ModuleUri = "https://www.powershellgallery.com/api/v2/package/$($Module.Name)/$($Module.Version)"
            
            try {
                Import-AzAutomationModule `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $Module.Name `
                    -ContentLinkUri $ModuleUri
                
                Write-Host "  ✓ Initiated installation: $($Module.Name)" -ForegroundColor Green
            }
            catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Host "  ✓ Module already exists: $($Module.Name)" -ForegroundColor Green
                } else {
                    Write-Warning "  Failed to install $($Module.Name): $($_.Exception.Message)"
                }
            }
        }
        
        if (-not $WhatIf) {
            Write-Host "⚠️  Module installation initiated. This process takes 15-30 minutes." -ForegroundColor Yellow
            Write-Host "   Monitor progress in Azure Portal → Automation Account → Modules" -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Failed to install modules: $($_.Exception.Message)"
        throw
    }
}

function Create-EnhancedRunbookContent {
    Write-Host "Creating enhanced runbook with full MFA Compliance Monitor script..." -ForegroundColor Yellow
    
    # Read the actual MFA Compliance Monitor script
    $ScriptPath = Join-Path $PSScriptRoot ".." "Scripts" "MFAComplianceMonitor.ps1"
    
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "MFA Compliance Monitor script not found at: $ScriptPath"
        throw "Cannot find source script for runbook deployment"
    }
    
    Write-Host "Reading source script ($(([System.IO.FileInfo]$ScriptPath).Length) bytes)..." -ForegroundColor Gray
    $OriginalScript = Get-Content -Path $ScriptPath -Raw
    
    # Create the Azure Automation wrapper that includes the ENTIRE original script
    $RunbookContent = @"
<#
.SYNOPSIS
    MFA Compliance Monitor - Azure Automation Runbook
    
.DESCRIPTION
    This runbook monitors MFA compliance by analyzing Azure AD sign-in logs to identify users
    who have used non-Microsoft Authenticator MFA methods. It sends notifications to non-compliant
    users and provides detailed reporting for IT administrators.
    
.NOTES
    Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Source Script: MFAComplianceMonitor.ps1
    Deployment Type: Azure Automation with Managed Identity
    Required Permissions: AuditLog.Read.All, User.Read.All, Directory.Read.All, Mail.Send
#>

param(
    [Parameter(Mandatory = `$false, HelpMessage = "Number of days to analyze")]
    [int]`$DaysToAnalyze = $DaysToAnalyze,
    
    [Parameter(Mandatory = `$false, HelpMessage = "IT admin emails (comma-separated)")]
    [string]`$ITAdminEmails = "$($ITAdminEmails -join ',')",
    
    [Parameter(Mandatory = `$false, HelpMessage = "Users to exclude (comma-separated)")]
    [string]`$ExcludeUsers = "$($ExcludeUsers -join ',')",
    
    [Parameter(Mandatory = `$false, HelpMessage = "Run in simulation mode")]
    [bool]`$WhatIf = `$true,
    
    [Parameter(Mandatory = `$false, HelpMessage = "Send notifications to users")]
    [bool]`$SendUserNotifications = `$true,
    
    [Parameter(Mandatory = `$false, HelpMessage = "Send admin summary report")]
    [bool]`$SendAdminSummary = `$true,
    
    [Parameter(Mandatory = `$false, HelpMessage = "Include compliant users in reports")]
    [bool]`$IncludeCompliantUsers = `$false,
    
    [Parameter(Mandatory = `$false, HelpMessage = "Export path for reports")]
    [string]`$ExportPath = "`$env:TEMP\MFAComplianceReports"
)

# Set error action preference
`$ErrorActionPreference = "Stop"

# Azure Automation specific variables
`$AzureAutomationEnvironment = `$true
`$RunbookStartTime = Get-Date

Write-Output "========================================="
Write-Output "MFA Compliance Monitor - Azure Automation"
Write-Output "Started: `$RunbookStartTime"
Write-Output "========================================="
Write-Output "Parameters:"
Write-Output "  Analysis Days: `$DaysToAnalyze"
Write-Output "  WhatIf Mode: `$WhatIf"
Write-Output "  Send User Notifications: `$SendUserNotifications"
Write-Output "  Send Admin Summary: `$SendAdminSummary"
Write-Output "  Include Compliant Users: `$IncludeCompliantUsers"
Write-Output "  Export Path: `$ExportPath"
Write-Output "========================================="

# Convert comma-separated parameters back to arrays for embedded script
`$ITAdminEmailArray = if (`$ITAdminEmails) { `$ITAdminEmails -split ',' | ForEach-Object { `$_.Trim() } } else { @() }
`$ExcludeUserArray = if (`$ExcludeUsers) { `$ExcludeUsers -split ',' | ForEach-Object { `$_.Trim() } } else { @() }

# ============================================
# EMBEDDED MFA COMPLIANCE MONITOR SCRIPT STARTS HERE
# ============================================

# Note: The original script is embedded below with modifications for Azure Automation:
# - Authentication uses Managed Identity (Connect-MgGraph -Identity)
# - File paths adjusted for Azure Automation temp directories
# - Parameters converted from Azure Automation format

# Override parameters for embedded script execution
`$DaysToAnalyzeParam = `$DaysToAnalyze
`$WhatIfParam = [bool]`$WhatIf
`$ITAdminEmailsParam = `$ITAdminEmailArray
`$ExcludedUsersParam = `$ExcludeUserArray
`$ExportPathParam = `$ExportPath
`$IncludeCompliantUsersParam = [bool]`$IncludeCompliantUsers
`$SendUserNotificationsParam = [bool]`$SendUserNotifications
`$SendAdminSummaryParam = [bool]`$SendAdminSummary

# --- Start of MFAComplianceMonitor.ps1 (modified for Azure Automation) ---

$OriginalScript

# --- End of MFAComplianceMonitor.ps1 ---

# ============================================
# EMBEDDED MFA COMPLIANCE MONITOR SCRIPT ENDS HERE
# ============================================

# Azure Automation completion logging
`$RunbookEndTime = Get-Date
`$Duration = `$RunbookEndTime - `$RunbookStartTime

Write-Output "========================================="
Write-Output "MFA Compliance Monitor Completed"
Write-Output "Duration: `$(`$Duration.TotalMinutes) minutes"
Write-Output "Completed: `$RunbookEndTime"
Write-Output "========================================="
"@
    
    # Apply necessary modifications for Azure Automation environment
    Write-Host "Applying Azure Automation modifications..." -ForegroundColor Gray
    
    # Replace parameter references with Azure Automation versions
    $RunbookContent = $RunbookContent -replace '\$DaysToAnalyze', '`$DaysToAnalyzeParam'
    $RunbookContent = $RunbookContent -replace '\$WhatIf', '`$WhatIfParam'
    $RunbookContent = $RunbookContent -replace '\$ITAdminEmails', '`$ITAdminEmailsParam'
    $RunbookContent = $RunbookContent -replace '\$ExcludedUsers', '`$ExcludedUsersParam'
    $RunbookContent = $RunbookContent -replace '\$ExportPath', '`$ExportPathParam'
    $RunbookContent = $RunbookContent -replace '\$IncludeCompliantUsers', '`$IncludeCompliantUsersParam'
    $RunbookContent = $RunbookContent -replace '\$SendUserNotifications', '`$SendUserNotificationsParam'
    $RunbookContent = $RunbookContent -replace '\$SendAdminSummary', '`$SendAdminSummaryParam'
    
    # Replace authentication methods with Managed Identity (but preserve existing Connect-MgGraph -Identity calls)
    $RunbookContent = $RunbookContent -replace 'Connect-MgGraph -Scopes[^\r\n]+', 'Connect-MgGraph -Identity -NoWelcome'
    
    # Adjust paths for Azure Automation
    $RunbookContent = $RunbookContent -replace 'C:\\MFAComplianceReports', '`$env:TEMP\MFAComplianceReports'
    $RunbookContent = $RunbookContent -replace 'C:\\Reports', '`$env:TEMP'
    $RunbookContent = $RunbookContent -replace 'C:\\Temp', '`$env:TEMP'
    
    Write-Host "✓ Enhanced runbook content created ($(($RunbookContent.Length / 1024)) KB)" -ForegroundColor Green
    
    return $RunbookContent
}

function Deploy-EnhancedRunbook {
    try {
        Write-Host "Deploying enhanced MFA Compliance Monitor runbook..." -ForegroundColor Yellow
        
        # Create the runbook content with embedded script
        $RunbookContent = Create-EnhancedRunbookContent
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would deploy runbook with full script content" -ForegroundColor Yellow
            Write-Host "[WHATIF] Runbook size: $(($RunbookContent.Length / 1024)) KB" -ForegroundColor Yellow
            return
        }
        
        # Create temp file for runbook content
        $TempFile = New-TemporaryFile
        $RunbookContent | Set-Content -Path $TempFile.FullName -Encoding UTF8
        
        try {
            # Check if runbook exists
            $ExistingRunbook = Get-AzAutomationRunbook `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Name $RunbookName `
                -ErrorAction SilentlyContinue
            
            if ($ExistingRunbook) {
                Write-Host "Updating existing runbook: $RunbookName" -ForegroundColor Yellow
                
                # Import the updated content
                Import-AzAutomationRunbook `
                    -Path $TempFile.FullName `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName `
                    -Type PowerShell `
                    -Force `
                    -Published
            } else {
                Write-Host "Creating new runbook: $RunbookName" -ForegroundColor Yellow
                
                # Create new runbook
                New-AzAutomationRunbook `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName `
                    -Type PowerShell `
                    -Description "MFA Compliance Monitor - Identifies users using non-Microsoft Authenticator MFA methods"
                
                # Import the content
                Import-AzAutomationRunbook `
                    -Path $TempFile.FullName `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName `
                    -Type PowerShell `
                    -Force
                
                # Publish the runbook
                Publish-AzAutomationRunbook `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -Name $RunbookName
            }
            
            Write-Host "✓ Runbook deployed successfully with full MFA monitoring script" -ForegroundColor Green
        }
        finally {
            # Clean up temp file
            if (Test-Path $TempFile.FullName) {
                Remove-Item $TempFile.FullName -Force
            }
        }
    }
    catch {
        Write-Error "Failed to deploy runbook: $($_.Exception.Message)"
        throw
    }
}

function Create-Schedule {
    try {
        Write-Host "Configuring automation schedule..." -ForegroundColor Yellow
        
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create schedule: $ScheduleName" -ForegroundColor Yellow
            return
        }
        
        # Check if schedule exists
        $ExistingSchedule = Get-AzAutomationSchedule `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -Name $ScheduleName `
            -ErrorAction SilentlyContinue
        
        if (-not $ExistingSchedule) {
            # Calculate next start time (tomorrow at specified time)
            $StartDateTime = (Get-Date).Date.AddDays(1).Add([TimeSpan]::Parse($StartTime))
            
            # Create daily schedule
            $Schedule = New-AzAutomationSchedule `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Name $ScheduleName `
                -StartTime $StartDateTime `
                -DayInterval 1 `
                -TimeZone $TimeZone `
                -Description "Daily MFA compliance monitoring at $StartTime $TimeZone"
            
            Write-Host "✓ Created schedule: $ScheduleName" -ForegroundColor Green
            Write-Host "  Next run: $($StartDateTime.ToString('yyyy-MM-dd HH:mm:ss')) $TimeZone" -ForegroundColor Gray
        } else {
            Write-Host "✓ Schedule already exists: $ScheduleName" -ForegroundColor Green
        }
        
        # Link runbook to schedule if enabled
        if ($EnableSchedule) {
            $ExistingLink = Get-AzAutomationScheduledRunbook `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -RunbookName $RunbookName `
                -ScheduleName $ScheduleName `
                -ErrorAction SilentlyContinue
            
            if (-not $ExistingLink) {
                # Create runbook parameters for scheduled execution
                $RunbookParameters = @{
                    "DaysToAnalyze" = $DaysToAnalyze
                    "WhatIf" = $false
                    "SendUserNotifications" = $true
                    "SendAdminSummary" = $true
                    "IncludeCompliantUsers" = $false
                }
                
                if ($ITAdminEmails.Count -gt 0) {
                    $RunbookParameters["ITAdminEmails"] = ($ITAdminEmails -join ',')
                }
                
                if ($ExcludeUsers.Count -gt 0) {
                    $RunbookParameters["ExcludeUsers"] = ($ExcludeUsers -join ',')
                }
                
                Register-AzAutomationScheduledRunbook `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -RunbookName $RunbookName `
                    -ScheduleName $ScheduleName `
                    -Parameters $RunbookParameters
                
                Write-Host "✓ Linked runbook to schedule with parameters" -ForegroundColor Green
            } else {
                Write-Host "✓ Runbook already linked to schedule" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Error "Failed to create schedule: $($_.Exception.Message)"
        throw
    }
}

function Show-PostDeploymentInstructions {
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " MFA COMPLIANCE MONITOR DEPLOYMENT COMPLETE" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "✓ WhatIf mode - No changes were made" -ForegroundColor Green
        Write-Host "✓ Deployment validation completed successfully" -ForegroundColor Green
        return
    }
    
    Write-Host "`n📋 Infrastructure Created:" -ForegroundColor Cyan
    Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
    Write-Host "  Automation Account: $AutomationAccountName" -ForegroundColor White
    Write-Host "  Location: $Location" -ForegroundColor White
    Write-Host "  Managed Identity: System-assigned (enabled)" -ForegroundColor White
    
    Write-Host "`n🔐 Required Microsoft Graph Permissions:" -ForegroundColor Cyan
    Write-Host "  Next step: Grant these permissions to the managed identity" -ForegroundColor Yellow
    foreach ($Permission in $RequiredPermissions) {
        Write-Host "    • $Permission" -ForegroundColor Gray
    }
    
    Write-Host "`n📊 Monitoring Configuration:" -ForegroundColor Cyan
    Write-Host "  Runbook: $RunbookName (with full embedded script)" -ForegroundColor White
    Write-Host "  Analysis Period: $DaysToAnalyze days" -ForegroundColor White
    Write-Host "  Schedule: Daily at $StartTime $TimeZone" -ForegroundColor White
    Write-Host "  Target: Non-Microsoft Authenticator MFA usage" -ForegroundColor White
    
    # Get managed identity details
    try {
        $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        if ($AutomationAccount -and $AutomationAccount.Identity) {
            Write-Host "`n🆔 Managed Identity Details:" -ForegroundColor Cyan
            Write-Host "  Object ID: $($AutomationAccount.Identity.PrincipalId)" -ForegroundColor White
            Write-Host "  Type: SystemAssigned" -ForegroundColor White
            
            Write-Host "`n📝 Next Steps:" -ForegroundColor Cyan
            Write-Host "  1. Grant Microsoft Graph permissions using:" -ForegroundColor White
            Write-Host "     .\Grant-MFAMonitorPermissions.ps1 -ManagedIdentityObjectId '$($AutomationAccount.Identity.PrincipalId)'" -ForegroundColor Gray
            Write-Host "  2. Wait 15-30 minutes for module installation to complete" -ForegroundColor White
            Write-Host "  3. Test the runbook in Azure Portal with WhatIf=true" -ForegroundColor White
            Write-Host "  4. Monitor the first scheduled execution" -ForegroundColor White
        }
    }
    catch {
        Write-Warning "Could not retrieve managed identity details. Check in Azure Portal."
    }
    
    Write-Host "`n🎯 MFA Compliance Capabilities:" -ForegroundColor Cyan
    Write-Host "  This automation will:" -ForegroundColor White
    Write-Host "  ✓ Analyze Azure AD sign-in logs for MFA method usage" -ForegroundColor Green
    Write-Host "  ✓ Identify users using non-Microsoft Authenticator methods" -ForegroundColor Green
    Write-Host "  ✓ Send professional notifications to non-compliant users" -ForegroundColor Green
    Write-Host "  ✓ Generate executive compliance reports for IT leadership" -ForegroundColor Green
    Write-Host "  ✓ Export detailed CSV reports for analysis" -ForegroundColor Green
    
    Write-Host "`n⚠️ Security Considerations:" -ForegroundColor Yellow
    Write-Host "  • Can read all Azure AD audit logs (sensitive data)" -ForegroundColor Red
    Write-Host "  • Can access user authentication method details" -ForegroundColor White
    Write-Host "  • Can send emails on behalf of the organization" -ForegroundColor White
    Write-Host "  • Regular access reviews are recommended" -ForegroundColor White
    
    Write-Host "`n📍 Azure Portal Links:" -ForegroundColor Cyan
    Write-Host "  Automation Account: https://portal.azure.com/#@/resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName" -ForegroundColor Gray
    Write-Host "  Runbooks: Navigate to Automation Account → Runbooks → $RunbookName" -ForegroundColor Gray
    Write-Host "  Schedules: Navigate to Automation Account → Schedules → $ScheduleName" -ForegroundColor Gray
}

# Main execution
try {
    # Step 1: Connect to Azure
    Connect-ToAzure
    
    # Step 2: Ensure infrastructure exists
    Ensure-ResourceGroup
    $AutomationAccount = Ensure-AutomationAccount
    
    # Step 3: Install required modules
    Install-RequiredModules
    
    # Step 4: Deploy enhanced runbook with embedded script
    Deploy-EnhancedRunbook
    
    # Step 5: Create and configure schedule
    Create-Schedule
    
    # Step 6: Show completion instructions
    Show-PostDeploymentInstructions
    
    Write-Host "`n🎉 MFA Compliance Monitor deployment ecosystem completed!" -ForegroundColor Green
    Write-Host "Ready for Microsoft Graph permission grant and testing" -ForegroundColor Green
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Verify Azure PowerShell modules are installed and up to date" -ForegroundColor Gray
    Write-Host "2. Ensure you have Contributor access to the subscription" -ForegroundColor Gray
    Write-Host "3. Check that the automation account name is globally unique" -ForegroundColor Gray
    Write-Host "4. Verify the specified Azure region supports Automation Accounts" -ForegroundColor Gray
    exit 1
}