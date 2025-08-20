# Azure Automation Deployment Scripts - Embedded Script Content Fixes Needed

## Issue Summary
Multiple Azure Automation deployment scripts reference external script files using `$PSScriptRoot` which don't exist in the Azure Automation environment. According to Microsoft best practices, runbook content should be fully embedded.

## Scripts That Need Updates

### 1. Device Cleanup Automation
**File**: `/home/claude/Azure/Device-Cleanup-Automation/Azure-Automation/Deploy-DeviceCleanupAutomation.ps1`
**Issue**: References `$ScriptPath = Join-Path $PSScriptRoot ".." "Scripts" "DeviceCleanupAutomation.ps1"`
**Status**: ✅ ALREADY FIXED - This script already embeds the full DeviceCleanupAutomation.ps1 content

### 2. MFA Compliance Monitor  
**File**: `/home/claude/Azure/MFA-Compliance-Monitor/Azure-Automation/Deploy-MFAComplianceMonitor.ps1`
**Issue**: References `$ScriptPath = Join-Path $PSScriptRoot ".." "Scripts" "MFAComplianceMonitor.ps1"`
**Status**: ✅ ALREADY FIXED - This script already embeds the full MFAComplianceMonitor.ps1 content

### 3. Application Permission Auditor
**File**: `/home/claude/Azure/Application-Permission-Auditor/Azure-Automation/Deploy-ApplicationPermissionAuditor.ps1`
**Issue**: References `$ScriptPath = "$PSScriptRoot\ApplicationPermissionAuditor.ps1"`
**Status**: ✅ FIXED (Aug 19, 2025) - Updated to embed full ApplicationPermissionAuditor.ps1 content with PowerShell 7.4 support

### 4. Enterprise App Certificate Monitor
**File**: `/home/claude/Azure/Enterprise-App-Certificate-Monitor/Azure-Automation/Deploy-EnterpriseAppCertificateMonitor.ps1`
**Issue**: References `$ScriptPath = "$PSScriptRoot\EnterpriseAppCertificateMonitor.ps1"`
**Status**: ❌ NEEDS FIX

### 5. Enterprise App Usage Monitor
**File**: `/home/claude/Azure/Enterprise-App-Usage-Monitor/Azure-Automation/Deploy-EnterpriseAppUsageMonitor.ps1`
**Issue**: References `$ScriptPath = "$PSScriptRoot\EnterpriseAppUsageMonitor.ps1"`
**Status**: ❌ NEEDS FIX

### 6. Service Principal Credential Manager
**File**: `/home/claude/Azure/Service-Principal-Credential-Manager/Azure-Automation/Deploy-ServicePrincipalCredentialManager.ps1`
**Issue**: References `$ScriptPath = "$PSScriptRoot\ServicePrincipalCredentialManager.ps1"`
**Status**: ❌ NEEDS FIX

## Fix Pattern Applied

The fix pattern used for Application Permission Auditor should be applied to the other scripts:

1. **Read the main script file**: Use `Get-Content $MainScriptPath -Raw` to read the full script content
2. **Remove duplicate param blocks**: Strip the CmdletBinding and param blocks from the main script
3. **Embed content**: Insert the main script content directly into the runbook
4. **PowerShell 7.4 compatibility**: Update `#Requires -Version 7.4` and ensure proper module imports
5. **Runtime environment**: Document that PowerShell 7.4 runtime should be configured in Azure Portal

## Example Fix Implementation

```powershell
function Create-RunbookContent {
    # Read the full main script content
    $MainScriptPath = "$PSScriptRoot\[MainScriptName].ps1"
    if (-not (Test-Path $MainScriptPath)) {
        throw "Main script not found at: $MainScriptPath"
    }
    
    # Get the main script content and remove param blocks
    $MainScriptContent = Get-Content $MainScriptPath -Raw
    $MainScriptContent = $MainScriptContent -replace '(?s)^[^#]*\[CmdletBinding\(\)\].*?^\)', ''
    $MainScriptContent = $MainScriptContent -replace '(?s)^param\(.*?^\)', ''
    
    # Create runbook with embedded content
    $RunbookContent = @"
#Requires -Version 7.4

# [Service Name] - Azure Automation Runbook
# PowerShell 7.4 Compatible

param(
    # Runbook parameters here
)

# Runbook initialization code here

#############################################################################
# EMBEDDED [SERVICE NAME] SCRIPT
#############################################################################

$MainScriptContent

#############################################################################
# END EMBEDDED SCRIPT
#############################################################################

"@

    return $RunbookContent
}
```

## Priority Order for Fixes

1. **Enterprise App Certificate Monitor** - Certificate monitoring is critical for security
2. **Service Principal Credential Manager** - Credential management is high security priority  
3. **Enterprise App Usage Monitor** - Lower priority, monitoring/reporting function

## Additional Requirements

All fixes should also include:
- PowerShell 7.4 compatibility (`#Requires -Version 7.4`)
- Proper Microsoft Graph module imports
- Documentation that PowerShell 7.4 runtime environment should be configured in Azure Portal
- Testing with managed identity authentication
- Cleanup of any remaining external file references

## Testing Notes

After fixing each deployment script:
1. Test runbook deployment to Azure Automation
2. Verify runbook executes without "script not found" errors
3. Confirm PowerShell 7.4 compatibility
4. Validate all embedded functions work correctly
5. Test with managed identity authentication

---

*Last Updated: August 19, 2025*
*Fixed by: AI Agent (Claude)*