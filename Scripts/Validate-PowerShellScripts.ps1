# Validate-PowerShellScripts.ps1
# Comprehensive PowerShell script validation for Azure automation projects
# This script performs syntax checking, best practice analysis, and security validation

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = $PSScriptRoot,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePaths = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTests,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Validation-Report.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$FailOnWarnings,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "PowerShell Script Validation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Validation Path: $Path" -ForegroundColor Yellow
Write-Host "Report Output: $ReportPath" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Initialize validation results
$ValidationResults = @()
$OverallSuccess = $true
$TotalScripts = 0
$PassedScripts = 0
$FailedScripts = 0
$WarningScripts = 0

# Function to validate PowerShell syntax
function Test-PowerShellSyntax {
    param(
        [string]$FilePath
    )
    
    try {
        $Errors = $null
        $Tokens = $null
        $AST = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$Tokens, [ref]$Errors)
        
        $Result = [PSCustomObject]@{
            Type = "Syntax"
            Status = if ($Errors.Count -eq 0) { "Pass" } else { "Fail" }
            Message = if ($Errors.Count -eq 0) { "No syntax errors" } else { "Syntax errors: $($Errors.Count)" }
            Details = $Errors | ForEach-Object { "$($_.Message) (Line: $($_.Extent.StartLineNumber))" }
            ErrorCount = $Errors.Count
        }
        
        return $Result
    }
    catch {
        return [PSCustomObject]@{
            Type = "Syntax"
            Status = "Error"
            Message = "Failed to parse: $($_.Exception.Message)"
            Details = @($_.Exception.Message)
            ErrorCount = 1
        }
    }
}

# Function to run PSScriptAnalyzer
function Test-ScriptAnalyzer {
    param(
        [string]$FilePath
    )
    
    try {
        # Check if PSScriptAnalyzer is available
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            Write-Host "Installing PSScriptAnalyzer module..." -ForegroundColor Yellow
            Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
        }
        
        Import-Module PSScriptAnalyzer -Force
        
        $Issues = Invoke-ScriptAnalyzer -Path $FilePath -Severity @('Error', 'Warning', 'Information')
        
        $Errors = @($Issues | Where-Object { $_.Severity -eq 'Error' })
        $Warnings = @($Issues | Where-Object { $_.Severity -eq 'Warning' })
        $Information = @($Issues | Where-Object { $_.Severity -eq 'Information' })
        
        $Status = if ($Errors.Count -eq 0) { 
            if ($Warnings.Count -eq 0) { "Pass" } else { "Warning" }
        } else { 
            "Fail" 
        }
        
        $Result = [PSCustomObject]@{
            Type = "PSScriptAnalyzer"
            Status = $Status
            Message = "Errors: $($Errors.Count), Warnings: $($Warnings.Count), Info: $($Information.Count)"
            Details = $Issues | ForEach-Object { 
                "[$($_.Severity)] $($_.RuleName): $($_.Message) (Line: $($_.Line))" 
            }
            ErrorCount = $Errors.Count
            WarningCount = $Warnings.Count
        }
        
        return $Result
    }
    catch {
        return [PSCustomObject]@{
            Type = "PSScriptAnalyzer"
            Status = "Error"
            Message = "Failed to run PSScriptAnalyzer: $($_.Exception.Message)"
            Details = @($_.Exception.Message)
            ErrorCount = 1
            WarningCount = 0
        }
    }
}

# Function to validate error handling
function Test-ErrorHandling {
    param(
        [string]$FilePath
    )
    
    try {
        $Content = Get-Content -Path $FilePath -Raw
        $Issues = @()
        
        # Check for try-catch blocks
        $TryCatchPattern = 'try\s*\{.*?\}\s*catch\s*\{'
        $TryCatchMatches = [regex]::Matches($Content, $TryCatchPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        
        # Check for ErrorAction parameters
        $ErrorActionPattern = '-ErrorAction\s+(Stop|SilentlyContinue|Continue|Inquire)'
        $ErrorActionMatches = [regex]::Matches($Content, $ErrorActionPattern)
        
        # Check for Write-Error usage
        $WriteErrorPattern = 'Write-Error'
        $WriteErrorMatches = [regex]::Matches($Content, $WriteErrorPattern)
        
        # Check for dangerous commands without error handling
        $DangerousCommands = @('Remove-', 'Delete-', 'Clear-', 'Stop-', 'Restart-', 'Disable-')
        $UnprotectedDangerous = @()
        
        foreach ($Command in $DangerousCommands) {
            $CommandPattern = "$Command\w+"
            $CommandMatches = [regex]::Matches($Content, $CommandPattern)
            foreach ($Match in $CommandMatches) {
                $LineNumber = ($Content.Substring(0, $Match.Index) -split "`n").Count
                $Line = ($Content -split "`n")[$LineNumber - 1]
                if ($Line -notmatch '-ErrorAction' -and $Line -notmatch '-WhatIf') {
                    $UnprotectedDangerous += "Line $LineNumber`: $($Match.Value) without error handling"
                }
            }
        }
        
        # Evaluate error handling quality
        $HasTryCatch = $TryCatchMatches.Count -gt 0
        $HasErrorAction = $ErrorActionMatches.Count -gt 0
        $HasWriteError = $WriteErrorMatches.Count -gt 0
        $HasUnprotectedCommands = $UnprotectedDangerous.Count -gt 0
        
        $Score = 0
        if ($HasTryCatch) { $Score += 3 }
        if ($HasErrorAction) { $Score += 2 }
        if ($HasWriteError) { $Score += 1 }
        if (-not $HasUnprotectedCommands) { $Score += 2 }
        
        $Status = switch ($Score) {
            { $_ -ge 6 } { "Pass" }
            { $_ -ge 4 } { "Warning" }
            default { "Fail" }
        }
        
        $Message = "Error handling score: $Score/8"
        if ($HasUnprotectedCommands) {
            $Message += " - Unprotected dangerous commands detected"
        }
        
        $Details = @()
        $Details += "Try-Catch blocks: $($TryCatchMatches.Count)"
        $Details += "ErrorAction parameters: $($ErrorActionMatches.Count)"
        $Details += "Write-Error usage: $($WriteErrorMatches.Count)"
        if ($UnprotectedDangerous.Count -gt 0) {
            $Details += $UnprotectedDangerous
        }
        
        $Result = [PSCustomObject]@{
            Type = "ErrorHandling"
            Status = $Status
            Message = $Message
            Details = $Details
            ErrorCount = if ($Status -eq "Fail") { 1 } else { 0 }
            WarningCount = if ($Status -eq "Warning") { 1 } else { 0 }
        }
        
        return $Result
    }
    catch {
        return [PSCustomObject]@{
            Type = "ErrorHandling"
            Status = "Error"
            Message = "Failed to analyze error handling: $($_.Exception.Message)"
            Details = @($_.Exception.Message)
            ErrorCount = 1
            WarningCount = 0
        }
    }
}

# Function to validate security best practices
function Test-SecurityPractices {
    param(
        [string]$FilePath
    )
    
    try {
        $Content = Get-Content -Path $FilePath -Raw
        $Issues = @()
        
        # Check for hardcoded credentials - ENHANCED PATTERNS
        $CredentialPatterns = @(
            '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})',  # GUID/UUID patterns
            '([a-zA-Z0-9+/]{20,}={0,2})',  # Base64-like patterns (common for secrets)
            '(password\s*=\s*["\`''][^"\`'']{8,}["\`''])',  # password assignments
            '(secret\s*=\s*["\`''][^"\`'']{8,}["\`''])',    # secret assignments  
            '(key\s*=\s*["\`''][^"\`'']{8,}["\`''])',       # key assignments
            '(token\s*=\s*["\`''][^"\`'']{8,}["\`''])',     # token assignments
            '(\$ClientSecret\s*=\s*["\`''][^"\`'']{8,}["\`''])',  # PowerShell client secret vars
            '(\$TenantId\s*=\s*["\`''][a-fA-F0-9-]{36}["\`''])',   # PowerShell tenant ID vars
            '(\$ClientId\s*=\s*["\`''][a-fA-F0-9-]{36}["\`''])'    # PowerShell client ID vars
        )
        
        foreach ($Pattern in $CredentialPatterns) {
            $Matches = [regex]::Matches($Content, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($Match in $Matches) {
                $LineNumber = ($Content.Substring(0, $Match.Index) -split "`n").Count
                $Value = $Match.Value
                
                # Skip obvious placeholder/safe values
                if ($Value -notmatch 'YOUR_.*_HERE|PLACEHOLDER|EXAMPLE|env:|EnvVar' -and 
                    $Value -notmatch '00000000-0000-0000-0000-000000000000' -and
                    $Value -notmatch '\$env:' -and
                    $Value.Length -gt 10) {
                    $SafeValue = $Value.Substring(0, [Math]::Min(15, $Value.Length)) + "..."
                    $Issues += "Line $LineNumber`: Potential hardcoded credential: $SafeValue"
                }
            }
        }
        
        # Check for secure string usage
        $SecureStringUsage = [regex]::Matches($Content, 'ConvertTo-SecureString|SecureString').Count
        
        # Check for parameter validation
        $ParameterValidation = [regex]::Matches($Content, '\[Parameter\(.*Mandatory.*\)\]|\[ValidateSet\(|\[ValidateNotNull').Count
        
        # Check for dangerous operations without confirmation
        $DangerousWithoutConfirm = @()
        $DangerousPatterns = @('Remove-ADUser', 'Remove-AzResource', 'Delete-', 'Clear-Host')
        foreach ($Pattern in $DangerousPatterns) {
            $Matches = [regex]::Matches($Content, $Pattern)
            foreach ($Match in $Matches) {
                $LineNumber = ($Content.Substring(0, $Match.Index) -split "`n").Count
                $Line = ($Content -split "`n")[$LineNumber - 1]
                if ($Line -notmatch '-Confirm' -and $Line -notmatch '-WhatIf') {
                    $DangerousWithoutConfirm += "Line $LineNumber`: $($Match.Value) without confirmation"
                }
            }
        }
        
        # Calculate security score
        $Score = 0
        if ($Issues.Count -eq 0) { $Score += 4 }  # No hardcoded credentials
        if ($SecureStringUsage -gt 0) { $Score += 2 }  # Uses secure strings
        if ($ParameterValidation -gt 0) { $Score += 2 }  # Has parameter validation
        if ($DangerousWithoutConfirm.Count -eq 0) { $Score += 2 }  # Safe dangerous operations
        
        $Status = switch ($Score) {
            { $_ -ge 8 } { "Pass" }
            { $_ -ge 6 } { "Warning" }
            default { "Fail" }
        }
        
        $Details = @()
        if ($Issues.Count -gt 0) { $Details += $Issues }
        if ($DangerousWithoutConfirm.Count -gt 0) { $Details += $DangerousWithoutConfirm }
        $Details += "SecureString usage: $SecureStringUsage instances"
        $Details += "Parameter validation: $ParameterValidation instances"
        
        $Result = [PSCustomObject]@{
            Type = "Security"
            Status = $Status
            Message = "Security score: $Score/10"
            Details = $Details
            ErrorCount = if ($Status -eq "Fail") { 1 } else { 0 }
            WarningCount = if ($Status -eq "Warning") { 1 } else { 0 }
        }
        
        return $Result
    }
    catch {
        return [PSCustomObject]@{
            Type = "Security"
            Status = "Error"
            Message = "Failed to analyze security practices: $($_.Exception.Message)"
            Details = @($_.Exception.Message)
            ErrorCount = 1
            WarningCount = 0
        }
    }
}

# Get all PowerShell files
Write-Host "`nDiscovering PowerShell scripts..." -ForegroundColor Yellow

$ScriptFiles = Get-ChildItem -Path $Path -Recurse -Include "*.ps1" | Where-Object {
    $Include = $true
    foreach ($ExcludePath in $ExcludePaths) {
        if ($_.FullName -like "*$ExcludePath*") {
            $Include = $false
            break
        }
    }
    if (-not $IncludeTests -and $_.Name -like "*Test*") {
        $Include = $false
    }
    $Include
}

Write-Host "Found $($ScriptFiles.Count) PowerShell scripts to validate" -ForegroundColor Green

# Validate each script
foreach ($ScriptFile in $ScriptFiles) {
    $TotalScripts++
    $RelativePath = $ScriptFile.FullName.Replace($Path, "").TrimStart("\", "/")
    
    Write-Host "`nValidating: $RelativePath" -ForegroundColor Cyan
    
    # Run all validation tests
    $SyntaxResult = Test-PowerShellSyntax -FilePath $ScriptFile.FullName
    $AnalyzerResult = Test-ScriptAnalyzer -FilePath $ScriptFile.FullName
    $ErrorHandlingResult = Test-ErrorHandling -FilePath $ScriptFile.FullName
    $SecurityResult = Test-SecurityPractices -FilePath $ScriptFile.FullName
    
    $AllResults = @($SyntaxResult, $AnalyzerResult, $ErrorHandlingResult, $SecurityResult)
    
    # Determine overall status for this script
    $HasErrors = $AllResults | Where-Object { $_.Status -eq "Fail" -or $_.Status -eq "Error" }
    $HasWarnings = $AllResults | Where-Object { $_.Status -eq "Warning" }
    
    $ScriptStatus = if ($HasErrors) { 
        "Fail" 
    } elseif ($HasWarnings -and $FailOnWarnings) { 
        "Fail" 
    } elseif ($HasWarnings) { 
        "Warning" 
    } else { 
        "Pass" 
    }
    
    # Track script results
    if ($ScriptStatus -eq "Pass") {
        $PassedScripts++
        Write-Host "  ✓ PASSED" -ForegroundColor Green
    } elseif ($ScriptStatus -eq "Warning") {
        $WarningScripts++
        Write-Host "  ⚠ WARNING" -ForegroundColor Yellow
    } else {
        $FailedScripts++
        $OverallSuccess = $false
        Write-Host "  ✗ FAILED" -ForegroundColor Red
    }
    
    # Display detailed results if requested
    if ($Detailed) {
        foreach ($Result in $AllResults) {
            Write-Host "    $($Result.Type): $($Result.Status) - $($Result.Message)" -ForegroundColor Gray
            if ($Result.Details -and $Result.Details.Count -gt 0) {
                foreach ($Detail in $Result.Details | Select-Object -First 3) {
                    Write-Host "      $Detail" -ForegroundColor DarkGray
                }
                if ($Result.Details.Count -gt 3) {
                    Write-Host "      ... and $($Result.Details.Count - 3) more" -ForegroundColor DarkGray
                }
            }
        }
    }
    
    # Add to validation results for report
    foreach ($Result in $AllResults) {
        $ValidationResults += [PSCustomObject]@{
            ScriptPath = $RelativePath
            ScriptName = $ScriptFile.Name
            TestType = $Result.Type
            Status = $Result.Status
            Message = $Result.Message
            ErrorCount = $Result.ErrorCount
            WarningCount = if ($Result.PSObject.Properties.Name -contains 'WarningCount') { $Result.WarningCount } else { 0 }
            Details = ($Result.Details -join "; ")
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# Generate summary report
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$TotalErrors = ($ValidationResults | Measure-Object ErrorCount -Sum).Sum
$TotalWarnings = ($ValidationResults | Measure-Object WarningCount -Sum).Sum

Write-Host "Scripts Analyzed: $TotalScripts" -ForegroundColor White
Write-Host "Scripts Passed: $PassedScripts" -ForegroundColor Green
Write-Host "Scripts with Warnings: $WarningScripts" -ForegroundColor Yellow
Write-Host "Scripts Failed: $FailedScripts" -ForegroundColor Red
Write-Host "Total Errors: $TotalErrors" -ForegroundColor Red
Write-Host "Total Warnings: $TotalWarnings" -ForegroundColor Yellow

$SuccessRate = if ($TotalScripts -gt 0) { [math]::Round(($PassedScripts / $TotalScripts) * 100, 1) } else { 0 }
Write-Host "Success Rate: $SuccessRate%" -ForegroundColor $(if ($SuccessRate -ge 90) { "Green" } elseif ($SuccessRate -ge 70) { "Yellow" } else { "Red" })

# Export detailed report
if ($ValidationResults.Count -gt 0) {
    Write-Host "`nExporting detailed report to: $ReportPath" -ForegroundColor Yellow
    $ValidationResults | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "✓ Report exported successfully" -ForegroundColor Green
}

# Show top issues
if ($TotalErrors -gt 0 -or $TotalWarnings -gt 0) {
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Top Issues Found" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    $FailedTests = $ValidationResults | Where-Object { $_.Status -eq "Fail" -or $_.Status -eq "Error" }
    if ($FailedTests) {
        Write-Host "`nCritical Issues:" -ForegroundColor Red
        $FailedTests | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Count)x $($_.Name)" -ForegroundColor Red
        }
    }
    
    $WarningTests = $ValidationResults | Where-Object { $_.Status -eq "Warning" }
    if ($WarningTests) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        $WarningTests | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Count)x $($_.Name)" -ForegroundColor Yellow
        }
    }
}

# Final recommendations
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "Recommendations" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if ($OverallSuccess) {
    Write-Host "✅ All scripts passed validation!" -ForegroundColor Green
    Write-Host "✓ Scripts are ready for production deployment" -ForegroundColor Green
} else {
    Write-Host "❌ Validation failed - address critical issues before deployment" -ForegroundColor Red
    Write-Host "• Fix all syntax errors and PSScriptAnalyzer errors" -ForegroundColor Yellow
    Write-Host "• Improve error handling in failed scripts" -ForegroundColor Yellow
    Write-Host "• Address security concerns" -ForegroundColor Yellow
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Review the detailed report: $ReportPath" -ForegroundColor White
Write-Host "2. Fix critical issues in failed scripts" -ForegroundColor White
Write-Host "3. Re-run validation after fixes" -ForegroundColor White
Write-Host "4. Consider implementing pre-commit hooks for continuous validation" -ForegroundColor White

# Exit with appropriate code
if ($OverallSuccess) {
    Write-Host "`n🎉 Validation completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️ Validation completed with failures" -ForegroundColor Red
    exit 1
}