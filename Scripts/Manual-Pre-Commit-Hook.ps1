# Pre-Commit-Hook.ps1
# Git pre-commit hook for PowerShell script validation
# This script automatically validates PowerShell scripts before allowing commits

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Pre-Commit PowerShell Validation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Get the repository root
$RepoRoot = git rev-parse --show-toplevel 2>$null
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

Write-Host "Repository Root: $RepoRoot" -ForegroundColor Yellow

# Get staged PowerShell files
try {
    $StagedFiles = git diff --cached --name-only --diff-filter=ACM 2>$null | Where-Object { $_ -like "*.ps1" }
    
    if (-not $StagedFiles) {
        Write-Host "✓ No PowerShell files staged for commit" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "PowerShell files staged for commit:" -ForegroundColor Cyan
    $StagedFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
}
catch {
    Write-Host "❌ Failed to get staged files: $_" -ForegroundColor Red
    if (-not $Force) {
        exit 1
    }
}

# Check if validation script exists
$ValidationScript = Join-Path $RepoRoot "Scripts\Validate-PowerShellScripts.ps1"
if (-not (Test-Path $ValidationScript)) {
    Write-Host "❌ Validation script not found: $ValidationScript" -ForegroundColor Red
    Write-Host "Skipping validation..." -ForegroundColor Yellow
    exit 0
}

# Create temporary directory for staged files
$TempDir = Join-Path $env:TEMP "pre-commit-validation-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

try {
    # Extract staged files to temporary directory
    Write-Host "`nExtracting staged files for validation..." -ForegroundColor Yellow
    
    foreach ($File in $StagedFiles) {
        $TempFile = Join-Path $TempDir $File
        $TempFileDir = Split-Path $TempFile -Parent
        
        if (-not (Test-Path $TempFileDir)) {
            New-Item -Path $TempFileDir -ItemType Directory -Force | Out-Null
        }
        
        # Get the staged content
        $StagedContent = git show ":$File" 2>$null
        if ($StagedContent) {
            $StagedContent | Out-File -FilePath $TempFile -Encoding UTF8
            Write-Host "  ✓ Extracted: $File" -ForegroundColor Gray
        }
    }
    
    # SECURITY: Scan for hardcoded credentials first
    Write-Host "`nScanning for hardcoded credentials..." -ForegroundColor Yellow
    $CredentialPatterns = @(
        '([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})',  # GUID pattern
        '([a-zA-Z0-9+/]{20,}={0,2})',  # Base64-like patterns (secrets)
        '(password\s*=\s*["\`''][^"\`'']+["\`''])',  # password assignments
        '(secret\s*=\s*["\`''][^"\`'']+["\`''])',    # secret assignments
        '(key\s*=\s*["\`''][^"\`'']+["\`''])'        # key assignments
    )
    
    $CredentialIssues = @()
    foreach ($File in $StagedFiles) {
        $TempFile = Join-Path $TempDir $File
        if (Test-Path $TempFile) {
            $Content = Get-Content $TempFile -Raw
            foreach ($Pattern in $CredentialPatterns) {
                $Matches = [regex]::Matches($Content, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($Match in $Matches) {
                    # Skip obvious placeholder values
                    $Value = $Match.Value
                    if ($Value -notmatch 'YOUR_.*_HERE|PLACEHOLDER|EXAMPLE|env:' -and 
                        $Value -notmatch '00000000-0000-0000-0000-000000000000' -and
                        $Value.Length -gt 10) {
                        $CredentialIssues += "SECURITY RISK in $File`: Potential hardcoded credential detected: $($Value.Substring(0, [Math]::Min(20, $Value.Length)))..."
                    }
                }
            }
        }
    }
    
    if ($CredentialIssues.Count -gt 0) {
        Write-Host "`n🚨 CRITICAL SECURITY ISSUES DETECTED:" -ForegroundColor Red
        $CredentialIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host "`nCOMMIT BLOCKED: Remove all hardcoded credentials before committing!" -ForegroundColor Red
        Write-Host "Replace with environment variables or secure parameter patterns." -ForegroundColor Yellow
        if (-not $Force) {
            exit 1
        }
    }
    
    # Run validation on extracted files
    Write-Host "`nRunning PowerShell validation..." -ForegroundColor Yellow
    
    $ValidationArgs = @(
        "-Path", $TempDir
        "-ReportPath", (Join-Path $TempDir "validation-report.csv")
        "-FailOnWarnings"
    )
    
    # Execute validation script
    $ValidationProcess = Start-Process -FilePath "pwsh" -ArgumentList @("-File", $ValidationScript) + $ValidationArgs -Wait -PassThru -NoNewWindow
    
    $ValidationExitCode = $ValidationProcess.ExitCode
    
    # Check validation results
    if ($ValidationExitCode -eq 0) {
        Write-Host "`n✅ All staged PowerShell scripts passed validation!" -ForegroundColor Green
        Write-Host "Proceeding with commit..." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`n❌ PowerShell validation failed!" -ForegroundColor Red
        Write-Host "Commit blocked to maintain code quality." -ForegroundColor Red
        
        # Show validation report if available
        $ReportPath = Join-Path $TempDir "validation-report.csv"
        if (Test-Path $ReportPath) {
            Write-Host "`nValidation issues found:" -ForegroundColor Yellow
            
            try {
                $Report = Import-Csv $ReportPath | Where-Object { $_.Status -eq "Fail" -or $_.Status -eq "Error" }
                $Report | Select-Object -First 10 | ForEach-Object {
                    Write-Host "  ❌ $($_.ScriptName): $($_.TestType) - $($_.Message)" -ForegroundColor Red
                }
                
                if ($Report.Count -gt 10) {
                    Write-Host "  ... and $($Report.Count - 10) more issues" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "  (Unable to parse validation report)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`nTo fix these issues:" -ForegroundColor Cyan
        Write-Host "1. Run the validation script manually:" -ForegroundColor White
        Write-Host "   pwsh -File Scripts\Validate-PowerShellScripts.ps1 -Path . -Detailed" -ForegroundColor Gray
        Write-Host "2. Fix all reported errors and warnings" -ForegroundColor White
        Write-Host "3. Re-stage your files and commit again" -ForegroundColor White
        Write-Host "`nTo bypass validation (not recommended):" -ForegroundColor Yellow
        Write-Host "   git commit --no-verify" -ForegroundColor Gray
        
        if (-not $Force) {
            exit 1
        } else {
            Write-Host "`n⚠️ Validation bypassed due to -Force flag" -ForegroundColor Yellow
            exit 0
        }
    }
}
catch {
    Write-Host "`n❌ Pre-commit validation failed with error: $_" -ForegroundColor Red
    
    if (-not $Force) {
        Write-Host "Use -Force to bypass validation" -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "⚠️ Continuing due to -Force flag" -ForegroundColor Yellow
        exit 0
    }
}
finally {
    # Clean up temporary directory
    if (Test-Path $TempDir) {
        try {
            Remove-Item -Path $TempDir -Recurse -Force
            Write-Host "✓ Cleaned up temporary files" -ForegroundColor Gray
        }
        catch {
            Write-Host "⚠️ Failed to clean up temporary directory: $TempDir" -ForegroundColor Yellow
        }
    }
}