# Analyze-EnterpriseApps.ps1
# Breaks down Enterprise Applications by type to explain the discrepancy

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$ClientId
)

try {
    Write-Host "Analyzing Enterprise Applications breakdown..." -ForegroundColor Cyan
    
    # Connect to Microsoft Graph
    Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Scopes "Application.Read.All","Directory.Read.All" -NoWelcome
    
    # Get all service principals
    Write-Host "Retrieving all Enterprise Applications..." -ForegroundColor Yellow
    $AllServicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,CreatedDateTime,ServicePrincipalType,PublisherName,AppOwnerOrganizationId,Tags
    
    Write-Host "Found $($AllServicePrincipals.Count) total Enterprise Applications" -ForegroundColor Green
    
    # Categorize applications
    $Categories = @{
        "Microsoft_BuiltIn" = @()
        "Microsoft_Office365" = @()
        "Microsoft_Azure" = @()
        "ThirdParty_SaaS" = @()
        "Custom_Internal" = @()
        "Legacy_Unused" = @()
        "System_ServicePrincipals" = @()
    }
    
    foreach ($SP in $AllServicePrincipals) {
        $Category = "Unknown"
        
        # Microsoft built-in applications
        if ($SP.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or 
            $SP.PublisherName -like "*Microsoft*" -or
            $SP.DisplayName -like "Microsoft*" -or
            $SP.AppId -in @(
                "00000003-0000-0000-c000-000000000000", # Microsoft Graph
                "00000002-0000-0000-c000-000000000000", # Azure AD Graph (legacy)
                "797f4846-ba00-4fd7-ba43-dac1f8f63013"  # Windows Azure Service Management API
            )) {
            
            if ($SP.DisplayName -like "*Office*" -or $SP.DisplayName -like "*SharePoint*" -or 
                $SP.DisplayName -like "*Teams*" -or $SP.DisplayName -like "*Exchange*" -or
                $SP.DisplayName -like "*OneDrive*") {
                $Categories["Microsoft_Office365"] += $SP
            } elseif ($SP.DisplayName -like "*Azure*" -or $SP.DisplayName -like "*Key Vault*" -or
                      $SP.DisplayName -like "*Storage*" -or $SP.DisplayName -like "*Logic Apps*") {
                $Categories["Microsoft_Azure"] += $SP
            } else {
                $Categories["Microsoft_BuiltIn"] += $SP
            }
        }
        # Third-party SaaS applications
        elseif ($SP.PublisherName -and $SP.PublisherName -ne "" -and $SP.PublisherName -notlike "*Microsoft*") {
            $Categories["ThirdParty_SaaS"] += $SP
        }
        # System service principals (no publisher, system-generated)
        elseif (-not $SP.PublisherName -and $SP.ServicePrincipalType -eq "Application" -and
                ($SP.DisplayName -like "*-*-*-*-*" -or $SP.DisplayName -like "S-*")) {
            $Categories["System_ServicePrincipals"] += $SP
        }
        # Legacy/unused (old applications with no recent activity)
        elseif ($SP.CreatedDateTime -and $SP.CreatedDateTime -lt (Get-Date).AddYears(-2)) {
            $Categories["Legacy_Unused"] += $SP
        }
        # Custom internal applications
        else {
            $Categories["Custom_Internal"] += $SP
        }
    }
    
    # Display breakdown
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "Enterprise Applications Breakdown" -ForegroundColor Cyan
    Write-Host "="*60 -ForegroundColor Cyan
    
    $TotalVisible = 0
    foreach ($Category in $Categories.Keys | Sort-Object) {
        $Count = $Categories[$Category].Count
        $Percentage = [math]::Round(($Count / $AllServicePrincipals.Count) * 100, 1)
        
        $Color = switch ($Category) {
            "Microsoft_BuiltIn" { "Gray" }
            "Microsoft_Office365" { "DarkGray" }
            "Microsoft_Azure" { "DarkGray" }
            "ThirdParty_SaaS" { "Yellow" }
            "Custom_Internal" { "Green" }
            "Legacy_Unused" { "Red" }
            "System_ServicePrincipals" { "DarkGray" }
            default { "White" }
        }
        
        Write-Host "$($Category.Replace('_', ' ')): $Count ($Percentage%)" -ForegroundColor $Color
        
        # These are typically visible in portal
        if ($Category -in @("ThirdParty_SaaS", "Custom_Internal")) {
            $TotalVisible += $Count
        }
    }
    
    Write-Host "`n" + "-"*60 -ForegroundColor Cyan
    Write-Host "Portal vs Script Comparison:" -ForegroundColor Cyan
    Write-Host "  Likely visible in portal: $TotalVisible" -ForegroundColor Green
    Write-Host "  Total found by script: $($AllServicePrincipals.Count)" -ForegroundColor Yellow
    Write-Host "  Hidden from portal: $($AllServicePrincipals.Count - $TotalVisible)" -ForegroundColor Gray
    
    # Show examples of hidden applications
    Write-Host "`nExamples of applications hidden from portal:" -ForegroundColor Yellow
    $HiddenExamples = $Categories["Microsoft_BuiltIn"] + $Categories["Microsoft_Office365"] + $Categories["System_ServicePrincipals"] | 
                     Select-Object -First 10 DisplayName, PublisherName
    
    foreach ($Example in $HiddenExamples) {
        Write-Host "  - $($Example.DisplayName)" -ForegroundColor Gray
        if ($Example.PublisherName) {
            Write-Host "    Publisher: $($Example.PublisherName)" -ForegroundColor DarkGray
        }
    }
    
    # Export detailed breakdown
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = ".\EnterpriseApps-Breakdown-$Timestamp.csv"
    
    $DetailedData = @()
    foreach ($Category in $Categories.Keys) {
        foreach ($SP in $Categories[$Category]) {
            $DetailedData += [PSCustomObject]@{
                Category = $Category.Replace('_', ' ')
                DisplayName = $SP.DisplayName
                AppId = $SP.AppId
                PublisherName = $SP.PublisherName
                ServicePrincipalType = $SP.ServicePrincipalType
                CreatedDateTime = $SP.CreatedDateTime
                VisibleInPortal = $Category -in @("ThirdParty_SaaS", "Custom_Internal")
            }
        }
    }
    
    $DetailedData | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "`nDetailed breakdown exported to: $ReportPath" -ForegroundColor Cyan
    
} catch {
    Write-Error "Analysis failed: $($_.Exception.Message)"
} finally {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}