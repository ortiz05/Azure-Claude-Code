# How to Mount Azure File Share in Windows with Intune

Comprehensive guide for deploying Azure File Share mounting through Microsoft Intune using configuration profiles and device configuration policies.

## 🎯 Overview

This guide covers mounting Azure File Shares on Windows devices managed by Microsoft Intune using device configuration profiles, administrative templates, and modern management approaches - no legacy net use commands required.

## 🔐 Prerequisites

### Azure Requirements
- Azure File Share deployed with Azure AD authentication enabled
- Storage account configured for identity-based authentication
- Proper RBAC permissions configured on the file share

### Intune Requirements
- Microsoft Intune license and administrative access
- Windows devices enrolled in Intune
- PowerShell script deployment capability enabled

### User Requirements
- Azure AD account with appropriate file share permissions
- Windows 10/11 device joined to Azure AD or Hybrid Azure AD

## 📋 Required Permissions and Roles

### Azure RBAC Roles for File Share Access

| Role | Scope | Purpose | Assignment Level |
|------|--------|---------|------------------|
| **Storage File Data SMB Share Contributor** | File Share | Read, write, delete files and directories | User/Group |
| **Storage File Data SMB Share Elevated Contributor** | File Share | Full control including NTFS permissions | Administrator |
| **Storage File Data SMB Share Reader** | File Share | Read-only access to files and directories | User/Group (Read-only) |

### Intune Administrative Roles

| Role | Purpose |
|------|---------|
| **Intune Administrator** | Deploy and manage PowerShell scripts |
| **Cloud Device Administrator** | Manage device configurations |
| **Azure AD Global Administrator** | Configure authentication and RBAC |

### PowerShell Script Execution Rights

| Permission | Level | Required For |
|------------|-------|--------------|
| **ExecutionPolicy** | RemoteSigned or Unrestricted | Script execution |
| **Local Administrator** | Device level | Drive mapping and registry modifications |
| **Network access** | Device level | Access to Azure File Share endpoints |

## 🔧 Step-by-Step Intune Configuration

### Step 1: Configure Azure File Share RBAC Permissions

```powershell
# Example: Assign Storage File Data SMB Share Contributor role
$SubscriptionId = "your-subscription-id"
$ResourceGroupName = "rg-secure-files"
$StorageAccountName = "stgsecurefiles001"
$FileShareName = "secure-fileshare"
$UserPrincipalName = "user@company.com"

# Get the file share resource ID
$FileShareScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$FileShareName"

# Assign role to user
New-AzRoleAssignment -SignInName $UserPrincipalName `
    -RoleDefinitionName "Storage File Data SMB Share Contributor" `
    -Scope $FileShareScope

# Assign role to group
$GroupObjectId = (Get-AzADGroup -DisplayName "FileShare-Users").Id
New-AzRoleAssignment -ObjectId $GroupObjectId `
    -RoleDefinitionName "Storage File Data SMB Share Contributor" `
    -Scope $FileShareScope
```

### Step 2: Create Administrative Templates (ADMX) Configuration Profile

1. **Navigate to Microsoft Endpoint Manager Admin Center**
   - URL: https://endpoint.microsoft.com
   - Sign in with Intune Administrator credentials

2. **Create Configuration Profile**
   - Go to **Devices** > **Configuration profiles**
   - Click **+ Create profile**
   - Platform: **Windows 10 and later**
   - Profile type: **Templates** > **Administrative templates**

3. **Configure Drive Mapping Settings**
   ```
   Profile Name: Azure File Share Mapping
   Description: Configure automatic mounting of Azure File Shares
   
   Computer Configuration:
   ├── Windows Components
   │   └── Network Shares
   │       ├── Add network share: Enabled
   │       │   └── Share name: \\stgsecurefiles001.file.core.windows.net\secure-fileshare
   │       ├── Drive letter: Z:
   │       ├── Label: Company Files
   │       └── Reconnect: Enabled
   ```

### Step 3: Create Device Configuration Profile for Registry Settings

1. **Create Custom OMA-URI Configuration**
   - Go to **Devices** > **Configuration profiles**
   - Click **+ Create profile**
   - Platform: **Windows 10 and later**
   - Profile type: **Templates** > **Custom**

2. **Configure OMA-URI Settings**
   ```
   Profile Name: Azure File Share Registry Settings
   Description: Registry settings for Azure File Share authentication
   
   OMA-URI Settings:
   
   Setting 1:
   Name: Enable Azure AD Auth for File Shares
   OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Authentication/EnableAzureADKerberosForFileShares
   Data type: Integer
   Value: 1
   
   Setting 2:
   Name: Configure SMB Client Authentication
   OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Kerberos/AllowForestSearchOrder
   Data type: String
   Value: AzureAD
   
   Setting 3:
   Name: Enable SMB Signing
   OMA-URI: ./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/SMBv1ClientDriver
   Data type: Integer
   Value: 0
   ```

### Step 4: Create App Configuration for File Explorer Integration

1. **Create Win32 App Package (Optional)**
   - Package a PowerShell script wrapper as Win32 app
   - Use Microsoft Win32 Content Prep Tool

2. **Configure App Settings**
   ```
   App Name: Azure File Share Connector
   Description: Configures automatic mounting of Azure File Shares
   App type: Windows app (Win32)
   
   Install command: powershell.exe -ExecutionPolicy Bypass -File "Install-FileShareMount.ps1"
   Uninstall command: powershell.exe -ExecutionPolicy Bypass -File "Uninstall-FileShareMount.ps1"
   
   Detection method: Registry
   Registry path: HKEY_LOCAL_MACHINE\SOFTWARE\Company\FileShare
   Registry name: InstallStatus
   Registry type: String
   Operator: Equals
   Value: Installed
   ```

### Step 5: Configure Settings Catalog (Modern Approach)

1. **Create Settings Catalog Profile**
   - Go to **Devices** > **Configuration profiles**
   - Click **+ Create profile**
   - Platform: **Windows 10 and later**
   - Profile type: **Settings catalog**

2. **Configure Network Drive Settings**
   ```
   Profile Name: Azure File Share - Settings Catalog
   Description: Modern approach to configure network drive mapping
   
   Categories to Configure:
   
   1. Administrative Templates > System > Logon
      ├── Always wait for the network at computer startup and logon: Enabled
      └── Run startup scripts synchronously: Enabled
   
   2. Administrative Templates > Windows Components > Network Shares
      ├── Add network drives: Configure
      │   ├── UNC Path: \\stgsecurefiles001.file.core.windows.net\secure-fileshare
      │   ├── Drive Letter: Z:
      │   ├── Display Name: Company Files
      │   └── Reconnect at logon: Yes
      └── Require authentication: Azure AD
   
   3. Administrative Templates > System > Group Policy
      └── Registry policy processing: Background refresh enabled
   ```

### Step 6: Create Compliance Policy for Prerequisites

1. **Create Device Compliance Policy**
   - Go to **Devices** > **Compliance policies**
   - Click **+ Create Policy**
   - Platform: **Windows 10 and later**

2. **Configure Compliance Settings**
   ```
   Policy Name: Azure File Share Prerequisites
   Description: Ensure devices meet requirements for file share access
   
   Settings:
   ├── Device Security
   │   ├── Require BitLocker: Yes
   │   ├── Require Secure Boot: Yes
   │   └── Require code integrity: Yes
   ├── System Security
   │   ├── Windows Defender Antimalware: Required
   │   └── Windows Defender Firewall: Required
   └── Device Properties
       ├── Minimum OS version: 10.0.19041 (Windows 10 20H1)
       └── Maximum OS version: Not configured
   ```

### Step 7: Create Conditional Access Integration

1. **Configure in Azure AD Portal**
   - Navigate to Azure AD > Security > Conditional Access
   - Create new policy: "Azure File Share Access"

2. **Policy Configuration**
   ```
   Policy Name: Azure File Share Access Control
   
   Assignments:
   ├── Users: FileShare-Users group
   ├── Cloud apps: Office 365 SharePoint Online
   └── Conditions:
       ├── Device platforms: Windows
       ├── Device state: Compliant devices
       └── Client apps: Modern authentication clients
   
   Access Controls:
   ├── Grant: Require device to be marked as compliant
   ├── Session: Use Conditional Access App Control
   └── Enable policy: On
   ```

### Step 8: Configure Deployment Groups and Assignments

1. **Create Azure AD Security Groups**
   ```
   Group Name: FileShare-Users
   Type: Security
   Membership: Assigned
   Members: Users who need file share access
   
   Group Name: FileShare-Devices
   Type: Security  
   Membership: Dynamic Device
   Dynamic rule: (device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM")
   ```

2. **Assign Configuration Profiles**
   ```
   Administrative Templates Profile:
   ├── Assigned to: FileShare-Devices
   ├── Assignment type: Required
   └── Availability: Available for enrolled devices
   
   Custom OMA-URI Profile:
   ├── Assigned to: FileShare-Devices
   ├── Assignment type: Required
   └── Scope: All devices in group
   
   Settings Catalog Profile:
   ├── Assigned to: FileShare-Devices
   ├── Assignment type: Required
   └── Filters: Windows version 10.0.19041 or later
   ```

### Step 9: Configure Monitoring and Reporting

1. **Device Configuration Monitoring**
   - Go to **Devices** > **Monitor** > **Assignment status**
   - Track deployment success/failure rates
   - Set up automated alerts for failed deployments

2. **Custom Reporting with Graph API**
   ```powershell
   # PowerShell script to monitor file share access
   Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
   
   # Get configuration profile status
   $ProfileId = "your-profile-id"
   $DeviceStatuses = Get-MgDeviceManagementDeviceConfigurationDeviceStatus -DeviceConfigurationId $ProfileId
   
   # Generate compliance report
   $Report = $DeviceStatuses | Select-Object DeviceDisplayName, Status, LastReportedDateTime
   $Report | Export-Csv -Path "FileShareDeploymentReport.csv" -NoTypeInformation
   ```

## 🛠️ Advanced Configuration Options

### Option 1: User-based Deployment with Registry Settings

```powershell
# Set registry entries for persistent configuration
$RegistryPath = "HKCU:\Software\Company\FileShare"
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force
}

Set-ItemProperty -Path $RegistryPath -Name "StorageAccount" -Value $StorageAccountName
Set-ItemProperty -Path $RegistryPath -Name "ShareName" -Value $FileShareName
Set-ItemProperty -Path $RegistryPath -Name "DriveLetter" -Value $DriveLetter
Set-ItemProperty -Path $RegistryPath -Name "LastMounted" -Value (Get-Date).ToString()
```

### Option 2: Group Policy Integration

For hybrid environments, create GPO settings:

1. **Computer Configuration** > **Preferences** > **Windows Settings** > **Drive Maps**
2. Configure UNC path: `\\storageaccount.file.core.windows.net\sharename`
3. Set reconnect options and user targeting

### Option 3: Conditional Access Integration

Configure conditional access policies:

```powershell
# Example conditional access requirements
# - Device must be compliant
# - Device must be hybrid Azure AD joined
# - MFA required for access
# - Specific locations only
```

## 📊 Monitoring and Troubleshooting

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|--------|----------|
| **Error 1326 - Logon failure** | User lacks file share permissions | Verify RBAC assignments |
| **Error 53 - Network path not found** | Network connectivity or DNS issues | Check network and firewall settings |
| **Error 5 - Access denied** | Authentication method mismatch | Ensure Azure AD authentication is configured |
| **Script doesn't execute** | PowerShell execution policy | Verify Intune script execution settings |

### PowerShell Troubleshooting Commands

```powershell
# Check current drive mappings
Get-PSDrive -PSProvider FileSystem

# Test network connectivity
Test-NetConnection -ComputerName "storageaccount.file.core.windows.net" -Port 445

# Check Azure AD authentication status
dsregcmd /status

# View detailed net use information
net use

# Clear cached credentials (if needed)
cmdkey /list
cmdkey /delete:storageaccount.file.core.windows.net
```

### Event Log Queries

```powershell
# Check for Azure File Share mount events
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='AzureFileShareMount'}

# Check for authentication events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625}
```

## 🔒 Security Best Practices

### Script Security
- **Code signing**: Sign PowerShell scripts in production environments
- **Least privilege**: Run scripts with minimum required permissions
- **Credential protection**: Never hardcode credentials in scripts
- **Audit logging**: Enable comprehensive logging for compliance

### Network Security
- **Private endpoints**: Use private endpoints for maximum security
- **Conditional access**: Implement device-based conditional access policies
- **Network segmentation**: Restrict access to storage endpoints
- **Monitoring**: Enable network traffic monitoring and alerting

### Access Control
- **Regular access reviews**: Quarterly review of file share permissions
- **Just-in-time access**: Implement time-limited access where appropriate
- **Group-based permissions**: Use security groups instead of individual assignments
- **Privileged access**: Separate administrative and user access patterns

## 📋 Compliance and Governance

### Documentation Requirements
- **Change management**: Document all script modifications
- **Access procedures**: Maintain user access request procedures
- **Incident response**: Define procedures for access issues
- **Compliance mapping**: Map to organizational security frameworks

### Audit Trail
- **Script execution logs**: Retain Intune deployment logs
- **File access logs**: Enable Azure Storage logging
- **User activity**: Monitor file share usage patterns
- **Security events**: Implement SIEM integration for security monitoring

## 🚀 Deployment Checklist

### Pre-Deployment
- [ ] Azure File Share configured with Azure AD authentication
- [ ] RBAC permissions assigned to users/groups
- [ ] Intune PowerShell script execution enabled
- [ ] Target device groups created and populated
- [ ] Network connectivity verified (port 445 open)

### During Deployment
- [ ] PowerShell script uploaded to Intune
- [ ] Script assignments configured
- [ ] Detection rules configured (if applicable)
- [ ] Deployment monitoring dashboard prepared
- [ ] Support procedures communicated to helpdesk

### Post-Deployment
- [ ] Deployment success rate verified (target >95%)
- [ ] User access testing completed
- [ ] Event log monitoring configured
- [ ] User training materials distributed
- [ ] Ongoing monitoring procedures established

## 📞 Support and Maintenance

### Regular Maintenance Tasks
- **Monthly**: Review deployment success rates and error patterns
- **Quarterly**: Validate RBAC permissions and access patterns
- **Semi-annually**: Review and update PowerShell scripts
- **Annually**: Comprehensive security assessment and documentation review

### Escalation Procedures
1. **Level 1**: Basic connectivity and authentication issues
2. **Level 2**: Advanced PowerShell and Intune configuration issues
3. **Level 3**: Azure infrastructure and RBAC permission issues

For technical support, refer to the main README.md troubleshooting section and Azure documentation.