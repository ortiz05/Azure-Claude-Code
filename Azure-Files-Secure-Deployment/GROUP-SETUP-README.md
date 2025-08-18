# Azure Files Deployment Group Setup

Simple script to create an Azure AD security group with minimal permissions for Azure Files deployment.

## 🎯 Purpose

Creates a dedicated Azure AD group with **least privilege access** scoped to a specific resource group. This allows you to:
- Add your account to the group for secure deployment access
- Avoid using Global Admin privileges for infrastructure deployment
- Maintain clear separation of duties and audit trail

## 🔐 Security Benefits

✅ **Resource Group Scoped** - No tenant-wide permissions  
✅ **Built-in Roles Only** - Microsoft-maintained, well-documented permissions  
✅ **No Azure AD Admin Rights** - Group members can't modify Azure AD  
✅ **Easily Auditable** - Clear role assignments and group membership  
✅ **Least Privilege** - Only permissions needed for Azure Files deployment  

## 🚀 Quick Setup

### Step 1: Run the Group Creation Script
```powershell
# Basic usage - creates group with Storage and Network permissions
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-prod"

# Custom group name
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-prod" `
    -GroupName "AzureFiles-ProductionDeployment"

# Storage only (no VNet permissions)
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-prod" `
    -IncludeNetworkPermissions:$false
```

### Step 2: Add Your Account to the Group
```powershell
# Add yourself (script will show this command with actual group ID)
Add-AzADGroupMember -TargetGroupId "group-id-from-output" -MemberObjectId "your-user-id"

# Or add by email
Add-AzADGroupMember -TargetGroupId "group-id-from-output" -MemberUserPrincipalName "your-email@company.com"
```

### Step 3: Deploy Azure Files
```powershell
# Now you can deploy with your regular account (no Global Admin needed!)
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-prod" `
    -StorageAccountName "stgsecure001" `
    -Location "East US 2"
```

## 📋 What Gets Created

### Azure AD Security Group
- **Name**: `AzureFiles-Deployment-{ResourceGroupName}` (customizable)
- **Type**: Security Group (not mail-enabled)
- **Description**: Clearly identifies purpose and scope

### Role Assignments (Resource Group Scoped)
| Built-in Role | Purpose | When Assigned |
|---------------|---------|---------------|
| **Storage Account Contributor** | Create/manage storage accounts and file shares | Always |
| **Network Contributor** | Configure VNet service endpoints and security | When `-IncludeNetworkPermissions` is true (default) |

## 🔧 Script Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `SubscriptionId` | ✅ Yes | - | Azure subscription ID (GUID format) |
| `ResourceGroupName` | ✅ Yes | - | Resource group where Azure Files will be deployed |
| `GroupName` | ❌ No | `AzureFiles-Deployment-{RGName}` | Custom Azure AD group name |
| `GroupDescription` | ❌ No | Auto-generated | Description for the group |
| `IncludeNetworkPermissions` | ❌ No | `$true` | Include Network Contributor role (needed for VNet integration) |
| `WhatIf` | ❌ No | `$false` | Preview what would be created without making changes |

## 🔑 Required Permissions to Run Script

The account running this script needs:

### Azure AD Permissions
- **User Administrator** or **Global Administrator** (to create security groups)

### Azure RBAC Permissions  
- **Owner** or **User Access Administrator** (to assign roles at resource group level)

## 🎯 Examples

### Example 1: Production Environment
```powershell
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-production" `
    -GroupName "AzureFiles-Production-Deployers"
```

### Example 2: Development Environment (Storage Only)
```powershell
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "87654321-4321-4321-4321-210987654321" `
    -ResourceGroupName "rg-storage-dev" `
    -GroupName "AzureFiles-Dev-Team" `
    -IncludeNetworkPermissions:$false
```

### Example 3: Test Mode
```powershell
.\Create-AzureFilesDeploymentGroup.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-storage-test" `
    -WhatIf
```

## 👥 Managing Group Membership

### Add Users
```powershell
# Single user by email
Add-AzADGroupMember -TargetGroupId "group-id" -MemberUserPrincipalName "user@company.com"

# Multiple users
$Users = @('user1@company.com', 'user2@company.com', 'user3@company.com')
foreach ($User in $Users) {
    Add-AzADGroupMember -TargetGroupId "group-id" -MemberUserPrincipalName $User
    Write-Host "Added: $User"
}
```

### View Members
```powershell
Get-AzADGroupMember -GroupId "group-id" | Select-Object DisplayName, UserPrincipalName
```

### Remove Users
```powershell
Remove-AzADGroupMember -GroupId "group-id" -MemberUserPrincipalName "user@company.com"
```

## 🛡️ Security Considerations

### What Group Members CAN Do
✅ Create storage accounts in the specified resource group  
✅ Configure file shares and security settings  
✅ Set up VNet service endpoints (if Network Contributor assigned)  
✅ Configure storage account networking and firewall rules  

### What Group Members CANNOT Do
❌ Access other resource groups or subscriptions  
❌ Modify Azure AD settings or create/delete users  
❌ Grant Microsoft Graph API permissions  
❌ Create or modify other Azure AD groups  
❌ Access billing or subscription settings  

### Ongoing Security
- **Regular Reviews**: Quarterly review of group membership
- **Audit Logging**: All actions logged in Azure Activity Log
- **Time-Limited Access**: Consider using Azure PIM for temporary elevation
- **Principle of Least Privilege**: Remove users when deployment tasks complete

## 🔍 Verification and Troubleshooting

### Verify Group Creation
```powershell
Get-AzADGroup -DisplayName "AzureFiles-Deployment-rg-storage-prod"
```

### Verify Role Assignments
```powershell
$Group = Get-AzADGroup -DisplayName "group-name"
Get-AzRoleAssignment -ObjectId $Group.Id
```

### Test Deployment Access
```powershell
# As a group member, test if you can list storage accounts
Get-AzStorageAccount -ResourceGroupName "rg-storage-prod"
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Insufficient privileges" | Missing User Administrator role | Run as Global Admin or request User Administrator role |
| "Cannot assign roles" | Missing Owner/User Access Administrator | Verify RBAC permissions on subscription/resource group |
| "Group already exists" | Previous run created the group | Script will use existing group and update role assignments |
| "Resource group not found" | RG doesn't exist | Script will prompt to create it or create manually first |

## 🧹 Cleanup (If Needed)

### Remove Group and Permissions
```powershell
# Get the group
$Group = Get-AzADGroup -DisplayName "AzureFiles-Deployment-rg-storage-prod"

# Remove role assignments
Get-AzRoleAssignment -ObjectId $Group.Id | Remove-AzRoleAssignment

# Delete the group
Remove-AzADGroup -ObjectId $Group.Id
```

## 📞 Support

This script is designed to be simple and self-documenting. If issues arise:
1. Check the script output for specific error messages
2. Verify your account has the required permissions listed above
3. Review Azure Activity Logs for detailed permission errors
4. Ensure resource group name follows Azure naming conventions

---
**Security Note**: This approach provides secure, auditable access without requiring Global Admin privileges for infrastructure deployment.