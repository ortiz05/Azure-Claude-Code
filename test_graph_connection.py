#!/usr/bin/env python3
"""
Test Microsoft Graph API connection and device cleanup logic
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import sys

# Application credentials - Replace with your values or use secure methods
CLIENT_ID = "YOUR_CLIENT_ID_HERE"
TENANT_ID = "YOUR_TENANT_ID_HERE"
CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"

# Graph API endpoints
TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

class GraphAPIClient:
    def __init__(self):
        self.access_token = None
        self.headers = None
        
    def authenticate(self) -> bool:
        """Authenticate with Microsoft Graph API using client credentials"""
        print("=" * 50)
        print("Microsoft Graph API Connection Test")
        print("=" * 50)
        print(f"Tenant ID: {TENANT_ID}")
        print(f"Client ID: {CLIENT_ID}")
        print("=" * 50)
        
        print("\nAuthenticating with Microsoft Graph...")
        
        token_data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(TOKEN_ENDPOINT, data=token_data)
            
            if response.status_code == 200:
                token_response = response.json()
                self.access_token = token_response['access_token']
                self.headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                }
                print("✓ Successfully authenticated with Microsoft Graph!")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {str(e)}")
            return False
    
    def test_device_read(self) -> bool:
        """Test basic device read operations"""
        print("\n" + "=" * 50)
        print("Testing Device Read Operations")
        print("=" * 50)
        
        if not self.headers:
            print("✗ Not authenticated")
            return False
        
        try:
            # Get devices with pagination
            devices_url = f"{GRAPH_BASE_URL}/devices?$top=5&$select=id,displayName,operatingSystem,approximateLastSignInDateTime"
            response = requests.get(devices_url, headers=self.headers)
            
            if response.status_code == 200:
                devices_data = response.json()
                devices = devices_data.get('value', [])
                
                print(f"✓ Successfully retrieved device information")
                print(f"Sample devices retrieved: {len(devices)}")
                
                if devices:
                    print("\nSample of devices:")
                    for device in devices[:5]:
                        print(f"  - {device.get('displayName', 'N/A')} (OS: {device.get('operatingSystem', 'N/A')})")
                
                return True
            else:
                print(f"✗ Failed to retrieve devices: {response.status_code}")
                print(f"Response: {response.text}")
                
                if response.status_code == 403:
                    print("\nPermission issue detected. Required permissions:")
                    print("  - Device.Read.All or Device.ReadWrite.All (Application)")
                    print("  - Make sure admin consent has been granted")
                
                return False
                
        except Exception as e:
            print(f"✗ Error testing device read: {str(e)}")
            return False
    
    def test_inactive_device_detection(self) -> bool:
        """Test detection of inactive devices"""
        print("\n" + "=" * 50)
        print("Testing Inactive Device Detection")
        print("=" * 50)
        
        if not self.headers:
            print("✗ Not authenticated")
            return False
        
        try:
            inactive_days = 90
            cutoff_date = datetime.now() - timedelta(days=inactive_days)
            
            # Get all devices
            devices_url = f"{GRAPH_BASE_URL}/devices?$select=id,displayName,approximateLastSignInDateTime,operatingSystem,trustType"
            all_devices = []
            
            while devices_url:
                response = requests.get(devices_url, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    all_devices.extend(data.get('value', []))
                    devices_url = data.get('@odata.nextLink', None)
                else:
                    print(f"✗ Failed to retrieve devices: {response.status_code}")
                    return False
            
            print(f"✓ Retrieved {len(all_devices)} total devices")
            
            # Filter inactive devices
            inactive_devices = []
            for device in all_devices:
                last_signin_str = device.get('approximateLastSignInDateTime')
                if last_signin_str:
                    try:
                        last_signin = datetime.fromisoformat(last_signin_str.replace('Z', '+00:00'))
                        if last_signin < cutoff_date:
                            inactive_devices.append(device)
                    except:
                        pass
            
            print(f"✓ Inactive device detection successful")
            print(f"Devices inactive for more than {inactive_days} days: {len(inactive_devices)}")
            
            if inactive_devices:
                print("\nSample of inactive devices (showing first 3):")
                for device in inactive_devices[:3]:
                    last_signin_str = device.get('approximateLastSignInDateTime', 'Never')
                    if last_signin_str != 'Never':
                        last_signin = datetime.fromisoformat(last_signin_str.replace('Z', '+00:00'))
                        last_signin_str = last_signin.strftime('%Y-%m-%d')
                    print(f"  - {device.get('displayName', 'N/A')} - Last Sign-in: {last_signin_str}")
            
            return True
            
        except Exception as e:
            print(f"✗ Error detecting inactive devices: {str(e)}")
            return False
    
    def test_autopilot_access(self) -> bool:
        """Test access to Autopilot devices"""
        print("\n" + "=" * 50)
        print("Testing Autopilot Device Access")
        print("=" * 50)
        
        if not self.headers:
            print("✗ Not authenticated")
            return False
        
        try:
            # Try to access Autopilot devices
            autopilot_url = f"{GRAPH_BASE_URL}/deviceManagement/windowsAutopilotDeviceIdentities?$top=5"
            response = requests.get(autopilot_url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                devices = data.get('value', [])
                print(f"✓ Successfully accessed Autopilot devices")
                print(f"Sample Autopilot devices found: {len(devices)}")
                return True
            elif response.status_code == 403:
                print("✗ Cannot access Autopilot devices: Permission denied")
                print("This is normal if the app doesn't have DeviceManagementServiceConfig permissions")
                return False
            else:
                print(f"✗ Failed to access Autopilot devices: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Error accessing Autopilot devices: {str(e)}")
            return False
    
    def simulate_cleanup_logic(self) -> None:
        """Simulate the cleanup logic without actually deleting"""
        print("\n" + "=" * 50)
        print("Simulating Device Cleanup Logic")
        print("=" * 50)
        
        if not self.headers:
            print("✗ Not authenticated")
            return
        
        try:
            inactive_days = 90
            cutoff_date = datetime.now() - timedelta(days=inactive_days)
            
            # Get devices for simulation
            devices_url = f"{GRAPH_BASE_URL}/devices?$top=20&$select=id,displayName,approximateLastSignInDateTime,operatingSystem,trustType"
            response = requests.get(devices_url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                devices = data.get('value', [])
                
                registered_cleanup = []
                autopilot_cleanup = []
                
                for device in devices:
                    last_signin_str = device.get('approximateLastSignInDateTime')
                    if last_signin_str:
                        try:
                            last_signin = datetime.fromisoformat(last_signin_str.replace('Z', '+00:00'))
                            if last_signin < cutoff_date:
                                trust_type = device.get('trustType', '')
                                if trust_type == 'AzureAd':
                                    autopilot_cleanup.append(device)
                                else:
                                    registered_cleanup.append(device)
                        except:
                            pass
                
                print(f"\n[SIMULATION] Cleanup Summary:")
                print(f"  - Registered devices to clean: {len(registered_cleanup)}")
                print(f"  - Autopilot devices to clean: {len(autopilot_cleanup)}")
                
                if registered_cleanup:
                    print("\n[SIMULATION] Sample registered devices that would be cleaned:")
                    for device in registered_cleanup[:3]:
                        print(f"  - Would remove: {device.get('displayName', 'N/A')}")
                
                if autopilot_cleanup:
                    print("\n[SIMULATION] Sample Autopilot devices that would be cleaned:")
                    for device in autopilot_cleanup[:3]:
                        print(f"  - Would remove from Entra ID (keep in Autopilot): {device.get('displayName', 'N/A')}")
                
                print("\n✓ Cleanup logic simulation completed successfully")
                
        except Exception as e:
            print(f"✗ Error simulating cleanup: {str(e)}")

def main():
    client = GraphAPIClient()
    
    # Run tests
    auth_success = client.authenticate()
    
    if auth_success:
        device_read_success = client.test_device_read()
        
        if device_read_success:
            client.test_inactive_device_detection()
            client.test_autopilot_access()
            client.simulate_cleanup_logic()
        
        print("\n" + "=" * 50)
        print("Connection Test Summary")
        print("=" * 50)
        
        if device_read_success:
            print("✓ Graph API connection successful")
            print("✓ Basic device operations working")
            print("✓ Ready for device cleanup automation")
        else:
            print("✗ Connection successful but device operations failed")
            print("Check API permissions and admin consent")
    else:
        print("\n" + "=" * 50)
        print("Troubleshooting Steps")
        print("=" * 50)
        print("1. Verify the Client ID and Tenant ID are correct")
        print("2. Ensure the client secret hasn't expired")
        print("3. Confirm the app registration has required permissions:")
        print("   - Device.ReadWrite.All (Application)")
        print("   - Directory.ReadWrite.All (Application)")
        print("4. Make sure admin consent has been granted")

if __name__ == "__main__":
    main()