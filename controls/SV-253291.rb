control 'SV-253291' do
  title 'Bluetooth must be turned off unless approved by the organization.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Connectivity\\

Value Name: AllowBluetooth

Value Type: REG_DWORD
Value: 0x00000000 (0)

Approval must be documented with the ISSO.'
  desc 'fix', 'Turn off Bluetooth radios not organizationally approved.

For systems managed by Intune, apply the DOD Windows 11 STIG Settings Catalog (or equivalent Intune policy) found in the Intune policy package available on cyber.mil.
Steps to create an Intune policy:
1. Sign in to the Intune admin center >> Devices >> Configuration >> Create >> New Policy.
2. Platform: Windows 10 and later. Profile type: Settings Catalog, then click "Create".
3. Basics: Provide a Name and Description of the profile, then click "Next".
4. Configuration settings: Click "+ Add settings" and search for connectivity under the Settings picker. Under the Connectivity category, check the box next to Allow Bluetooth setting. Choose the first option, "Disallow Bluetooth", then click "Next".
5. Scope tags: (optional), then click "Next".
6. Assignments: Assign the policy to Entra security groups that contain the target users or devices, then click "Next".
7. Review + create: Review the deployment summary, then click "Create".'
  impact 0.5
  tag check_id: 'C-56744r1153420_chk'
  tag severity: 'medium'
  tag gid: 'V-253291'
  tag rid: 'SV-253291r1153422_rule'
  tag stig_id: 'WN11-00-000210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56694r1153421_fix'
  tag 'documentable'
  tag legacy: ['SV-87403', 'V-72765']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  pnp = <<~POWERSHELL
    $bt = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' })
    $bt.Count
  POWERSHELL

  bt_count = powershell(pnp).stdout.to_i

  # 1) No Bluetooth devices -> control is NA
  if bt_count == 0
    impact 0.0
    describe 'No Bluetooth devices present' do
      skip 'This system does not have Bluetooth, therefore this control is not applicable.'
    end
    
  # 2) Bluetooth present 
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity') do
      its('AllowBluetooth') { should cmp input('bluetooth_approved')}
    end
  end
end