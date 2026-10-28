control 'SV-253424' do
  title 'Windows Ink Workspace must be configured to disallow access above the lock.'
  desc 'This action secures Windows Ink, which contains applications and features oriented toward pen computing.

Note: A different registry location is needed when systems are managed by Intune versus GPO.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace  (For GPO-managed systems)
Or
Registry Path: \\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\WindowsInkWorkspace  (For Intune-managed systems)
 
Value Name: AllowWindowsInkWorkspace
Value Type: REG_DWORD
Value data: 1'
  desc 'fix', 'Disable the convenience PIN sign-in. 

For GPO-managed systems:

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Ink Workspace >> Set "Allow Windows Ink Workspace" to "Enabled and set Options On, but disallow access above lock".

For Intune-managed systems:

Set the Windows Ink Workspace Policy to disallow access above lock.'
  impact 0.5
  tag check_id: 'C-56877r1210227_chk'
  tag severity: 'medium'
  tag gid: 'V-253424'
  tag rid: 'SV-253424r1210299_rule'
  tag stig_id: 'WN11-CC-000385'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-56827r1210228_fix'
  tag 'documentable'
  tag legacy: ['SV-108665', 'V-99561']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']

  # GPO-managed systems use the WindowsInkWorkspace policy key; Intune-managed systems use the WindowsInkWorkspace CSP
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp 1 }
    end
  end
end
