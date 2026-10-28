control 'SV-253410' do
  title 'Users must be prevented from changing installation options.'
  desc 'Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: EnableUserControl

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Allow user control over installs" to "Disabled".'
  impact 0.5
  tag check_id: 'C-56863r829312_chk'
  tag severity: 'medium'
  tag gid: 'V-253410'
  tag rid: 'SV-253410r1051053_rule'
  tag stig_id: 'WN11-CC-000310'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-56813r829313_fix'
  tag 'documentable'
  tag legacy: ['V-63321', 'SV-77811']
  tag cci: ['CCI-003980', 'CCI-001812']
  tag nist: ['CM-11 (2)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should cmp 0 }
  end
end
