control 'SV-253474' do
  title 'User Account Control must run all administrators in Admin Approval Mode, enabling UAC.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableLUA

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Run all administrators in Admin Approval Mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56927r829504_chk'
  tag severity: 'medium'
  tag gid: 'V-253474'
  tag rid: 'SV-253474r1016444_rule'
  tag stig_id: 'WN11-SO-000270'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-56877r829505_fix'
  tag 'documentable'
  tag legacy: ['SV-78319', 'V-63829']
  tag cci: ['CCI-004895', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableLUAs' }
    its('EnableLUA') { should cmp 1 }
  end
end
