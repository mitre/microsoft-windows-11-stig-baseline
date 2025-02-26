control 'SV-253420' do
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: DisableRunAs

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Disallow WinRM from storing RunAs credentials" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56873r829342_chk'
  tag severity: 'medium'
  tag gid: 'V-253420'
  tag rid: 'SV-253420r1016440_rule'
  tag stig_id: 'WN11-CC-000355'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-56823r829343_fix'
  tag 'documentable'
  tag legacy: ['V-63375', 'SV-77865']
  tag cci: ['CCI-004895', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should cmp 1 }
  end
end
