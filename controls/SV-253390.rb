control 'SV-253390' do
  title 'Microsoft consumer experiences must be turned off.'
  desc 'Microsoft consumer experiences provides suggestions and notifications to users, which may include the installation of Windows Store apps. Organizations may control the execution of applications through other means such as allowlisting. Turning off Microsoft consumer experiences will help prevent the unwanted installation of suggested applications.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\

Value Name: DisableWindowsConsumerFeatures

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Cloud Content >> "Turn off Microsoft consumer experiences" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56843r829252_chk'
  tag severity: 'low'
  tag gid: 'V-253390'
  tag rid: 'SV-253390r958478_rule'
  tag stig_id: 'WN11-CC-000197'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56793r829253_fix'
  tag 'documentable'
  tag legacy: ['V-71771', 'SV-86395']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId == '1507'
    describe 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.' do
      skip 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent') do
      it { should have_property 'DisableWindowsConsumerFeatures' }
      its('DisableWindowsConsumerFeatures') { should cmp 1 }
    end
  end
end
