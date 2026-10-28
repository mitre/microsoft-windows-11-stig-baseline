control 'SV-289260' do
  title 'Windows 11 must be configured to prevent Windows apps from being activated by voice.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\  
Value Name: LetAppsActivateWithVoice

Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy>>"Let Windows apps activate with voice" to "Enabled" with Default for all Apps set to "Force Deny".'
  impact 0.5
  tag check_id: 'C-93950r1270953_chk'
  tag severity: 'medium'
  tag gid: 'V-289260'
  tag rid: 'SV-289260r1270955_rule'
  tag stig_id: 'WN11-CC-000366'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-93855r1270954_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy') do
    it { should have_property 'LetAppsActivateWithVoice' }
    its('LetAppsActivateWithVoice') { should cmp 2 }
  end
end
