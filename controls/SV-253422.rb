control 'SV-253422' do
  title 'Windows 11 must be configured to prevent Windows apps from being activated by voice while the system is locked.'
  desc 'Allowing Windows apps to be activated by voice from the lock screen could allow for unauthorized use. Requiring logon will ensure the apps are used only by authorized personnel.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\  
Value Name: LetAppsActivateWithVoiceAboveLock

Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy >> "Let Windows apps activate with voice while the system is locked" to "Enabled" with Default for all Apps: set to "Force Deny".'
  impact 0.5
  tag check_id: 'C-56875r1270950_chk'
  tag severity: 'medium'
  tag gid: 'V-253422'
  tag rid: 'SV-253422r1270952_rule'
  tag stig_id: 'WN11-CC-000365'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-56825r1270951_fix'
  tag 'documentable'
  tag legacy: ['V-94719', 'SV-104549']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy') do
    it { should have_property 'LetAppsActivateWithVoiceAboveLock' }
    its('LetAppsActivateWithVoiceAboveLock') { should cmp 2 }
  end
end
