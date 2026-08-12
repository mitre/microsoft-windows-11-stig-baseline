control 'SV-253399' do
  title 'Windows 11 must be configured to disable Windows Game Recording and Broadcasting.'
  desc 'Windows Game Recording and Broadcasting is intended for use with games; however, it could potentially record screen shots of other applications and expose sensitive data. Disabling the feature will prevent this from occurring.'
  desc 'check', 'This is NA for Windows 11 LTSC.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\\

Value Name: AllowGameDVR

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting" to "Disabled".'
  impact 0.5
  tag check_id: 'C-56852r829279_chk'
  tag severity: 'medium'
  tag gid: 'V-253399'
  tag rid: 'SV-253399r958478_rule'
  tag stig_id: 'WN11-CC-000252'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56802r829280_fix'
  tag 'documentable'
  tag legacy: ['SV-89091', 'V-74417']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  releaseID = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId.to_i

  if releaseID == 1607 || releaseID <= 1507
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1507 and 1607.' do
      skip 'This STIG does not apply to Prior Versions before 1507 and 1607.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR') do
      it { should have_property 'AllowGameDVR' }
      its('AllowGameDVR') { should cmp 0 }
    end
  end
end
