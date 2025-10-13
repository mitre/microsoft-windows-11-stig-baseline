control 'SV-253389' do
  title 'Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.'
  desc 'Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\\

Value Name: EnhancedAntiSpoofing

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled".'
  impact 0.5
  tag check_id: 'C-56842r829249_chk'
  tag severity: 'medium'
  tag gid: 'V-253389'
  tag rid: 'SV-253389r991589_rule'
  tag stig_id: 'WN11-CC-000195'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56792r829250_fix'
  tag 'documentable'
  tag legacy: ['SV-78167', 'V-63677']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId == '1507'
    impact 0.0
    describe 'Windows 10 v1507 LTSB version does not include this setting.' do
      skip 'Windows 10 v1507 LTSB version does not include this setting.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures') do
      it { should have_property 'EnhancedAntiSpoofing' }
      its('EnhancedAntiSpoofing') { should cmp 1 }
    end
  end
end
