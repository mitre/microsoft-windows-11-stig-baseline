control 'SV-253389' do
  title 'Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.'
  desc 'Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.

Note: A different registry location is needed when systems are managed by Intune versus GPO.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\\   (For GPO-managed systems)
Or
Registry Path: \\SOFTWARE\\Microsoft\\Policies\\PassportForWork\\Biometrics\\   (For Intune-managed systems)

Value Name: EnhancedAntiSpoofing 
Or
Value Name: FacialFeaturesUseEnhancedAntiSpoofing  (For Intune-managed systems)

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'For GPO-managed systems:

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled".

For Intune-managed systems:

Revise the Intune policy to enable enhanced anti-spoofing for Facial Features.'
  impact 0.5
  tag check_id: 'C-56842r1256672_chk'
  tag severity: 'medium'
  tag gid: 'V-253389'
  tag rid: 'SV-253389r1268251_rule'
  tag stig_id: 'WN11-CC-000195'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56792r1210207_fix'
  tag 'documentable'
  tag legacy: ['SV-78167', 'V-63677']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # GPO-managed systems use the Biometrics policy key; Intune-managed systems use the PassportForWork CSP key
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures') do
      it { should have_property 'EnhancedAntiSpoofing' }
      its('EnhancedAntiSpoofing') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics') do
      it { should have_property 'FacialFeaturesUseEnhancedAntiSpoofing' }
      its('FacialFeaturesUseEnhancedAntiSpoofing') { should cmp 1 }
    end
  end
end
