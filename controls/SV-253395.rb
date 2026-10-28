control 'SV-253395' do
  title 'The Microsoft Defender SmartScreen for Explorer must be enabled.'
  desc 'Microsoft Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling Microsoft Defender SmartScreen will warn or prevent users from running potentially malicious programs.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)

And

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: ShellSmartScreenLevel

Value Type: REG_SZ
Value: Block'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Configure Windows Defender SmartScreen" to "Enabled" with "Warn and prevent bypass" selected.

Windows 11 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Explorer.'
  impact 0.5
  tag check_id: 'C-56848r829267_chk'
  tag severity: 'medium'
  tag gid: 'V-253395'
  tag rid: 'SV-253395r958478_rule'
  tag stig_id: 'WN11-CC-000210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56798r829268_fix'
  tag 'documentable'
  tag legacy: ['V-63685', 'SV-78175']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should have_property 'ShellSmartScreenLevel' }
      its('ShellSmartScreenLevel') { should cmp 'Block' }
    end
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
        it { should have_property 'EnableSmartScreen' }
        its('EnableSmartScreen') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
        it { should have_property 'EnableSmartScreen' }
        its('EnableSmartScreen') { should cmp 2 }
      end
    end
  end
end
