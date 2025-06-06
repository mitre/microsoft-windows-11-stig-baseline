control 'SV-253377' do
  title 'Systems must at least attempt device authentication using certificates.'
  desc 'Using certificates to authenticate devices to the domain provides increased security over passwords.  By default systems will attempt to authenticate using certificates and fall back to passwords if the domain controller does not support certificates for devices.  This may also be configured to always use certificates for device authentication.'
  desc 'check', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

The default behavior for "Support device authentication using certificate" is "Automatic".

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

Value Name: DevicePKInitEnabled
Value Type: REG_DWORD
Value: 1 (or if the Value Name does not exist)'
  desc 'fix', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

The default behavior for "Support device authentication using certificate" is "Automatic".

To correct this, configured the policy value for Computer Configuration >> Administrative Templates >> System >> Kerberos >> "Support device authentication using certificate" to "Not Configured or "Enabled" with either option selected in "Device authentication behavior using certificate:".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56830r829213_chk'
  tag severity: 'medium'
  tag gid: 'V-253377'
  tag rid: 'SV-253377r991589_rule'
  tag stig_id: 'WN11-CC-000115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56780r829214_fix'
  tag 'documentable'
  tag legacy: ['V-63627', 'SV-78117']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
      it { should have_property 'DevicePKInitEnabled' }
      its('DevicePKInitEnabled') { should cmp 1 }
    end
  end
end
